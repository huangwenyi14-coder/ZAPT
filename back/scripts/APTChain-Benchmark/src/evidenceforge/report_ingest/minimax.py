# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Small, redaction-safe MiniMax HTTP client."""

import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import UnionType
from typing import Any, Union, get_args, get_origin
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, SecretStr

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.report_ingest.models import ReportExtraction

LOG = logging.getLogger(__name__)
DEFAULT_BASE_URL = "https://api.minimaxi.com/anthropic"
DEFAULT_MODEL = "MiniMax-M2.7"
OFFICIAL_HOSTS = {"api.minimaxi.com", "api.minimax.io"}
EXTRACTION_TOOL_NAME = "submit_report_extraction"
FACT_EXTRACTION_TOOL_NAME = "submit_report_facts"
AUDIT_TOOL_NAME = "submit_report_audit"
COMPLETION_TOOL_NAME = "submit_simulation_plan"
DEFAULT_TEMPERATURE = 0.1
_SAFE_LABEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")


class MiniMaxError(EvidenceForgeError):
    """A MiniMax credential, transport, or response error."""


class MiniMaxOutputTruncatedError(MiniMaxError):
    """The service stopped before a complete structured payload was returned."""


class MiniMaxHttpError(MiniMaxError):
    """A safe HTTP failure that never includes request content."""

    def __init__(
        self,
        status_code: int,
        *,
        retryable: bool,
        retry_after_seconds: float | None = None,
    ) -> None:
        self.status_code = status_code
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds
        if status_code == 401:
            message = "MiniMax 鉴权失败（401）；API Key 无效、已过期或不属于当前接口"
        elif status_code == 403:
            message = "MiniMax 拒绝访问（403）；请检查 API Key 的模型权限和账户状态"
        else:
            message = f"MiniMax HTTP 请求失败，状态码 {status_code}"
        super().__init__(message)


class MiniMaxCredentials(BaseModel):
    """Resolved MiniMax credentials with secret-safe representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    api_key: SecretStr
    base_url: str


JsonTransport = Callable[[str, dict[str, str], dict[str, Any], float], dict[str, Any]]
Sleeper = Callable[[float], None]


@dataclass(frozen=True)
class MiniMaxCallRecord:
    """Safe metadata for one completed HTTP call without prompts or responses."""

    stage: str
    prompt_version: str
    tool_name: str
    duration_seconds: float
    input_tokens: int | None
    output_tokens: int | None
    repair: bool


def load_minimax_credentials(
    *,
    api_key_file: Path | None = None,
    base_url: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> MiniMaxCredentials:
    """Resolve a MiniMax key and HTTPS base URL without logging either value."""
    environment = os.environ if environ is None else environ
    file_key: str | None = None
    file_url: str | None = None
    if api_key_file is not None:
        if api_key_file.is_symlink():
            raise MiniMaxError("拒绝从符号链接读取 MiniMax 凭据")
        try:
            lines = [
                line.strip()
                for line in api_key_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError as exc:
            raise MiniMaxError(f"无法读取 MiniMax 凭据文件：{type(exc).__name__}") from exc
        for line in lines:
            if line.startswith("https://") and file_url is None:
                file_url = line
                continue
            label, value = _split_labeled_value(line)
            if label in {"api_key", "apikey", "minimax_api_key", "key", "token"} and value:
                file_key = value
            elif line.startswith("sk-") and file_key is None:
                file_key = line

    api_key = environment.get("MINIMAX_API_KEY") or file_key
    if not api_key:
        raise MiniMaxError("未找到 MiniMax API Key；请设置 MINIMAX_API_KEY 或 --api-key-file")
    resolved_url = base_url or environment.get("MINIMAX_BASE_URL") or file_url or DEFAULT_BASE_URL
    _validate_base_url(resolved_url)
    return MiniMaxCredentials(api_key=SecretStr(api_key), base_url=resolved_url.rstrip("/"))


class MiniMaxClient:
    """Call MiniMax through its Anthropic- or OpenAI-compatible JSON API."""

    def __init__(
        self,
        credentials: MiniMaxCredentials,
        *,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 12_000,
        timeout_seconds: float = 180.0,
        max_retries: int = 3,
        transport: JsonTransport | None = None,
        sleeper: Sleeper = time.sleep,
    ) -> None:
        self.credentials = credentials
        self.model = model
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._transport = transport or _urllib_transport
        self._sleeper = sleeper
        self.call_history: list[MiniMaxCallRecord] = []

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        tool_name: str = EXTRACTION_TOOL_NAME,
        tool_description: str = "提交来源约束的完整威胁报告结构化抽取结果。",
        response_model: type[BaseModel] = ReportExtraction,
        stage: str = "legacy_extraction",
        prompt_version: str = "report-extraction-v1",
        repair: bool = False,
    ) -> str:
        """Return the text block from one non-streaming MiniMax response."""
        _validate_safe_label(tool_name, "tool_name")
        _validate_safe_label(stage, "stage")
        _validate_safe_label(prompt_version, "prompt_version")
        if not tool_description.strip() or len(tool_description) > 500:
            raise MiniMaxError("MiniMax 工具描述必须为 1 到 500 个字符")
        protocol = _detect_protocol(self.credentials.base_url)
        if protocol == "anthropic":
            url = f"{self.credentials.base_url}/v1/messages"
            headers = {
                "Content-Type": "application/json",
                "X-Api-Key": self.credentials.api_key.get_secret_value(),
            }
            payload: dict[str, Any] = {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "stream": False,
                "temperature": DEFAULT_TEMPERATURE,
                "tools": [
                    {
                        "name": tool_name,
                        "description": tool_description,
                        "input_schema": _inline_local_schema_refs(
                            response_model.model_json_schema()
                        ),
                    }
                ],
                "tool_choice": {"type": "tool", "name": tool_name},
            }
        else:
            url = f"{self.credentials.base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.credentials.api_key.get_secret_value()}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "temperature": DEFAULT_TEMPERATURE,
                "max_completion_tokens": min(self.max_tokens, 12_000),
                "reasoning_split": True,
            }

        started = time.perf_counter()
        response = self._request_with_retries(url, headers, payload)
        input_tokens, output_tokens = _extract_usage(response, protocol)
        self.call_history.append(
            MiniMaxCallRecord(
                stage=stage,
                prompt_version=prompt_version,
                tool_name=tool_name,
                duration_seconds=max(0.0, time.perf_counter() - started),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                repair=repair,
            )
        )
        return _extract_response_text(response, protocol, tool_name, response_model)

    def _request_with_retries(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Retry only transient failures with a bounded backoff."""
        for attempt in range(self.max_retries + 1):
            try:
                return self._transport(url, headers, payload, self.timeout_seconds)
            except MiniMaxHttpError as exc:
                if not exc.retryable or attempt >= self.max_retries:
                    raise
                LOG.debug("Retrying MiniMax after HTTP %s", exc.status_code)
                delay = (
                    exc.retry_after_seconds
                    if exc.retry_after_seconds is not None
                    else float(5 * (2**attempt))
                )
            except MiniMaxError:
                if attempt >= self.max_retries:
                    raise
                LOG.debug("Retrying MiniMax after a transient transport error")
                delay = float(5 * (2**attempt))
            self._sleeper(min(max(delay, 0.0), 60.0))
        raise MiniMaxError("MiniMax 请求重试状态异常")


def _urllib_transport(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    """Send one JSON request using only the Python standard library."""
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read(10 * 1024 * 1024)
    except HTTPError as exc:
        retryable = exc.code == 429 or 500 <= exc.code <= 599
        retry_after_seconds: float | None = None
        retry_after = exc.headers.get("Retry-After") if exc.headers is not None else None
        if isinstance(retry_after, str):
            try:
                parsed_retry_after = float(retry_after.strip())
            except ValueError:
                parsed_retry_after = -1.0
            if parsed_retry_after >= 0:
                retry_after_seconds = min(parsed_retry_after, 60.0)
        raise MiniMaxHttpError(
            exc.code,
            retryable=retryable,
            retry_after_seconds=retry_after_seconds,
        ) from exc
    except (TimeoutError, URLError, OSError) as exc:
        raise MiniMaxError(f"MiniMax 网络请求失败：{type(exc).__name__}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MiniMaxError("MiniMax 返回了无法解析的 JSON 响应") from exc
    if not isinstance(parsed, dict):
        raise MiniMaxError("MiniMax HTTP 响应必须是 JSON 对象")
    return parsed


def _extract_response_text(
    response: dict[str, Any],
    protocol: str,
    tool_name: str,
    response_model: type[BaseModel],
) -> str:
    """Extract a tool input or text while discarding model thinking blocks."""
    if protocol == "anthropic":
        if response.get("stop_reason") == "max_tokens":
            raise MiniMaxOutputTruncatedError("MiniMax 输出达到 max_tokens 上限，JSON 可能被截断")
        blocks = response.get("content")
        if not isinstance(blocks, list):
            raise MiniMaxError("MiniMax Anthropic 响应缺少 content 列表")
        tool_inputs = [
            block.get("input")
            for block in blocks
            if isinstance(block, dict)
            and block.get("type") == "tool_use"
            and block.get("name") == tool_name
        ]
        if tool_inputs:
            if len(tool_inputs) != 1 or not isinstance(tool_inputs[0], dict):
                raise MiniMaxError("MiniMax 返回了无效或重复的报告提交工具调用")
            extraction_input = _unwrap_tool_input(tool_inputs[0], response_model)
            return json.dumps(extraction_input, ensure_ascii=False, separators=(",", ":"))
        text_blocks = [
            str(block.get("text") or "")
            for block in blocks
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        content = "\n".join(block for block in text_blocks if block.strip()).strip()
    else:
        choices = response.get("choices")
        if not isinstance(choices, list) or not choices:
            raise MiniMaxError("MiniMax OpenAI 响应缺少 choices")
        first = choices[0]
        if isinstance(first, dict) and first.get("finish_reason") == "length":
            raise MiniMaxOutputTruncatedError("MiniMax 输出达到 max_tokens 上限，JSON 可能被截断")
        message = first.get("message") if isinstance(first, dict) else None
        content = str(message.get("content") or "").strip() if isinstance(message, dict) else ""
    if not content:
        raise MiniMaxError("MiniMax 返回内容为空，可能触发了内容策略或接口错误")
    return content


def _unwrap_tool_input(
    tool_input: dict[str, Any],
    response_model: type[BaseModel],
) -> dict[str, Any]:
    """Remove only a redundant wrapper matching the requested model name."""
    unwrapped = tool_input
    if len(tool_input) == 1:
        wrapper_names = {
            response_model.__name__,
            re.sub(r"(?<!^)(?=[A-Z])", "_", response_model.__name__).lower(),
        }
        for wrapper_name in wrapper_names:
            wrapped = tool_input.get(wrapper_name)
            if isinstance(wrapped, dict):
                unwrapped = wrapped
                break
    return _decode_known_nested_json(unwrapped, response_model)


def _decode_known_nested_json(
    tool_input: dict[str, Any],
    response_model: type[BaseModel],
) -> dict[str, Any]:
    """Decode JSON-string containers only when the requested field expects one."""
    decoded = dict(tool_input)
    for field_name, field in response_model.model_fields.items():
        value = decoded.get(field_name)
        if not isinstance(value, str):
            continue
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            continue
        if _annotation_accepts_container(field.annotation, parsed):
            decoded[field_name] = parsed
    return decoded


def _annotation_accepts_container(annotation: Any, value: Any) -> bool:
    """Return whether a model annotation accepts the parsed list or object."""
    origin = get_origin(annotation)
    if origin is list:
        return isinstance(value, list)
    if origin is dict:
        return isinstance(value, dict)
    if origin in {UnionType, Union}:
        return any(_annotation_accepts_container(item, value) for item in get_args(annotation))
    return (
        isinstance(annotation, type)
        and issubclass(annotation, BaseModel)
        and isinstance(value, dict)
    )


def _extract_usage(response: dict[str, Any], protocol: str) -> tuple[int | None, int | None]:
    """Read token counts without retaining request or response content."""
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return None, None
    if protocol == "anthropic":
        return _optional_int(usage.get("input_tokens")), _optional_int(usage.get("output_tokens"))
    return _optional_int(usage.get("prompt_tokens")), _optional_int(usage.get("completion_tokens"))


def _optional_int(value: Any) -> int | None:
    """Return a non-negative integer token count when available."""
    return value if isinstance(value, int) and value >= 0 else None


def _inline_local_schema_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Inline Pydantic's local ``$defs`` references for MiniMax tool use."""
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        return schema

    def expand(value: Any, active_refs: frozenset[str] = frozenset()) -> Any:
        if isinstance(value, list):
            return [expand(item, active_refs) for item in value]
        if not isinstance(value, dict):
            return value
        reference = value.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/$defs/"):
            name = reference.removeprefix("#/$defs/")
            target = definitions.get(name)
            if not isinstance(target, dict) or name in active_refs:
                raise MiniMaxError("报告工具 Schema 包含无法解析的本地引用")
            expanded = expand(target, active_refs | {name})
            siblings = {
                key: expand(item, active_refs) for key, item in value.items() if key != "$ref"
            }
            return {**expanded, **siblings}
        return {key: expand(item, active_refs) for key, item in value.items() if key != "$defs"}

    expanded_schema = expand(schema)
    if not isinstance(expanded_schema, dict):
        raise MiniMaxError("报告工具 Schema 展开结果无效")
    return expanded_schema


def _split_labeled_value(line: str) -> tuple[str, str]:
    """Split a small key/value credential line without exposing its value."""
    for delimiter in ("=", ":", "："):
        if delimiter not in line:
            continue
        label, value = line.split(delimiter, 1)
        return label.strip().lower().replace("-", "_").replace(" ", "_"), value.strip()
    return "", ""


def _validate_safe_label(value: str, label: str) -> None:
    """Keep call-history labels bounded and incapable of carrying report text."""
    if _SAFE_LABEL_RE.fullmatch(value) is None:
        raise MiniMaxError(f"MiniMax {label} 只能使用短标识符")


def _validate_base_url(base_url: str) -> None:
    """Allow only official MiniMax HTTPS API hosts."""
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or parsed.hostname not in OFFICIAL_HOSTS:
        raise MiniMaxError("MiniMax base URL 必须使用官方 HTTPS API 域名")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise MiniMaxError("MiniMax base URL 不能包含凭据、查询参数或片段")


def _detect_protocol(base_url: str) -> str:
    """Infer the compatible protocol from the configured base path."""
    path = urlsplit(base_url).path.rstrip("/")
    return "anthropic" if path.endswith("/anthropic") else "openai"
