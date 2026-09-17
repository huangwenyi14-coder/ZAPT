"""Validated models for the provenance graph experiment."""

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DatasetSpec(BaseModel):
    """One EvidenceForge output directory to convert."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, description="Stable dataset name used for output paths.")
    source: Path = Field(description="EvidenceForge dataset root containing data/.")

    @field_validator("source")
    @classmethod
    def require_relative_source(cls, value: Path) -> Path:
        """Keep the checked-in catalog portable across workspaces."""
        if value.is_absolute():
            raise ValueError("catalog source paths must be relative to the repository root")
        return value


class DatasetCatalog(BaseModel):
    """Catalog of datasets included in the experiment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    datasets: list[DatasetSpec] = Field(min_length=1)


class EcarRecord(BaseModel):
    """Fields emitted by EvidenceForge's eCAR renderer."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    timestamp_ms: int = Field(ge=0)
    id: str = Field(min_length=1)
    hostname: str = Field(min_length=1)
    object: str = Field(min_length=1)
    action: str = Field(min_length=1)
    object_id: str = Field(alias="objectID", min_length=1)
    actor_id: str | None = Field(default=None, alias="actorID")
    pid: int | None = Field(default=None, ge=0)
    tid: int | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    principal: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


NodeType = Literal[
    "HOST",
    "PRINCIPAL",
    "SUBJECT",
    "FILE_OBJECT",
    "NET_FLOW_OBJECT",
    "REGISTRY_KEY_OBJECT",
    "SESSION",
    "THREAD",
    "UNKNOWN_OBJECT",
]


class GraphNode(BaseModel):
    """A CDM-inspired provenance graph entity."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1.0"] = "0.1.0"
    id: str
    type: NodeType
    host: str | None = None
    natural_key: str
    first_seen_ns: int = Field(ge=0)
    last_seen_ns: int = Field(ge=0)
    properties: dict[str, Any] = Field(default_factory=dict)


class SourceReference(BaseModel):
    """Location of the raw data record that produced an edge."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["ecar"] = "ecar"
    relative_path: str
    record_index: int = Field(ge=0)
    source_instance: str


class GraphEdge(BaseModel):
    """A CDM-inspired event edge with explicit causal-flow orientation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1.0"] = "0.1.0"
    id: str
    sequence: int = Field(ge=0)
    timestamp_ns: int = Field(ge=0)
    type: str
    subject_id: str
    object_id: str | None = None
    causal_from: str | None = None
    causal_to: str | None = None
    host: str
    properties: dict[str, Any] = Field(default_factory=dict)
    source: SourceReference


class EdgeLabel(BaseModel):
    """Offline-only label joined to a graph edge after conversion."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1.0"] = "0.1.0"
    edge_id: str
    label: Literal["benign", "malicious"]
    storyline_id: str | None = None
    contributing_storyline_ids: list[str] = Field(default_factory=list)
    logical_event_id: str | None = None
    contributing_logical_event_ids: list[str] = Field(default_factory=list)
    physical_record_id: str
    event_type: str
    provenance_kind: str
    detectability_class: str
    detectability_reason: str
    causal_parentage_status: str
    parent_logical_event_ids: list[str] = Field(default_factory=list)


class ConversionResult(BaseModel):
    """Summary returned by a completed dataset conversion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset: str
    output_dir: Path
    node_count: int
    edge_count: int
    labeled_edge_count: int
    malicious_edge_count: int
    readiness_score: float | None


class SpadeVertex(BaseModel):
    """A vertex accepted by SPADE's JSON reporter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    type: Literal["Subject", "Object", "Principal"]
    annotations: dict[str, str]


class SpadeEdge(BaseModel):
    """A CDM-style edge accepted by SPADE's JSON reporter."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    from_id: str = Field(alias="from")
    to_id: str = Field(alias="to")
    type: Literal["SimpleEdge"] = "SimpleEdge"
    annotations: dict[str, str]
