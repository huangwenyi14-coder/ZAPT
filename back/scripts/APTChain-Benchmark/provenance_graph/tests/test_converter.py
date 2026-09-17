"""Tests for the isolated provenance graph converter."""

import json
from pathlib import Path

from provenance_graph.converter import convert_dataset


def _write_jsonl(path: Path, values: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_process_file_flow_and_spade_direction(tmp_path: Path) -> None:
    """Process and file events retain event roles and causal-flow orientation."""
    dataset_root = tmp_path / "dataset"
    ecar_path = dataset_root / "data" / "host.example.local" / "ecar.json"
    parent_uuid = "00000000-0000-4000-8000-000000000001"
    child_uuid = "00000000-0000-4000-8000-000000000002"
    file_uuid = "00000000-0000-4000-8000-000000000003"
    _write_jsonl(
        ecar_path,
        [
            {
                "timestamp_ms": 1000,
                "id": "10000000-0000-4000-8000-000000000001",
                "hostname": "HOST",
                "object": "PROCESS",
                "action": "CREATE",
                "objectID": child_uuid,
                "actorID": parent_uuid,
                "pid": 20,
                "ppid": 10,
                "principal": "alice",
                "properties": {
                    "image_path": "/usr/bin/curl",
                    "parent_image_path": "/bin/bash",
                    "command_line": "curl example.test",
                },
            },
            {
                "timestamp_ms": 1100,
                "id": "10000000-0000-4000-8000-000000000002",
                "hostname": "HOST",
                "object": "FILE",
                "action": "READ",
                "objectID": file_uuid,
                "actorID": child_uuid,
                "pid": 20,
                "principal": "alice",
                "properties": {
                    "image_path": "/usr/bin/curl",
                    "file_path": "/home/alice/input.txt",
                },
            },
            {
                "timestamp_ms": 1200,
                "id": "10000000-0000-4000-8000-000000000003",
                "hostname": "HOST",
                "object": "PROCESS",
                "action": "TERMINATE",
                "objectID": child_uuid,
                "pid": 20,
                "principal": "alice",
                "properties": {"image_path": "/usr/bin/curl"},
            },
        ],
    )

    result = convert_dataset(
        dataset_name="fixture",
        dataset_root=dataset_root,
        output_root=tmp_path / "graphs",
        include_offline_labels=False,
    )

    edges = _read_jsonl(result.output_dir / "edges.jsonl")
    assert len(edges) == 3
    assert edges[0]["type"] == "EVENT_EXECUTE"
    assert edges[0]["causal_from"] == parent_uuid
    assert edges[0]["causal_to"] == child_uuid
    assert edges[1]["type"] == "EVENT_READ"
    assert edges[1]["subject_id"] == child_uuid
    assert edges[1]["object_id"] == file_uuid
    assert edges[1]["causal_from"] == file_uuid
    assert edges[1]["causal_to"] == child_uuid
    assert "label" not in edges[1]

    spade_records = _read_jsonl(result.output_dir / "spade.jsonl")
    first_edge_index = next(index for index, value in enumerate(spade_records) if "from" in value)
    assert all("from" not in value for value in spade_records[:first_edge_index])
    spade_read = next(
        value
        for value in spade_records[first_edge_index:]
        if value["annotations"]["cdm.type"] == "EVENT_READ"
    )
    assert spade_read["from"] == file_uuid
    assert spade_read["to"] == child_uuid
    assert spade_read["type"] == "SimpleEdge"


def test_user_session_actor_id_is_not_misclassified_as_process(tmp_path: Path) -> None:
    """Session-to-session actor references do not create conflicting subject nodes."""
    dataset_root = tmp_path / "dataset"
    ecar_path = dataset_root / "data" / "host.example.local" / "ecar.json"
    resumed_session = "20000000-0000-4000-8000-000000000001"
    login_session = "20000000-0000-4000-8000-000000000002"
    _write_jsonl(
        ecar_path,
        [
            {
                "timestamp_ms": 1000,
                "id": "30000000-0000-4000-8000-000000000001",
                "hostname": "HOST",
                "object": "USER_SESSION",
                "action": "LOGIN",
                "objectID": login_session,
                "actorID": resumed_session,
                "principal": "alice",
                "properties": {"outcome": "success", "logon_type": "7"},
            },
            {
                "timestamp_ms": 1100,
                "id": "30000000-0000-4000-8000-000000000002",
                "hostname": "HOST",
                "object": "USER_SESSION",
                "action": "LOGOUT",
                "objectID": resumed_session,
                "principal": "alice",
                "properties": {"logon_type": "2"},
            },
        ],
    )

    result = convert_dataset(
        dataset_name="session-fixture",
        dataset_root=dataset_root,
        output_root=tmp_path / "graphs",
        include_offline_labels=False,
    )
    nodes = _read_jsonl(result.output_dir / "nodes.jsonl")
    resumed_node = next(value for value in nodes if value["id"] == resumed_session)
    assert resumed_node["type"] == "SESSION"
