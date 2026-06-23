"""Regression spec for EVO-1752 — ADK event normalization for JSON response.

``GET /sessions/{id}/messages`` returned 500 because an ADK event field reached
``JSONResponse`` as a ``set`` (not JSON-serializable). ``normalize_event_for_json``
walks the event dict and coerces ``set``/``frozenset`` to ``list`` and ``bytes``
to base64, so the entire ``processed_events`` payload survives ``json.dumps``.

These specs exercise the helper directly so they do not depend on the FastAPI
stack, the ADK runtime, or the auth middleware.
"""

from __future__ import annotations

import base64
import json

import pytest

from src.utils.event_json import normalize_event_for_json


def test_top_level_set_field_becomes_list():
    event = {"branch": {"a", "b"}}

    out = normalize_event_for_json(event)

    assert isinstance(out["branch"], list)
    assert set(out["branch"]) == {"a", "b"}
    json.dumps(out)  # must not raise


def test_top_level_frozenset_field_becomes_list():
    event = {"requested_auth_configs": frozenset(["scope:read", "scope:write"])}

    out = normalize_event_for_json(event)

    assert isinstance(out["requested_auth_configs"], list)
    assert set(out["requested_auth_configs"]) == {"scope:read", "scope:write"}
    json.dumps(out)


def test_set_nested_inside_dict_inside_list():
    event = {"events": [{"meta": {"tags": {"x", "y"}}}]}

    out = normalize_event_for_json(event)

    assert isinstance(out["events"][0]["meta"]["tags"], list)
    assert set(out["events"][0]["meta"]["tags"]) == {"x", "y"}
    json.dumps(out)


def test_set_as_direct_list_item_becomes_list():
    event = {"items": [{"a"}, {"b", "c"}]}

    out = normalize_event_for_json(event)

    assert all(isinstance(item, list) for item in out["items"])
    assert {tuple(sorted(item)) for item in out["items"]} == {("a",), ("b", "c")}
    json.dumps(out)


def test_bytes_inside_set_get_base64_encoded():
    """Sets may contain bytes (hashable). After set→list conversion the helper
    must recurse so the bytes do not survive into the JSON payload.
    """
    payload = b"\x00\x01\x02hello"
    event = {"blobs": {payload}}

    out = normalize_event_for_json(event)

    assert isinstance(out["blobs"], list)
    assert out["blobs"] == [base64.b64encode(payload).decode("utf-8")]
    json.dumps(out)


def test_bytes_as_direct_list_item_get_base64_encoded():
    """Regression for the refactor that replaced the manual list-iteration
    branch with ``normalize_event_for_json(value)``: bytes sitting directly in
    a list (not in a sub-dict) must now also be base64-encoded.
    """
    payload = b"raw-bytes"
    event = {"blobs": [payload, {"nested": payload}]}

    out = normalize_event_for_json(event)

    encoded = base64.b64encode(payload).decode("utf-8")
    assert out["blobs"][0] == encoded
    assert out["blobs"][1]["nested"] == encoded
    json.dumps(out)


def test_frozenset_inside_set_is_normalized_recursively():
    inner = frozenset(["a", "b"])
    event = {"sets_of_sets": {inner}}

    out = normalize_event_for_json(event)

    assert isinstance(out["sets_of_sets"], list)
    assert len(out["sets_of_sets"]) == 1
    assert isinstance(out["sets_of_sets"][0], list)
    assert set(out["sets_of_sets"][0]) == {"a", "b"}
    json.dumps(out)


def test_plain_values_are_untouched():
    event = {
        "id": "evt-1",
        "ts": 1718900000,
        "ok": True,
        "score": 0.42,
        "missing": None,
        "tags": ["x", "y"],
        "meta": {"k": "v"},
    }
    snapshot = json.dumps(event, sort_keys=True)

    out = normalize_event_for_json(event)

    assert json.dumps(out, sort_keys=True) == snapshot


def test_returns_same_object_mutated_in_place():
    event = {"branch": {"a"}}

    out = normalize_event_for_json(event)

    assert out is event


@pytest.mark.parametrize("empty", [set(), frozenset()])
def test_empty_set_becomes_empty_list(empty):
    event = {"k": empty}

    out = normalize_event_for_json(event)

    assert out["k"] == []
    json.dumps(out)
