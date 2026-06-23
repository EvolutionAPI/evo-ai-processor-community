"""JSON-safety normalization for ADK event payloads — EVO-1752.

``GET /sessions/{id}/messages`` returned 500 because an ADK event field reached
``JSONResponse`` as a ``set``. ``normalize_event_for_json`` walks the event
dict and coerces non-JSON-serializable values so the full ``processed_events``
payload survives ``json.dumps``.

Kept dependency-free (only ``base64`` + logging) so the regression spec can
import it without spinning up the FastAPI / ADK runtime stack.
"""

from __future__ import annotations

import base64
import logging

logger = logging.getLogger(__name__)


def normalize_event_for_json(d):
    """Recursively coerce non-JSON-serializable values inside an ADK event dict.

    Conversions:
    - ``bytes`` → base64-encoded ``str``
    - ``set`` / ``frozenset`` → ``list`` (then recursed into, because sets
      may contain ``bytes`` or ``frozenset`` items that still need processing)

    Mutates ``d`` in place and returns it.
    """
    if isinstance(d, dict):
        for key, value in list(d.items()):
            if isinstance(value, bytes):
                try:
                    d[key] = base64.b64encode(value).decode("utf-8")
                    logger.debug(f"Converted bytes field to base64: {key}")
                except Exception as e:
                    logger.error(f"Error encoding bytes to base64: {str(e)}")
                    d[key] = None
            elif isinstance(value, (set, frozenset)):
                logger.debug(
                    f"Converted {type(value).__name__} field to list: "
                    f"{key} (size={len(value)})"
                )
                d[key] = list(value)
                normalize_event_for_json(d[key])
            elif isinstance(value, dict):
                normalize_event_for_json(value)
            elif isinstance(value, list):
                normalize_event_for_json(value)
    elif isinstance(d, list):
        for i, item in enumerate(d):
            if isinstance(item, bytes):
                try:
                    d[i] = base64.b64encode(item).decode("utf-8")
                except Exception as e:
                    logger.error(
                        f"Error encoding bytes to base64 in list: {str(e)}"
                    )
                    d[i] = None
            elif isinstance(item, (set, frozenset)):
                logger.debug(
                    f"Converted {type(item).__name__} item to list "
                    f"(size={len(item)})"
                )
                d[i] = list(item)
                normalize_event_for_json(d[i])
            elif isinstance(item, (dict, list)):
                normalize_event_for_json(item)
    return d
