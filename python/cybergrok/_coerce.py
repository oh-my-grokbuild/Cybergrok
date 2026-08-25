"""Untyped stdlib FFI (json / yaml / urllib / regex). Callers pass typed values only.

typeshed types these APIs as Any. This is the single file that touches them.
"""

# pyright: reportAny=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownParameterType=false
# pyright: reportExplicitAny=false
# pyright: reportUnnecessaryCast=false

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.request import OpenerDirector, Request

import yaml
from jinja2 import Template


def json_loads(raw: str) -> object:
    return json.loads(raw)


def json_object(raw: str) -> dict[str, object]:
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise TypeError("JSON value is not an object")
    return as_str_map(parsed)


def yaml_load(raw: str) -> object:
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RuntimeError(str(exc)) from exc


def yaml_load_map(raw: str) -> dict[str, object]:
    data = yaml_load(raw)
    if not isinstance(data, dict):
        raise TypeError("YAML value is not a mapping")
    return as_str_map(data)


def as_str_map(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, object] = {}
    for key, item in value.items():
        out[str(key)] = item
    return out


def as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def as_objects(value: object) -> list[object]:
    if not isinstance(value, list):
        return []
    return list(value)


def as_paths(value: object) -> list[Path]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Path)]


def render_template(source: str, context: dict[str, object]) -> str:
    return str(Template(source).render(**context))


def as_maps(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [as_str_map(item) for item in value]


def first_regex_group(pattern: re.Pattern[str], text: str) -> str:
    matches = pattern.findall(text)
    if not matches:
        return ""
    return str(matches[0])


def read_limited_text(resp: Any, limit: int) -> str:
    raw = resp.read(limit)
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="ignore")
    return str(raw)


def response_headers(resp: Any) -> dict[str, str]:
    headers = getattr(resp, "headers", None)
    if headers is None:
        return {}
    items = getattr(headers, "items", None)
    if not callable(items):
        return {}
    pairs: Any = items()
    return {str(key): str(val) for key, val in pairs}


def response_url(resp: Any, fallback: str) -> str:
    geturl = getattr(resp, "geturl", None)
    if not callable(geturl):
        return fallback
    return str(geturl())


def response_status(resp: Any, default: int = 200) -> int:
    return int(str(getattr(resp, "status", default)))


def open_limited(opener: OpenerDirector, req: Request, timeout: int, limit: int) -> str:
    with opener.open(req, timeout=timeout) as resp:
        return read_limited_text(resp, limit)


def open_probe(
    opener: OpenerDirector, req: Request, timeout: int, limit: int, fallback_url: str
) -> tuple[str, dict[str, str], int, str]:
    with opener.open(req, timeout=timeout) as resp:
        return (
            read_limited_text(resp, limit),
            response_headers(resp),
            response_status(resp),
            response_url(resp, fallback_url),
        )
