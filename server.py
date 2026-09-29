#!/usr/bin/env python3
"""
mcp-server-glitchtip - MCP server enabling LLMs to query GlitchTip issues,
stacktraces, and event details in a read-only way.

GlitchTip is an open-source, self-hosted error tracking platform that's
API-compatible with Sentry. This MCP server lets AI assistants directly
access your error data to help debug and fix issues faster. Mutating
operations (resolve/ignore/delete) are intentionally not exposed as MCP tools.

https://github.com/hffmnnj/mcp-server-glitchtip
"""

import ipaddress
import json
import logging
import os
import re
import socket
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
import mcp.types as types
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

ALLOWED_STATUSES = frozenset({"unresolved", "resolved", "ignored"})

# Privacy-safe event projection limits (fail-closed)
_REDACTED = "[REDACTED]"
_OMITTED = "[OMITTED]"
_MAX_EVENT_STRING_LEN = 500
_MAX_EVENT_LIST_ITEMS = 50
_MAX_EVENT_DEPTH = 8
_MAX_BREADCRUMBS = 20
_MAX_TAGS = 40
_MAX_PROJECTION_CHARS = 24000
_MAX_EVENTS_LIMIT = 50
_DEFAULT_EVENTS_LIMIT = 10

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|auth|authorization|session|"
    r"cookie|csrf|dsn|credential|private[_-]?key|access[_-]?key|refresh|"
    r"bearer|xsrf|jwt|client[_-]?secret)",
    re.IGNORECASE,
)

_SENSITIVE_HEADERS = frozenset({
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-session-id",
    "x-amz-security-token",
})

_ALLOWED_REQUEST_HEADERS = frozenset({
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "cf-connecting-ip",
    "true-client-ip",
    "via",
    "host",
    "user-agent",
    "accept",
    "referer",
    "content-type",
    "content-length",
    "accept-language",
})

# Strict diagnostic response headers only (never cookie/auth/token-like names).
_ALLOWED_RESPONSE_HEADERS = frozenset({
    "content-type",
    "content-length",
    "cache-control",
    "location",
    "server",
    "date",
    "via",
    "x-request-id",
    "x-correlation-id",
})

_ALLOWED_ENV_KEYS = frozenset({
    "remote_addr",
    "server_name",
    "server_port",
    "request_method",
    "request_uri",
    "server_protocol",
    "https",
})

# Fail-closed context categories useful for runtime diagnosis (never "user"/extras).
_ALLOWED_CONTEXT_CATEGORIES = frozenset({
    "runtime",
    "os",
    "browser",
    "device",
    "trace",
    "app",
})

_ALLOWED_CONTEXT_FIELDS: dict[str, frozenset[str]] = {
    "runtime": frozenset({"name", "version", "build"}),
    "os": frozenset({"name", "version", "build", "kernel_version"}),
    "browser": frozenset({"name", "version"}),
    "device": frozenset({
        "family",
        "model",
        "arch",
        "name",
        "brand",
        "simulator",
        "orientation",
    }),
    "trace": frozenset({
        "trace_id",
        "span_id",
        "parent_span_id",
        "op",
        "status",
        "origin",
        "type",
        "sampled",
    }),
    "app": frozenset({
        "app_name",
        "app_version",
        "app_identifier",
        "build_type",
        "app_start_time",
    }),
}

# Breadcrumb metadata only — never message/data/query payloads.
_ALLOWED_BREADCRUMB_FIELDS = frozenset({
    "category",
    "type",
    "level",
    "timestamp",
})

# Private and metadata IP ranges (for SSRF prevention)
_PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "169.254.", "127.",
)


def validate_issue_id(value: str | None) -> bool:
    """Return True only if value is non-empty, stripped, and digits only."""
    if value is None:
        return False
    s = str(value).strip()
    return bool(s and re.match(r"^\d+$", s))


def validate_slug(value: str | None) -> bool:
    """Return True if non-empty and safe slug (letters, numbers, hyphen, underscore)."""
    if value is None:
        return False
    s = str(value).strip()
    return bool(s and re.match(r"^[a-zA-Z0-9_-]+$", s))


def validate_event_id(value: str | None) -> bool:
    """Return True if value looks like a safe Sentry/GlitchTip event id."""
    if value is None:
        return False
    s = str(value).strip()
    return bool(s and re.match(r"^[a-zA-Z0-9_-]{1,64}$", s))


def normalize_status(value: str | None) -> str:
    """Return value if in ALLOWED_STATUSES, else 'unresolved'."""
    if value in ALLOWED_STATUSES:
        return value
    return "unresolved"


def normalize_events_limit(value: int | str | None) -> int:
    """Clamp pagination limit to a safe positive bound."""
    try:
        n = int(value) if value is not None else _DEFAULT_EVENTS_LIMIT
    except (TypeError, ValueError):
        return _DEFAULT_EVENTS_LIMIT
    if n < 1:
        return 1
    return min(n, _MAX_EVENTS_LIMIT)


def _is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(str(key)))


def _truncate_string(value: str, max_len: int = _MAX_EVENT_STRING_LEN) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 15] + "...[truncated]"


def _sanitize_value(value, *, depth: int = 0, omissions: list[str] | None = None):
    """Recursively redact sensitive keys and bound size. Fail-closed on uncertainty."""
    if omissions is None:
        omissions = []
    if depth > _MAX_EVENT_DEPTH:
        omissions.append("max_depth_exceeded")
        return _OMITTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _truncate_string(value)
    if isinstance(value, dict):
        out = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= _MAX_EVENT_LIST_ITEMS:
                omissions.append("dict_items_truncated")
                break
            key = str(k)
            if _is_sensitive_key(key):
                out[key] = _REDACTED
            else:
                out[key] = _sanitize_value(v, depth=depth + 1, omissions=omissions)
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for i, item in enumerate(value):
            if i >= _MAX_EVENT_LIST_ITEMS:
                omissions.append("list_items_truncated")
                break
            out.append(_sanitize_value(item, depth=depth + 1, omissions=omissions))
        return out
    # Unknown / non-JSON-serializable types are omitted (fail-closed)
    omissions.append(f"unsupported_type:{type(value).__name__}")
    return _OMITTED


def _header_map(raw) -> dict[str, str]:
    """Normalize header structures (dict or list of pairs) to a lowercase-key map."""
    result: dict[str, str] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, (list, tuple)):
                v = ", ".join(str(x) for x in v)
            result[str(k).lower()] = str(v)
    elif isinstance(raw, (list, tuple)):
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                result[str(item[0]).lower()] = str(item[1])
            elif isinstance(item, dict) and "key" in item:
                result[str(item.get("key", "")).lower()] = str(item.get("value", ""))
    return result


def _sanitize_headers(raw, *, allowed: frozenset[str] | None = None) -> dict[str, str]:
    """Keep only allowlisted headers; always redact known sensitive names (case-insensitive)."""
    headers = _header_map(raw)
    out: dict[str, str] = {}
    for name, value in headers.items():
        lname = name.lower()
        if lname in _SENSITIVE_HEADERS or _is_sensitive_key(lname):
            continue
        if allowed is not None and lname not in allowed:
            continue
        out[lname] = _truncate_string(value, 300)
    return out


def _sanitize_query(raw, omissions: list[str]) -> dict | str | None:
    """Sanitize query string / params. Omit when structure is uncertain."""
    if raw is None or raw == "":
        return None
    pairs: list[tuple[str, str]] = []
    if isinstance(raw, str):
        try:
            pairs = [(k, v) for k, v in parse_qsl(raw.lstrip("?"), keep_blank_values=True)]
        except Exception:
            omissions.append("query_string: omitted (parse failed)")
            return None
    elif isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, (list, tuple)):
                for item in v:
                    pairs.append((str(k), str(item)))
            else:
                pairs.append((str(k), "" if v is None else str(v)))
    elif isinstance(raw, (list, tuple)):
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                pairs.append((str(item[0]), str(item[1])))
            else:
                omissions.append("query_string: omitted (uncertain structure)")
                return None
    else:
        omissions.append("query_string: omitted (uncertain type)")
        return None

    sanitized: dict[str, str] = {}
    for i, (k, v) in enumerate(pairs):
        if i >= _MAX_EVENT_LIST_ITEMS:
            omissions.append("query_string: truncated")
            break
        if _is_sensitive_key(k):
            sanitized[k] = _REDACTED
        else:
            sanitized[k] = _truncate_string(v, 200)
    return sanitized


def _sanitize_url(url: str | None, omissions: list[str]) -> str | None:
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
        # Drop userinfo (credentials in URL)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        safe_q = []
        for k, v in query_pairs:
            if _is_sensitive_key(k):
                safe_q.append((k, _REDACTED))
            else:
                safe_q.append((k, _truncate_string(v, 200)))
        return urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            "",
            urlencode(safe_q),
            "",
        ))
    except Exception:
        omissions.append("url: omitted (parse failed)")
        return None


def _sanitize_structured_body(body, omissions: list[str], *, field_label: str):
    """
    Sanitize structured body/data. Dict/list are sanitized recursively.
    JSON or form-like strings are parsed then sanitized; arbitrary plain
    strings are omitted (fail-closed — never returned verbatim).
    """
    if body is None or body == "":
        return None, None
    if isinstance(body, (dict, list)):
        return _sanitize_value(body, omissions=omissions), None
    if isinstance(body, str):
        stripped = body.strip()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(stripped)
                return _sanitize_value(parsed, omissions=omissions), None
            except (json.JSONDecodeError, TypeError):
                omissions.append(f"{field_label}: omitted (non-JSON string)")
                return None, f"{field_label} omitted (non-JSON string)."
        if ("=" in stripped and "&" in stripped) or (
            "=" in stripped and len(stripped) < 500 and " " not in stripped
        ):
            parsed_q = _sanitize_query(stripped, omissions)
            if parsed_q is not None:
                return parsed_q, None
            omissions.append(f"{field_label}: omitted (uncertain sensitivity)")
            return None, f"{field_label} omitted (uncertain sensitivity)."
        omissions.append(f"{field_label}: omitted (non-structured string)")
        return None, f"{field_label} omitted (non-structured string)."
    omissions.append(f"{field_label}: omitted (unsupported type)")
    return _OMITTED, f"{field_label} omitted (unsupported type)."


def _project_contexts(contexts: dict, omissions: list[str]) -> dict:
    """Allowlist runtime/os/browser/device/trace/app scalars only; never user/extras."""
    projected: dict = {}
    for raw_key, raw_val in contexts.items():
        key = str(raw_key)
        lkey = key.lower()
        if lkey == "response":
            continue  # projected separately
        if lkey == "user" or lkey not in _ALLOWED_CONTEXT_CATEGORIES:
            omissions.append(f"contexts.{key}: omitted (not allowlisted)")
            continue
        if not isinstance(raw_val, dict):
            omissions.append(f"contexts.{key}: omitted (non-object)")
            continue
        allowed_fields = _ALLOWED_CONTEXT_FIELDS.get(lkey, frozenset())
        out: dict = {}
        for fk, fv in raw_val.items():
            fname = str(fk)
            if fname.lower() not in allowed_fields or _is_sensitive_key(fname):
                continue
            if isinstance(fv, (bool, int, float)) or fv is None:
                out[fname] = fv
            elif isinstance(fv, str):
                out[fname] = _truncate_string(fv, 200)
            else:
                omissions.append(f"contexts.{key}.{fname}: omitted (non-scalar)")
        if out:
            projected[key] = out
        else:
            omissions.append(f"contexts.{key}: omitted (no allowlisted fields)")
    return projected


def _project_breadcrumbs(breadcrumbs, omissions: list[str]) -> list[dict]:
    """Emit only bounded breadcrumb metadata; never message/data/query payloads."""
    if isinstance(breadcrumbs, dict):
        breadcrumbs = breadcrumbs.get("values", breadcrumbs)
    if not isinstance(breadcrumbs, list) or not breadcrumbs:
        return []
    out: list[dict] = []
    for i, item in enumerate(breadcrumbs[:_MAX_BREADCRUMBS]):
        if not isinstance(item, dict):
            continue
        meta: dict = {}
        for field in _ALLOWED_BREADCRUMB_FIELDS:
            if field not in item:
                continue
            val = item[field]
            if isinstance(val, (bool, int, float)) or val is None:
                meta[field] = val
            elif isinstance(val, str):
                meta[field] = _truncate_string(val, 100)
            else:
                omissions.append(f"breadcrumbs[{i}].{field}: omitted (non-scalar)")
        if meta:
            out.append(meta)
    if len(breadcrumbs) > _MAX_BREADCRUMBS:
        omissions.append("breadcrumbs: truncated")
    return out


def _extract_request_section(event_data: dict, omissions: list[str]) -> dict:
    """Pull request URL/method/headers/env from Sentry-compatible event shapes."""
    request = event_data.get("request")
    if not isinstance(request, dict):
        # entries may contain request
        for entry in event_data.get("entries") or []:
            if isinstance(entry, dict) and entry.get("type") == "request":
                data = entry.get("data")
                if isinstance(data, dict):
                    request = data
                    break
    if not isinstance(request, dict):
        return {}

    section: dict = {}
    url = _sanitize_url(request.get("url"), omissions)
    if url:
        section["url"] = url
    method = request.get("method")
    if isinstance(method, str) and method:
        section["method"] = method.upper()[:16]

    qs = _sanitize_query(
        request.get("query_string", request.get("query")),
        omissions,
    )
    if qs is not None:
        section["query_string"] = qs

    headers = _sanitize_headers(
        request.get("headers"),
        allowed=_ALLOWED_REQUEST_HEADERS,
    )
    if headers:
        section["headers"] = headers

    env_raw = request.get("env") or request.get("environment")
    if isinstance(env_raw, dict):
        env_out = {}
        for k, v in env_raw.items():
            lk = str(k).lower()
            if lk in _ALLOWED_ENV_KEYS and not _is_sensitive_key(lk):
                env_out[str(k)] = _truncate_string(str(v), 200)
            elif lk == "remote_addr":
                env_out["REMOTE_ADDR"] = _truncate_string(str(v), 200)
        if env_out:
            section["env"] = env_out
    elif env_raw is not None:
        omissions.append("request.env: omitted (uncertain structure)")

    body = request.get("data", request.get("body"))
    sanitized, _note = _sanitize_structured_body(
        body, omissions, field_label="request.data"
    )
    if sanitized is not None:
        section["data"] = sanitized

    return section


def _extract_response_section(event_data: dict, omissions: list[str]) -> dict:
    """Represent response telemetry honestly; never invent missing fields."""
    contexts = event_data.get("contexts") if isinstance(event_data.get("contexts"), dict) else {}
    response = None
    if isinstance(event_data.get("response"), dict):
        response = event_data["response"]
    elif isinstance(contexts.get("response"), dict):
        response = contexts["response"]

    if not isinstance(response, dict) or not response:
        return {
            "present": False,
            "note": "No response telemetry recorded on this event.",
        }

    section: dict = {"present": True}
    for key in ("status_code", "status", "statusCode"):
        if key in response and response[key] is not None:
            section["status_code"] = response[key]
            break
    if "headers" in response:
        section["headers"] = _sanitize_headers(
            response.get("headers"),
            allowed=_ALLOWED_RESPONSE_HEADERS,
        )
    body = response.get("body", response.get("data"))
    if body is None:
        section["body"] = None
        section["body_note"] = "No response body recorded."
    else:
        sanitized, note = _sanitize_structured_body(
            body, omissions, field_label="response.body"
        )
        if sanitized is not None:
            section["body"] = sanitized
        else:
            section["body"] = None
            section["body_note"] = note or "response.body omitted."
    return section


def _extract_exception_summary(event_data: dict) -> dict | None:
    for entry in event_data.get("entries") or []:
        if not isinstance(entry, dict) or entry.get("type") != "exception":
            continue
        values = (entry.get("data") or {}).get("values") or []
        if values and isinstance(values[0], dict):
            exc = values[0]
            return {
                "type": _truncate_string(str(exc.get("type") or "Unknown"), 200),
                "value": _truncate_string(str(exc.get("value") or ""), 500),
            }
    exception = event_data.get("exception")
    if isinstance(exception, dict):
        values = exception.get("values") or []
        if values and isinstance(values[0], dict):
            exc = values[0]
            return {
                "type": _truncate_string(str(exc.get("type") or "Unknown"), 200),
                "value": _truncate_string(str(exc.get("value") or ""), 500),
            }
    return None


def _projection_size(obj: dict) -> int:
    return len(json.dumps(obj, default=str))


def _bound_projection(obj: dict) -> dict:
    """Ensure serialized projection stays within a hard character budget."""
    try:
        if _projection_size(obj) <= _MAX_PROJECTION_CHARS:
            return obj
    except (TypeError, ValueError):
        return {
            "error": "Unable to serialize sanitized projection.",
            "omissions": ["serialization_failed"],
        }

    trimmed = dict(obj)
    omissions = list(trimmed["omissions"]) if isinstance(trimmed.get("omissions"), list) else []

    # Drop bulky optional sections first
    for key in ("breadcrumbs", "contexts", "tags", "request", "response", "exception", "message"):
        if key not in trimmed:
            continue
        trimmed[key] = _OMITTED
        omissions.append(f"{key}: omitted due to size limit")
        trimmed["omissions"] = omissions
        try:
            if _projection_size(trimmed) <= _MAX_PROJECTION_CHARS:
                trimmed["note"] = "Projection truncated to size limit."
                return trimmed
        except (TypeError, ValueError):
            break

    # Last resort: core identifiers only, still hard-capped
    core = {
        "event_id": trimmed.get("event_id"),
        "issue_id": trimmed.get("issue_id"),
        "timestamp": trimmed.get("timestamp"),
        "title": trimmed.get("title"),
        "platform": trimmed.get("platform"),
        "note": "Projection truncated to size limit.",
        "omissions": omissions + ["projection: reduced to core identifiers due to size limit"],
    }
    try:
        if _projection_size(core) <= _MAX_PROJECTION_CHARS:
            return core
    except (TypeError, ValueError):
        pass

    # Extreme edge: truncate remaining string fields until under budget
    for field in ("title", "timestamp", "platform", "event_id", "issue_id"):
        val = core.get(field)
        if isinstance(val, str) and len(val) > 32:
            core[field] = _truncate_string(val, 32)
        try:
            if _projection_size(core) <= _MAX_PROJECTION_CHARS:
                return core
        except (TypeError, ValueError):
            break

    # Absolute fail-closed minimum
    minimal = {
        "event_id": str(core.get("event_id") or "")[:64],
        "issue_id": str(core.get("issue_id") or "")[:64] if core.get("issue_id") is not None else None,
        "note": "Projection truncated to size limit.",
        "omissions": ["projection: hard size limit enforced"],
    }
    return minimal


def project_event_for_analysis(event_data: dict | None) -> dict:
    """
    Build a sanitized, analysis-oriented projection of a GlitchTip/Sentry event.
    Never returns raw cookies, auth headers, tokens, or credential-bearing fields.
    """
    if not isinstance(event_data, dict):
        return {"error": "Invalid event payload.", "omissions": ["invalid_payload"]}

    omissions: list[str] = []
    tags_raw = event_data.get("tags")
    tags: dict = {}
    if isinstance(tags_raw, dict):
        for i, (k, v) in enumerate(tags_raw.items()):
            if i >= _MAX_TAGS:
                omissions.append("tags: truncated")
                break
            if _is_sensitive_key(str(k)):
                tags[str(k)] = _REDACTED
            else:
                tags[str(k)] = _truncate_string(str(v), 200)
    elif isinstance(tags_raw, list):
        for i, item in enumerate(tags_raw):
            if i >= _MAX_TAGS:
                omissions.append("tags: truncated")
                break
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                k, v = str(item[0]), item[1]
            elif isinstance(item, dict):
                k, v = str(item.get("key", "")), item.get("value", "")
            else:
                continue
            if _is_sensitive_key(k):
                tags[k] = _REDACTED
            else:
                tags[k] = _truncate_string(str(v), 200)

    # Prefer explicit fields; fall back to tag values commonly used by Sentry
    def _tag(name: str) -> str | None:
        for key, val in tags.items():
            if key.lower() == name.lower() and val != _REDACTED:
                return val
        return None

    issue_id = event_data.get("groupID", event_data.get("group_id", event_data.get("issue_id")))
    title = event_data.get("title")
    metadata = event_data.get("metadata")
    if not title and isinstance(metadata, dict):
        title = metadata.get("title") or metadata.get("type")

    projection: dict = {
        "event_id": str(event_data.get("eventID") or event_data.get("id") or event_data.get("event_id") or ""),
        "issue_id": str(issue_id) if issue_id is not None else None,
        "timestamp": event_data.get("dateCreated") or event_data.get("timestamp") or event_data.get("datetime"),
        "title": _truncate_string(str(title), 300) if title else None,
        "message": _truncate_string(str(event_data["message"]), 500) if event_data.get("message") else None,
        "platform": event_data.get("platform") or _tag("platform"),
        "environment": event_data.get("environment") or _tag("environment"),
        "release": event_data.get("release") or _tag("release"),
        "transaction": event_data.get("transaction") or _tag("transaction"),
        "logger": event_data.get("logger"),
        "server_name": event_data.get("server_name") or _tag("server_name"),
    }

    if tags:
        projection["tags"] = tags

    exc = _extract_exception_summary(event_data)
    if exc:
        projection["exception"] = exc

    request_section = _extract_request_section(event_data, omissions)
    if request_section:
        projection["request"] = request_section

    projection["response"] = _extract_response_section(event_data, omissions)

    contexts = event_data.get("contexts")
    if isinstance(contexts, dict) and contexts:
        projected_ctx = _project_contexts(contexts, omissions)
        if projected_ctx:
            projection["contexts"] = projected_ctx

    breadcrumbs = event_data.get("breadcrumbs")
    if breadcrumbs:
        projected_crumbs = _project_breadcrumbs(breadcrumbs, omissions)
        if projected_crumbs:
            projection["breadcrumbs"] = projected_crumbs

    if omissions:
        # dedupe while preserving order
        seen = set()
        unique = []
        for item in omissions:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        projection["omissions"] = unique

    return _bound_projection(projection)


def event_projection_to_text(projection: dict) -> str:
    """Serialize a sanitized projection as stable JSON text for MCP tool results."""
    return json.dumps(projection, indent=2, default=str, ensure_ascii=False)


def _is_private_or_metadata_ip(host: str) -> bool:
    """Return True if host resolves to a private or metadata IP."""
    import socket
    try:
        # getaddrinfo can return IPv4 and IPv6
        for res in socket.getaddrinfo(host, None):
            addr = res[4][0]
            if ":" in addr:
                # IPv6: ::1 is loopback
                if addr == "::1":
                    return True
                # Simplified: treat link-local fe80:: as private
                if addr.lower().startswith("fe80"):
                    return True
                continue
            for prefix in _PRIVATE_IP_PREFIXES:
                if addr.startswith(prefix):
                    return True
            if addr.startswith("127.") and addr != "127.0.0.1":
                return True
        return False
    except (socket.gaierror, OSError):
        return False


def validate_api_url(url: str) -> tuple[bool, str]:
    """
    Validate API base URL for scheme and SSRF.
    Return (True, "") if valid, (False, "reason") otherwise.
    """
    if not url or not url.strip():
        return False, "API URL is empty."
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return False, "API URL must use http or https."
    if not parsed.netloc:
        return False, "API URL must have a host."
    host = parsed.hostname or parsed.netloc.split(":")[0]
    if parsed.scheme == "http":
        # Allow only localhost for HTTP (cleartext)
        if host not in ("localhost", "127.0.0.1"):
            return False, "HTTP is only allowed for localhost or 127.0.0.1. Use HTTPS for other hosts."
    else:
        # HTTPS: allow localhost, otherwise block private/metadata IPs
        if host in ("localhost", "127.0.0.1"):
            return True, ""
        if _is_private_or_metadata_ip(host):
            return False, "API URL must not point to a private or metadata IP address."
    return True, ""


def parse_allowed_ips(env_value: str) -> tuple[bool, str, list]:
    """
    Parse GLITCHTIP_ALLOWED_IPS (comma-separated IPv4 addresses or CIDR ranges).
    Return (True, "", entries) on success, (False, error_message, []) on invalid input.
    entries are ipaddress.IPv4Address or ipaddress.IPv4Network objects.
    """
    raw = (env_value or "").strip()
    if not raw:
        return True, "", []

    entries = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                if not isinstance(net, ipaddress.IPv4Network):
                    return False, f"Only IPv4 is supported; invalid entry: {part!r}", []
                entries.append(net)
            else:
                addr = ipaddress.ip_address(part)
                if not isinstance(addr, ipaddress.IPv4Address):
                    return False, f"Only IPv4 is supported; invalid entry: {part!r}", []
                entries.append(addr)
        except ValueError as e:
            return False, f"Invalid IP or CIDR in GLITCHTIP_ALLOWED_IPS: {part!r} ({e})", []
    if not entries:
        return True, "", []
    return True, "", entries


def get_outbound_ip(timeout: float = 5.0) -> str | None:
    """
    Return the outbound IPv4 address used for the default route (no packets sent).
    Returns None on failure (no network, timeout, etc.).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except (OSError, socket.error):
        return None


def check_ip_allowed(
    current_ip: str,
    entries: list[ipaddress.IPv4Address | ipaddress.IPv4Network],
) -> bool:
    """Return True if current_ip (string) is in any of the allowed entries (single IP or CIDR)."""
    try:
        addr = ipaddress.ip_address(current_ip)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    for entry in entries:
        if isinstance(entry, ipaddress.IPv4Address):
            if addr == entry:
                return True
        else:
            if addr in entry:
                return True
    return False


def check_allowed_ips_from_env() -> tuple[bool, str]:
    """
    If GLITCHTIP_ALLOWED_IPS is set, verify current host's outbound IP is in the list.
    Return (True, "") if allowed or check skipped; (False, message) if not allowed or check failed.
    """
    raw = os.environ.get("GLITCHTIP_ALLOWED_IPS", "").strip()
    if not raw:
        return True, ""

    ok, msg, entries = parse_allowed_ips(raw)
    if not ok:
        return False, msg
    if not entries:
        return True, ""

    current = get_outbound_ip()
    if current is None:
        return False, "Could not determine current outbound IP; server cannot start when GLITCHTIP_ALLOWED_IPS is set."
    if check_ip_allowed(current, entries):
        return True, ""
    return False, f"Current IP {current} is not in GLITCHTIP_ALLOWED_IPS."


@dataclass
class GlitchTipIssueData:
    """Represents a GlitchTip issue with its details."""
    title: str
    issue_id: str
    status: str
    level: str
    first_seen: str
    last_seen: str
    count: int
    stacktrace: str
    culprit: str = ""
    short_id: str = ""

    def to_text(self) -> str:
        return f"""
GlitchTip Issue: {self.title}
Issue ID: {self.issue_id}
Short ID: {self.short_id}
Status: {self.status}
Level: {self.level}
Culprit: {self.culprit}
First Seen: {self.first_seen}
Last Seen: {self.last_seen}
Event Count: {self.count}

{self.stacktrace}
        """

    def to_tool_result(self) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=self.to_text())]


class GlitchTipError(Exception):
    """Custom exception for GlitchTip-related errors."""
    pass


def create_stacktrace(event_data: dict) -> str:
    """
    Creates a formatted stacktrace string from a GlitchTip event.

    Handles the Sentry-compatible event format used by GlitchTip.
    """
    stacktraces = []

    # Try to get exception info from entries
    for entry in event_data.get("entries", []):
        if entry.get("type") != "exception":
            continue

        exception_values = entry.get("data", {}).get("values", [])
        for exception in exception_values:
            exception_type = exception.get("type", "Unknown")
            exception_value = exception.get("value", "")
            stacktrace = exception.get("stacktrace")

            stacktrace_text = f"Exception: {exception_type}: {exception_value}\n\n"
            if stacktrace:
                stacktrace_text += "Stacktrace:\n"
                for frame in stacktrace.get("frames", []):
                    filename = frame.get("filename", "Unknown")
                    lineno = frame.get("lineNo", frame.get("lineno", "?"))
                    function = frame.get("function", "Unknown")

                    stacktrace_text += f"  {filename}:{lineno} in {function}\n"

                    # Include context lines if available
                    context = frame.get("context", [])
                    for ctx_line in context:
                        if isinstance(ctx_line, list) and len(ctx_line) >= 2:
                            stacktrace_text += f"    {ctx_line[1]}\n"

                stacktrace_text += "\n"

            stacktraces.append(stacktrace_text)

    # Fallback: try to get from exception directly
    if not stacktraces:
        exception = event_data.get("exception", {})
        if exception:
            values = exception.get("values", [])
            for exc in values:
                exc_type = exc.get("type", "Unknown")
                exc_value = exc.get("value", "")
                stacktraces.append(f"Exception: {exc_type}: {exc_value}\n")

    return "\n".join(stacktraces) if stacktraces else "No stacktrace found"


async def fetch_issue(
    http_client: httpx.AsyncClient,
    auth_token: str,
    issue_id: str
) -> GlitchTipIssueData | str:
    """Fetch a single issue by ID."""
    try:
        # Get issue details
        response = await http_client.get(
            f"issues/{issue_id}/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
        if response.status_code == 404:
            return f"Error: Issue {issue_id} not found."
        response.raise_for_status()
        issue_data = response.json()

        # Try to get the latest event for stacktrace
        stacktrace = "No stacktrace available"
        try:
            events_response = await http_client.get(
                f"issues/{issue_id}/events/latest/",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            if events_response.status_code == 200:
                latest_event = events_response.json()
                stacktrace = create_stacktrace(latest_event)
        except Exception:
            # Try alternate endpoint
            try:
                hashes_response = await http_client.get(
                    f"issues/{issue_id}/hashes/",
                    headers={"Authorization": f"Bearer {auth_token}"}
                )
                if hashes_response.status_code == 200:
                    hashes = hashes_response.json()
                    if hashes and "latestEvent" in hashes[0]:
                        stacktrace = create_stacktrace(hashes[0]["latestEvent"])
            except Exception:
                pass

        return GlitchTipIssueData(
            title=issue_data.get("title", "Unknown"),
            issue_id=str(issue_data.get("id", issue_id)),
            short_id=issue_data.get("shortId", ""),
            status=issue_data.get("status", "unknown"),
            level=issue_data.get("level", "error"),
            culprit=issue_data.get("culprit", ""),
            first_seen=issue_data.get("firstSeen", ""),
            last_seen=issue_data.get("lastSeen", ""),
            count=issue_data.get("count", 0),
            stacktrace=stacktrace
        )

    except httpx.HTTPStatusError as e:
        return f"Error fetching issue: Request failed with status {e.response.status_code}."
    except httpx.RequestError:
        return "Error: Connection or request failed."
    except (ValueError, KeyError):
        return "Error: Invalid response from server."
    except Exception:
        logger.exception("Unexpected error in fetch_issue")
        return "An unexpected error occurred."


async def fetch_project_issues(
    http_client: httpx.AsyncClient,
    auth_token: str,
    organization_slug: str,
    project_slug: str,
    status: str = "unresolved"
) -> list[GlitchTipIssueData] | str:
    """Fetch all issues for a project."""
    try:
        response = await http_client.get(
            f"projects/{organization_slug}/{project_slug}/issues/",
            params={"query": f"is:{status}"},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
        if response.status_code == 404:
            return f"Error: Project {organization_slug}/{project_slug} not found."
        response.raise_for_status()
        issues_data = response.json()

        results = []
        for issue in issues_data:
            results.append(GlitchTipIssueData(
                title=issue.get("title", "Unknown"),
                issue_id=str(issue.get("id", "")),
                short_id=issue.get("shortId", ""),
                status=issue.get("status", "unknown"),
                level=issue.get("level", "error"),
                culprit=issue.get("culprit", ""),
                first_seen=issue.get("firstSeen", ""),
                last_seen=issue.get("lastSeen", ""),
                count=issue.get("count", 0),
                stacktrace="(Use get_glitchtip_issue for full stacktrace)"
            ))
        return results

    except httpx.HTTPStatusError as e:
        return f"Error fetching issues: Request failed with status {e.response.status_code}."
    except httpx.RequestError:
        return "Error: Connection or request failed."
    except (ValueError, KeyError):
        return "Error: Invalid response from server."
    except Exception:
        logger.exception("Unexpected error in fetch_project_issues")
        return "An unexpected error occurred."


async def fetch_organizations(
    http_client: httpx.AsyncClient,
    auth_token: str,
) -> list[dict] | str:
    """Fetch all organizations. Returns list of dicts with slug/name or error string."""
    try:
        response = await http_client.get(
            "organizations/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            return "Error: Invalid response from server."
        return [{"slug": item.get("slug", ""), "name": item.get("name", item.get("slug", ""))} for item in data]
    except httpx.HTTPStatusError as e:
        return f"Error fetching organizations: Request failed with status {e.response.status_code}."
    except httpx.RequestError:
        return "Error: Connection or request failed."
    except (ValueError, KeyError):
        return "Error: Invalid response from server."
    except Exception:
        logger.exception("Unexpected error in fetch_organizations")
        return "An unexpected error occurred."


async def fetch_projects(
    http_client: httpx.AsyncClient,
    auth_token: str,
    organization_slug: str,
) -> list[dict] | str:
    """Fetch all projects for an organization. Returns list of dicts with slug/name or error string."""
    if not validate_slug(organization_slug):
        return "Error: organization_slug must contain only letters, numbers, hyphens, and underscores."
    try:
        response = await http_client.get(
            f"organizations/{organization_slug}/projects/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
        if response.status_code == 404:
            return f"Error: Organization {organization_slug} not found."
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            return "Error: Invalid response from server."
        return [{"slug": item.get("slug", ""), "name": item.get("name", item.get("slug", ""))} for item in data]
    except httpx.HTTPStatusError as e:
        return f"Error fetching projects: Request failed with status {e.response.status_code}."
    except httpx.RequestError:
        return "Error: Connection or request failed."
    except (ValueError, KeyError):
        return "Error: Invalid response from server."
    except Exception:
        logger.exception("Unexpected error in fetch_projects")
        return "An unexpected error occurred."


async def resolve_issue(
    http_client: httpx.AsyncClient,
    auth_token: str,
    issue_id: str,
    organization_slug: str,
    project_slug: str,
) -> str:
    """Mark an issue as resolved (project-scoped, then global fallback)."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    try:
        if organization_slug and project_slug:
            response = await http_client.put(
                f"projects/{organization_slug}/{project_slug}/issues/",
                params={"id": issue_id},
                json={"status": "resolved"},
                headers=headers,
            )
            if response.status_code == 401:
                return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
            if response.status_code == 404:
                return f"Error: Project {organization_slug}/{project_slug} or issue {issue_id} not found."
            if response.status_code < 400:
                return f"Issue {issue_id} marked as resolved ({organization_slug}/{project_slug})."
            if response.status_code != 403:
                response.raise_for_status()

        response = await http_client.put(
            f"issues/{issue_id}/",
            json={"status": "resolved"},
            headers=headers,
        )
        if response.status_code == 401:
            return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
        if response.status_code == 404:
            return f"Error: Issue {issue_id} not found."
        response.raise_for_status()
        return f"Issue {issue_id} marked as resolved."
    except httpx.HTTPStatusError as e:
        return f"Error resolving issue: Request failed with status {e.response.status_code}."
    except httpx.RequestError:
        return "Error: Connection or request failed."
    except (ValueError, KeyError):
        return "Error: Invalid response from server."
    except Exception:
        logger.exception("Unexpected error in resolve_issue")
        return "An unexpected error occurred."


async def fetch_issue_events(
    http_client: httpx.AsyncClient,
    auth_token: str,
    issue_id: str,
    limit: int = _DEFAULT_EVENTS_LIMIT,
    cursor: str | None = None,
) -> dict | str:
    """
    List events for an issue via GET issues/{id}/events/ with bounded limit/cursor.
    Returns a sanitized summary dict or an error string.
    """
    if not validate_issue_id(issue_id):
        return "Error: issue_id must be a numeric ID."
    safe_limit = normalize_events_limit(limit)
    headers = {"Authorization": f"Bearer {auth_token}"}
    params: dict[str, str | int] = {"limit": safe_limit}
    if cursor is not None and str(cursor).strip():
        # Cursor is an opaque pagination token; reject path-like values
        cursor_s = str(cursor).strip()
        if "/" in cursor_s or ".." in cursor_s or len(cursor_s) > 256:
            return "Error: invalid cursor."
        params["cursor"] = cursor_s
    try:
        response = await http_client.get(
            f"issues/{issue_id}/events/",
            params=params,
            headers=headers,
        )
        if response.status_code == 401:
            return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
        if response.status_code == 404:
            return f"Error: Issue {issue_id} not found."
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            return "Error: Invalid response from server."

        events = []
        for item in data[:safe_limit]:
            if not isinstance(item, dict):
                continue
            # List endpoints often return summaries; still run through projection
            events.append(project_event_for_analysis(item))

        result: dict = {
            "issue_id": str(issue_id),
            "limit": safe_limit,
            "count": len(events),
            "events": events,
        }
        # Surface pagination hint from Link header without exposing raw secrets
        link = response.headers.get("link") or response.headers.get("Link")
        if link and "cursor=" in link.lower():
            result["pagination_note"] = (
                "Additional pages may be available; pass cursor from the API Link header."
            )
        return result
    except httpx.HTTPStatusError as e:
        return f"Error fetching issue events: Request failed with status {e.response.status_code}."
    except httpx.RequestError:
        return "Error: Connection or request failed."
    except (ValueError, KeyError, TypeError):
        return "Error: Invalid response from server."
    except Exception:
        logger.exception("Unexpected error in fetch_issue_events")
        return "An unexpected error occurred."


async def fetch_event(
    http_client: httpx.AsyncClient,
    auth_token: str,
    event_id: str,
    issue_id: str | None = None,
    organization_slug: str | None = None,
    project_slug: str | None = None,
) -> dict | str:
    """
    Retrieve one event via GET only.
    Prefers issues/{issue_id}/events/{event_id}/ when issue_id is set;
    otherwise projects/{org}/{project}/events/{event_id}/.
    """
    if not validate_event_id(event_id):
        return "Error: event_id must be alphanumeric (optionally with _ or -), max 64 chars."
    headers = {"Authorization": f"Bearer {auth_token}"}

    paths: list[str] = []
    if issue_id:
        if not validate_issue_id(issue_id):
            return "Error: issue_id must be a numeric ID."
        paths.append(f"issues/{issue_id}/events/{event_id}/")
    if organization_slug and project_slug:
        if not validate_slug(organization_slug):
            return "Error: organization_slug must contain only letters, numbers, hyphens, and underscores."
        if not validate_slug(project_slug):
            return "Error: project_slug must contain only letters, numbers, hyphens, and underscores."
        paths.append(f"projects/{organization_slug}/{project_slug}/events/{event_id}/")

    if not paths:
        return (
            "Error: Provide issue_id and/or organization_slug+project_slug to resolve the event."
        )

    try:
        for path in paths:
            response = await http_client.get(path, headers=headers)
            if response.status_code == 401:
                return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
            if response.status_code == 404:
                continue
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return "Error: Invalid response from server."
            return project_event_for_analysis(data)

        return f"Error: Event {event_id} not found."
    except httpx.HTTPStatusError as e:
        return f"Error fetching event: Request failed with status {e.response.status_code}."
    except httpx.RequestError:
        return "Error: Connection or request failed."
    except (ValueError, KeyError, TypeError):
        return "Error: Invalid response from server."
    except Exception:
        logger.exception("Unexpected error in fetch_event")
        return "An unexpected error occurred."


def create_app(
    api_base: str,
    auth_token: str,
    organization_slug: str,
    project_slug: str,
    host: str = "0.0.0.0",
    port: int = 8000,
) -> FastMCP:
    """Create and configure the MCP server (FastMCP). Supports stdio and streamable-http transports."""
    base_url = api_base.rstrip("/") + "/" if api_base else ""
    http_client = httpx.AsyncClient(base_url=base_url, timeout=30.0)
    mcp = FastMCP("glitchtip", host=host, port=port)

    @mcp.tool(
        description="List all organizations on the GlitchTip server. Use this to discover organization slugs before listing projects or issues.",
    )
    async def list_glitchtip_organizations() -> str:
        result = await fetch_organizations(http_client, auth_token)
        if isinstance(result, str):
            return result
        if not result:
            return "No organizations found."
        text = "GlitchTip Organizations:\n\n"
        for item in result:
            text += f"  {item.get('slug', '')}  ({item.get('name', '')})\n"
        return text

    @mcp.tool(
        description="List all projects for an organization. Use list_glitchtip_organizations first to get the organization slug.",
    )
    async def list_glitchtip_projects(organization_slug: str) -> str:
        if not organization_slug:
            return "Error: Missing organization_slug argument"
        if not validate_slug(organization_slug):
            return "Error: organization_slug must contain only letters, numbers, hyphens, and underscores."
        result = await fetch_projects(http_client, auth_token, organization_slug)
        if isinstance(result, str):
            return result
        if not result:
            return f"No projects found for organization {organization_slug}."
        text = f"GlitchTip Projects (organization: {organization_slug}):\n\n"
        for item in result:
            text += f"  {item.get('slug', '')}  ({item.get('name', '')})\n"
        return text

    _default_org = organization_slug
    _default_proj = project_slug

    @mcp.tool(
        description="""List all issues from GlitchTip for a project.
Use this to see all current errors and exceptions. Pass organization_slug and project_slug (from list_glitchtip_organizations and list_glitchtip_projects), or set GLITCHTIP_ORGANIZATION and GLITCHTIP_PROJECT as defaults.""",
    )
    async def get_glitchtip_issues(
        organization_slug: str | None = None,
        project_slug: str | None = None,
        status: str = "unresolved",
    ) -> str:
        org = (organization_slug or _default_org) or ""
        proj = (project_slug or _default_proj) or ""
        if not org or not proj:
            return "Error: organization_slug and project_slug are required (or set GLITCHTIP_ORGANIZATION and GLITCHTIP_PROJECT). Use list_glitchtip_organizations and list_glitchtip_projects to discover values."
        if not validate_slug(org):
            return "Error: organization_slug must contain only letters, numbers, hyphens, and underscores."
        if not validate_slug(proj):
            return "Error: project_slug must contain only letters, numbers, hyphens, and underscores."
        status_val = normalize_status(status)
        result = await fetch_project_issues(http_client, auth_token, org, proj, status_val)
        if isinstance(result, str):
            return result
        issues = result
        if not issues:
            return f"No {status_val} issues found."
        text = f"GlitchTip Issues ({org}/{proj}, {status_val}):\n\n"
        for issue in issues:
            text += "---\n"
            text += f"ID: {issue.issue_id} ({issue.short_id})\n"
            text += f"Title: {issue.title}\n"
            text += f"Level: {issue.level} | Count: {issue.count}\n"
            text += f"Culprit: {issue.culprit}\n"
            text += f"First: {issue.first_seen} | Last: {issue.last_seen}\n\n"
        return text

    @mcp.tool(
        description="""Get detailed information about a specific GlitchTip issue including full stacktrace.
Use this when you need to investigate a specific error in detail.
Provides the complete stacktrace, error counts, and timing information.""",
    )
    async def get_glitchtip_issue(issue_id: str) -> str:
        if not issue_id:
            return "Error: Missing issue_id argument"
        if not validate_issue_id(issue_id):
            return "Error: issue_id must be a numeric ID."
        result = await fetch_issue(http_client, auth_token, issue_id)
        if isinstance(result, str):
            return result
        return result.to_text()

    # resolve_issue remains available as an internal helper for unit tests, but is
    # intentionally NOT registered as an MCP tool — the connector is read-only.

    @mcp.tool(
        description="""List events for a GlitchTip issue (read-only).
Returns a privacy-sanitized projection of each event for incident analysis.
Supports bounded limit (default 10, max 50) and optional cursor pagination.
Uses GET issues/{issue_id}/events/ only.""",
    )
    async def get_glitchtip_issue_events(
        issue_id: str,
        limit: int = _DEFAULT_EVENTS_LIMIT,
        cursor: str | None = None,
    ) -> str:
        if not issue_id:
            return "Error: Missing issue_id argument"
        if not validate_issue_id(issue_id):
            return "Error: issue_id must be a numeric ID."
        result = await fetch_issue_events(
            http_client, auth_token, issue_id, limit=limit, cursor=cursor
        )
        if isinstance(result, str):
            return result
        return event_projection_to_text(result)

    @mcp.tool(
        description="""Get one GlitchTip/Sentry-compatible event (read-only), sanitized for incident analysis.
Provide event_id plus issue_id and/or organization_slug+project_slug.
Uses GET only against issues/{issue_id}/events/{event_id}/ or projects/{org}/{project}/events/{event_id}/.
Sensitive headers, cookies, tokens, and credential-bearing fields are redacted or omitted.""",
    )
    async def get_glitchtip_event(
        event_id: str,
        issue_id: str | None = None,
        organization_slug: str | None = None,
        project_slug: str | None = None,
    ) -> str:
        if not event_id:
            return "Error: Missing event_id argument"
        if not validate_event_id(event_id):
            return "Error: event_id must be alphanumeric (optionally with _ or -), max 64 chars."
        org = (organization_slug or _default_org) or None
        proj = (project_slug or _default_proj) or None
        # Normalize empty strings to None
        issue = (issue_id or "").strip() or None
        org = (org or "").strip() or None
        proj = (proj or "").strip() or None
        result = await fetch_event(
            http_client,
            auth_token,
            event_id.strip(),
            issue_id=issue,
            organization_slug=org,
            project_slug=proj,
        )
        if isinstance(result, str):
            return result
        return event_projection_to_text(result)

    return mcp


def main():
    """Main entry point."""
    # Configuration from environment variables (strip to avoid newlines/spaces from .env breaking auth)
    api_base = (os.environ.get("GLITCHTIP_API_URL") or "").strip()
    auth_token = (os.environ.get("GLITCHTIP_AUTH_TOKEN") or "").strip()
    organization_slug = (os.environ.get("GLITCHTIP_ORGANIZATION") or "").strip()
    project_slug = (os.environ.get("GLITCHTIP_PROJECT") or "").strip()

    missing = []
    if not api_base:
        missing.append("GLITCHTIP_API_URL")
    if not auth_token:
        missing.append("GLITCHTIP_AUTH_TOKEN")

    if missing:
        print(f"Error: Missing required environment variables: {', '.join(missing)}")
        print("\nRequired configuration:")
        print("  GLITCHTIP_API_URL       - Your GlitchTip API URL (e.g., https://glitchtip.example.com/api/0/)")
        print("  GLITCHTIP_AUTH_TOKEN    - API token from your GlitchTip settings")
        print("\nOptional (default org/project for get_glitchtip_issues when not passed per call):")
        print("  GLITCHTIP_ORGANIZATION  - Your organization slug")
        print("  GLITCHTIP_PROJECT       - Your project slug")
        return

    ok, msg = validate_api_url(api_base)
    if not ok:
        print(f"Error: Invalid GLITCHTIP_API_URL. {msg}")
        return

    if organization_slug and not validate_slug(organization_slug):
        print("Error: GLITCHTIP_ORGANIZATION must contain only letters, numbers, hyphens, and underscores.")
        return
    if project_slug and not validate_slug(project_slug):
        print("Error: GLITCHTIP_PROJECT must contain only letters, numbers, hyphens, and underscores.")
        return

    # Temporarily disabled: IP whitelist fails in Docker (container sees internal IP, not host).
    # allowed, ip_msg = check_allowed_ips_from_env()
    # if not allowed:
    #     print(f"Error: {ip_msg}")
    #     return

    transport = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
    host = os.environ.get("MCP_HTTP_HOST", "0.0.0.0").strip()
    try:
        port = int(os.environ.get("MCP_HTTP_PORT", "8000").strip())
    except ValueError:
        port = 8000

    app = create_app(
        api_base,
        auth_token,
        organization_slug,
        project_slug,
        host=host,
        port=port,
    )

    if transport == "streamable-http":
        app.run(transport="streamable-http")
    else:
        app.run(transport="stdio")


if __name__ == "__main__":
    main()
