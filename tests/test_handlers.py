"""Tests for fetch_issue, fetch_project_issues, resolve_issue, event tools (with respx)."""

import json

import pytest
import httpx
import respx

from server import (
    GlitchTipIssueData,
    _MAX_PROJECTION_CHARS,
    _REDACTED,
    create_app,
    fetch_event,
    fetch_issue,
    fetch_issue_events,
    fetch_organizations,
    fetch_project_issues,
    fetch_projects,
    normalize_events_limit,
    normalize_status,
    project_event_for_analysis,
    resolve_issue,
    validate_event_id,
)

BASE_URL = "https://glitchtip.example.com/api/0/"


def _registered_tool_names(app) -> set[str]:
    """Collect MCP tool names from a FastMCP app (version-tolerant, sync)."""
    manager = getattr(app, "_tool_manager", None)
    if manager is not None:
        tools = getattr(manager, "_tools", None) or getattr(manager, "tools", None)
        if isinstance(tools, dict):
            return set(tools.keys())

    tools_attr = getattr(app, "_tools", None)
    if isinstance(tools_attr, dict):
        return set(tools_attr.keys())

    # Fallback: some FastMCP builds expose a sync/async list_tools helper
    list_tools = getattr(app, "list_tools", None)
    if callable(list_tools):
        import inspect

        result = list_tools()
        if inspect.isawaitable(result):
            raise AssertionError(
                "list_tools is async; expected sync _tool_manager/_tools enumeration"
            )
        names = set()
        for tool in result or []:
            name = getattr(tool, "name", None)
            if name:
                names.add(name)
            elif isinstance(tool, dict) and "name" in tool:
                names.add(tool["name"])
            elif isinstance(tool, str):
                names.add(tool)
        if names:
            return names

    raise AssertionError("Unable to enumerate FastMCP registered tools")


def _sample_event_payload(**overrides):
    """Representative Sentry/GlitchTip event with sensitive and allowed fields."""
    event = {
        "id": "abc123def456abc123def456abc123de",
        "eventID": "abc123def456abc123def456abc123de",
        "groupID": "123",
        "title": "ValueError: boom",
        "message": "boom",
        "platform": "python",
        "environment": "production",
        "release": "1.2.3",
        "datetime": "2024-06-01T12:00:00Z",
        "dateCreated": "2024-06-01T12:00:00Z",
        "transaction": "/api/orders",
        "logger": "app.orders",
        "server_name": "web-1",
        "tags": [
            ["environment", "production"],
            ["url", "https://app.example.com/api/orders"],
            ["token", "should-not-leak"],
        ],
        "request": {
            "url": "https://app.example.com/api/orders?id=9&api_key=secret123&q=widget",
            "method": "POST",
            "query_string": "id=9&api_key=secret123&q=widget",
            "headers": [
                ["Host", "app.example.com"],
                ["User-Agent", "Mozilla/5.0"],
                ["Accept", "application/json"],
                ["Referer", "https://app.example.com/cart"],
                ["X-Forwarded-For", "203.0.113.10"],
                ["X-Real-IP", "203.0.113.10"],
                ["CF-Connecting-IP", "203.0.113.10"],
                ["True-Client-IP", "203.0.113.10"],
                ["Forwarded", "for=203.0.113.10"],
                ["Via", "1.1 proxy"],
                ["Cookie", "sessionid=abc; csrftoken=xyz"],
                ["Authorization", "Bearer super-secret-token"],
                ["Proxy-Authorization", "Basic YWRtaW46cGFzcw=="],
                ["Set-Cookie", "sessionid=abc"],
                ["X-Api-Key", "key-should-go"],
            ],
            "env": {
                "REMOTE_ADDR": "203.0.113.10",
                "SERVER_NAME": "app.example.com",
                "PASSWORD": "nope",
            },
            "data": {"order_id": 9, "password": "hunter2", "note": "ok"},
        },
        "entries": [
            {
                "type": "exception",
                "data": {
                    "values": [
                        {
                            "type": "ValueError",
                            "value": "boom",
                            "stacktrace": {"frames": []},
                        }
                    ]
                },
            }
        ],
        "contexts": {
            "runtime": {"name": "CPython", "version": "3.12.0"},
            "response": {"status_code": 500, "headers": {"Set-Cookie": "x=1"}},
        },
        "breadcrumbs": {
            "values": [
                {"category": "query", "message": "SELECT 1", "timestamp": "2024-06-01T11:59:00Z"},
            ]
        },
    }
    event.update(overrides)
    return event


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_issue_valid_requests_correct_path(respx_mock):
    """Valid issue_id results in request to issues/123/ (no path traversal)."""
    issue_payload = {
        "id": 123,
        "title": "Test Error",
        "shortId": "PROJ-1",
        "status": "unresolved",
        "level": "error",
        "culprit": "app.py",
        "firstSeen": "2024-01-01T00:00:00Z",
        "lastSeen": "2024-01-01T12:00:00Z",
        "count": 5,
    }
    respx_mock.get("/issues/123/").mock(return_value=httpx.Response(200, json=issue_payload))
    # 404 on events/latest: code does not enter exception branch, so no hashes call
    respx_mock.get("/issues/123/events/latest/").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_issue(client, "token", "123")

    assert isinstance(result, GlitchTipIssueData)
    assert result.issue_id == "123"
    assert result.title == "Test Error"
    assert respx_mock.calls.call_count >= 1
    first_call = respx_mock.calls[0]
    assert "/issues/123/" in str(first_call.request.url)
    assert "../" not in str(first_call.request.url)


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_issue_401_returns_unauthorized_message(respx_mock):
    respx_mock.get("/issues/123/").mock(return_value=httpx.Response(401))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_issue(client, "token", "123")

    assert isinstance(result, str)
    assert "Unauthorized" in result
    assert "GLITCHTIP_AUTH_TOKEN" in result


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_issue_404_returns_not_found(respx_mock):
    respx_mock.get("/issues/999/").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_issue(client, "token", "999")

    assert isinstance(result, str)
    assert "not found" in result
    assert "999" in result


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_issue_500_returns_safe_message(respx_mock):
    """Server error should return stable message, not raw exception."""
    respx_mock.get("/issues/123/").mock(return_value=httpx.Response(500, text="Internal Server Error"))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_issue(client, "token", "123")

    assert isinstance(result, str)
    assert "Error" in result
    # Should not expose internal paths or tracebacks
    assert "/server.py" not in result
    assert "Traceback" not in result


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_project_issues_valid_status_in_query(respx_mock):
    respx_mock.get(
        "/projects/my-org/my-project/issues/",
        params={"query": "is:resolved"},
    ).mock(return_value=httpx.Response(200, json=[]))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_project_issues(
            client, "token", "my-org", "my-project", status="resolved"
        )

    assert result == []
    assert respx_mock.calls.call_count == 1
    call = respx_mock.calls[0]
    assert call.request.url.params.get("query") == "is:resolved"


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_resolve_issue_200_returns_success(respx_mock):
    respx_mock.put(
        "/projects/my-org/my-project/issues/",
        params={"id": "456"},
    ).mock(return_value=httpx.Response(200, json={"status": "resolved"}))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await resolve_issue(client, "token", "456", "my-org", "my-project")

    assert "resolved" in result
    assert "456" in result
    assert respx_mock.calls.call_count == 1
    assert respx_mock.calls[0].request.method == "PUT"


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_resolve_issue_404_returns_not_found(respx_mock):
    # Project-scoped 404 returns immediately (no global fallback on 404).
    respx_mock.put(
        "/projects/my-org/my-project/issues/",
        params={"id": "999"},
    ).mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await resolve_issue(client, "token", "999", "my-org", "my-project")

    assert isinstance(result, str)
    assert "not found" in result


def test_normalize_status_used_for_handler():
    """Status is normalized to allowed set (used by handler)."""
    assert normalize_status("unresolved") == "unresolved"
    assert normalize_status("invalid") == "unresolved"
    assert normalize_status("resolved") == "resolved"


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_organizations_returns_list(respx_mock):
    respx_mock.get("/organizations/").mock(return_value=httpx.Response(200, json=[
        {"slug": "org1", "name": "Organization 1"},
        {"slug": "org2", "name": "Organization 2"},
    ]))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_organizations(client, "token")

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["slug"] == "org1" and result[0]["name"] == "Organization 1"
    assert result[1]["slug"] == "org2"


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_organizations_401_returns_error(respx_mock):
    respx_mock.get("/organizations/").mock(return_value=httpx.Response(401))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_organizations(client, "token")

    assert isinstance(result, str)
    assert "Unauthorized" in result


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_projects_returns_list(respx_mock):
    respx_mock.get("/organizations/my-org/projects/").mock(return_value=httpx.Response(200, json=[
        {"slug": "proj1", "name": "Project 1"},
        {"slug": "proj2", "name": "Project 2"},
    ]))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_projects(client, "token", "my-org")

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["slug"] == "proj1" and result[0]["name"] == "Project 1"


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_projects_invalid_slug_returns_error(respx_mock):
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_projects(client, "token", "invalid/slug")

    assert isinstance(result, str)
    assert "organization_slug" in result
    assert respx_mock.calls.call_count == 0


def test_create_app_accepts_empty_org_project():
    """create_app() accepts empty organization_slug and project_slug (all-projects mode)."""
    app = create_app(BASE_URL, "token", "", "")
    assert app is not None


def test_create_app_accepts_org_project():
    """create_app() accepts org and project (default project mode)."""
    app = create_app(BASE_URL, "token", "my-org", "my-project")
    assert app is not None


def test_create_app_tools_are_read_only_and_include_event_tools():
    """Mutating resolve tool must not be registered; event tools must be present."""
    app = create_app(BASE_URL, "token", "my-org", "my-project")
    names = _registered_tool_names(app)
    assert "resolve_glitchtip_issue" not in names
    assert "get_glitchtip_issue_events" in names
    assert "get_glitchtip_event" in names


def test_validate_event_id_and_limit_bounds():
    assert validate_event_id("abc123def456abc123def456abc123de")
    assert not validate_event_id("../evil")
    assert not validate_event_id("")
    assert normalize_events_limit(999) == 50
    assert normalize_events_limit(0) == 1
    assert normalize_events_limit("nope") == 10


def test_project_event_redacts_sensitive_headers_and_keeps_proxy_headers():
    projection = project_event_for_analysis(_sample_event_payload())
    assert projection["event_id"] == "abc123def456abc123def456abc123de"
    assert projection["issue_id"] == "123"
    assert projection["title"] == "ValueError: boom"
    assert projection["platform"] == "python"
    assert projection["environment"] == "production"
    assert projection["release"] == "1.2.3"
    assert projection["exception"]["type"] == "ValueError"

    headers = projection["request"]["headers"]
    assert "cookie" not in headers
    assert "set-cookie" not in headers
    assert "authorization" not in headers
    assert "proxy-authorization" not in headers
    assert "x-api-key" not in headers
    assert headers["x-forwarded-for"] == "203.0.113.10"
    assert headers["x-real-ip"] == "203.0.113.10"
    assert headers["cf-connecting-ip"] == "203.0.113.10"
    assert headers["true-client-ip"] == "203.0.113.10"
    assert headers["forwarded"] == "for=203.0.113.10"
    assert headers["via"] == "1.1 proxy"
    assert headers["host"] == "app.example.com"
    assert headers["user-agent"] == "Mozilla/5.0"
    assert headers["accept"] == "application/json"
    assert headers["referer"] == "https://app.example.com/cart"

    assert projection["request"]["method"] == "POST"
    assert "api_key=secret123" not in projection["request"]["url"]
    assert projection["request"]["query_string"]["api_key"] == _REDACTED
    assert projection["request"]["query_string"]["q"] == "widget"
    assert projection["request"]["env"]["REMOTE_ADDR"] == "203.0.113.10"
    assert "PASSWORD" not in projection["request"]["env"]
    assert projection["request"]["data"]["password"] == _REDACTED
    assert projection["request"]["data"]["order_id"] == 9
    assert projection["tags"]["token"] == _REDACTED

    serialized = json.dumps(projection)
    assert "super-secret-token" not in serialized
    assert "sessionid=abc" not in serialized
    assert "hunter2" not in serialized
    assert "secret123" not in serialized
    # Breadcrumb SQL payloads must not leak
    assert "SELECT 1" not in serialized


def test_project_event_case_insensitive_header_redaction():
    event = _sample_event_payload()
    event["request"]["headers"] = {
        "COOKIE": "a=b",
        "Authorization": "Bearer x",
        "x-FoRwArDeD-fOr": "198.51.100.1",
    }
    projection = project_event_for_analysis(event)
    headers = projection["request"]["headers"]
    assert "cookie" not in headers
    assert "authorization" not in headers
    assert headers["x-forwarded-for"] == "198.51.100.1"


def test_project_event_missing_response_is_honest():
    event = _sample_event_payload()
    event.pop("contexts", None)
    projection = project_event_for_analysis(event)
    assert projection["response"]["present"] is False
    assert "No response telemetry" in projection["response"]["note"]
    assert "status_code" not in projection["response"]


def test_project_event_recorded_response_sanitized():
    event = _sample_event_payload()
    projection = project_event_for_analysis(event)
    assert projection["response"]["present"] is True
    assert projection["response"]["status_code"] == 500
    assert "set-cookie" not in (projection["response"].get("headers") or {})


def test_project_event_contexts_and_breadcrumbs_fail_closed():
    """User/PII/SQL/arbitrary context values and breadcrumb payloads must not leak."""
    event = _sample_event_payload(
        contexts={
            "runtime": {"name": "CPython", "version": "3.12.0", "extra_blob": "leak-me"},
            "os": {"name": "Linux", "version": "6.1"},
            "user": {
                "email": "alice@example.com",
                "ip_address": "198.51.100.44",
                "username": "alice",
                "id": "u-99",
            },
            "extra": {"sql": "SELECT * FROM users WHERE email='alice@example.com'"},
            "browser": {"name": "Chrome", "version": "120.0"},
        },
        breadcrumbs={
            "values": [
                {
                    "category": "query",
                    "type": "default",
                    "level": "info",
                    "timestamp": "2024-06-01T11:59:00Z",
                    "message": "SELECT password FROM accounts WHERE email='bob@example.com'",
                    "data": {
                        "query": "SELECT * FROM sessions",
                        "email": "bob@example.com",
                        "ip": "203.0.113.99",
                    },
                }
            ]
        },
    )
    projection = project_event_for_analysis(event)
    serialized = json.dumps(projection)

    assert projection["contexts"]["runtime"]["name"] == "CPython"
    assert projection["contexts"]["os"]["name"] == "Linux"
    assert projection["contexts"]["browser"]["name"] == "Chrome"
    assert "user" not in projection.get("contexts", {})
    assert "extra" not in projection.get("contexts", {})
    assert "extra_blob" not in projection["contexts"]["runtime"]

    crumbs = projection.get("breadcrumbs") or []
    assert crumbs
    assert crumbs[0]["category"] == "query"
    assert "message" not in crumbs[0]
    assert "data" not in crumbs[0]

    for secret in (
        "alice@example.com",
        "bob@example.com",
        "198.51.100.44",
        "203.0.113.99",
        "SELECT password FROM accounts",
        "SELECT * FROM sessions",
        "SELECT * FROM users",
        "leak-me",
    ):
        assert secret not in serialized


def test_project_event_omits_plain_string_response_body_secrets():
    """Arbitrary plain-text response bodies must be omitted, never returned verbatim."""
    event = _sample_event_payload()
    event["contexts"]["response"] = {
        "status_code": 500,
        "headers": {
            "Content-Type": "text/plain",
            "X-Custom-Debug": "should-not-appear",
            "X-Request-Id": "req-123",
            "Set-Cookie": "session=abc",
            "Authorization": "Bearer resp-token",
        },
        "body": (
            "debug dump Authorization: Bearer leaked-token password=hunter2 "
            "session=sess-xyz user=eve@example.com"
        ),
    }
    projection = project_event_for_analysis(event)
    serialized = json.dumps(projection)

    assert projection["response"]["body"] is None
    assert "body_note" in projection["response"]
    headers = projection["response"].get("headers") or {}
    assert headers.get("content-type") == "text/plain"
    assert headers.get("x-request-id") == "req-123"
    assert "x-custom-debug" not in headers
    assert "set-cookie" not in headers
    assert "authorization" not in headers

    for secret in (
        "Bearer leaked-token",
        "password=hunter2",
        "session=sess-xyz",
        "eve@example.com",
        "should-not-appear",
    ):
        assert secret not in serialized


def test_project_event_sanitizes_json_response_body():
    event = _sample_event_payload()
    event["contexts"]["response"] = {
        "status_code": 200,
        "body": '{"ok": true, "password": "hunter2", "order_id": 9}',
    }
    projection = project_event_for_analysis(event)
    assert projection["response"]["body"]["ok"] is True
    assert projection["response"]["body"]["password"] == _REDACTED
    assert projection["response"]["body"]["order_id"] == 9
    assert "hunter2" not in json.dumps(projection)


def test_project_event_hard_projection_budget():
    """Serialized projection must never exceed _MAX_PROJECTION_CHARS."""
    event = _sample_event_payload()
    huge = "A" * 8000
    event["request"]["headers"].extend(
        [
            ["Accept-Language", huge],
            ["Content-Type", "application/json"],
            ["Content-Length", "99999"],
        ]
    )
    event["request"]["data"] = {
        f"field_{i}": ("value-" + ("B" * 400)) for i in range(80)
    }
    event["contexts"] = {
        "runtime": {"name": "CPython", "version": "3.12.0"},
        "os": {"name": "Linux", "version": "6.1"},
        "browser": {"name": "Chrome", "version": "120"},
        "device": {"family": "desktop", "model": "x"},
        "trace": {"trace_id": "t" * 32, "span_id": "s" * 16, "op": "http.server"},
        "app": {"app_name": "demo", "app_version": "1.0"},
        "response": {
            "status_code": 500,
            "headers": {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "X-Request-Id": "r" * 200,
            },
            "body": {f"k_{i}": ("C" * 500) for i in range(60)},
        },
    }
    event["breadcrumbs"] = {
        "values": [
            {
                "category": f"cat-{i}",
                "type": "default",
                "level": "info",
                "timestamp": f"2024-06-01T11:{i:02d}:00Z",
                "message": "SHOULD_NOT_LEAK " + ("D" * 200),
            }
            for i in range(40)
        ]
    }
    event["tags"] = [[f"tag_{i}", "E" * 200] for i in range(40)]

    projection = project_event_for_analysis(event)
    encoded = json.dumps(projection, default=str)
    assert len(encoded) <= _MAX_PROJECTION_CHARS
    assert projection.get("event_id")
    assert "size limit" in (projection.get("note") or "") or any(
        "size limit" in str(o) for o in (projection.get("omissions") or [])
    )
    assert "SHOULD_NOT_LEAK" not in encoded


def test_project_event_truncates_long_strings():
    event = _sample_event_payload()
    event["message"] = "x" * 5000
    event["request"]["headers"].append(["User-Agent", "U" * 5000])
    projection = project_event_for_analysis(event)
    assert projection["message"].endswith("...[truncated]")
    assert len(projection["message"]) < 600
    assert projection["request"]["headers"]["user-agent"].endswith("...[truncated]")


def test_project_event_omits_uncertain_raw_body():
    event = _sample_event_payload()
    event["request"]["data"] = "not json and not form; may contain secrets"
    projection = project_event_for_analysis(event)
    assert "data" not in projection["request"]
    assert any("request.data" in o for o in projection.get("omissions", []))


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_issue_events_get_only_path_and_limit(respx_mock):
    payload = [
        {
            "eventID": "aaa111bbb222ccc333ddd444eee555ff",
            "groupID": "123",
            "title": "Error A",
            "dateCreated": "2024-06-01T12:00:00Z",
            "platform": "python",
        },
        {
            "eventID": "fff555eee444ddd333ccc222bbb111aa",
            "groupID": "123",
            "title": "Error B",
            "dateCreated": "2024-06-01T11:00:00Z",
            "platform": "python",
        },
    ]
    route = respx_mock.get("/issues/123/events/").mock(
        return_value=httpx.Response(200, json=payload)
    )

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_issue_events(client, "token", "123", limit=2)

    assert isinstance(result, dict)
    assert result["count"] == 2
    assert result["limit"] == 2
    assert result["events"][0]["event_id"] == "aaa111bbb222ccc333ddd444eee555ff"
    assert route.called
    assert respx_mock.calls.call_count == 1
    call = respx_mock.calls[0]
    assert call.request.method == "GET"
    assert "/issues/123/events/" in str(call.request.url)
    assert call.request.url.params.get("limit") == "2"
    assert all(c.request.method == "GET" for c in respx_mock.calls)


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_issue_events_clamps_limit_and_rejects_bad_issue(respx_mock):
    respx_mock.get("/issues/123/events/").mock(return_value=httpx.Response(200, json=[]))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        bad = await fetch_issue_events(client, "token", "../1", limit=5)
        ok = await fetch_issue_events(client, "token", "123", limit=500)

    assert isinstance(bad, str) and "issue_id" in bad
    assert isinstance(ok, dict)
    assert ok["limit"] == 50
    assert respx_mock.calls[0].request.url.params.get("limit") == "50"


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_event_issue_scoped_get_and_sanitizes(respx_mock):
    event_id = "abc123def456abc123def456abc123de"
    route = respx_mock.get(f"/issues/123/events/{event_id}/").mock(
        return_value=httpx.Response(200, json=_sample_event_payload())
    )

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_event(client, "token", event_id, issue_id="123")

    assert isinstance(result, dict)
    assert result["event_id"] == event_id
    assert result["request"]["method"] == "POST"
    assert "authorization" not in result["request"]["headers"]
    assert result["request"]["headers"]["x-forwarded-for"] == "203.0.113.10"
    assert route.called
    assert respx_mock.calls[0].request.method == "GET"
    assert f"/issues/123/events/{event_id}/" in str(respx_mock.calls[0].request.url)


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_event_project_scoped_fallback(respx_mock):
    event_id = "abc123def456abc123def456abc123de"
    respx_mock.get(f"/issues/123/events/{event_id}/").mock(
        return_value=httpx.Response(404)
    )
    route = respx_mock.get(f"/projects/my-org/my-project/events/{event_id}/").mock(
        return_value=httpx.Response(200, json=_sample_event_payload())
    )

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_event(
            client,
            "token",
            event_id,
            issue_id="123",
            organization_slug="my-org",
            project_slug="my-project",
        )

    assert isinstance(result, dict)
    assert result["event_id"] == event_id
    assert route.called
    assert all(c.request.method == "GET" for c in respx_mock.calls)


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_fetch_event_requires_resolving_identifiers(respx_mock):
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await fetch_event(client, "token", "abc123def456abc123def456abc123de")

    assert isinstance(result, str)
    assert "issue_id" in result or "organization_slug" in result
    assert respx_mock.calls.call_count == 0
