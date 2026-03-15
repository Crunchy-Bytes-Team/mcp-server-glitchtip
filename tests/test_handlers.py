"""Tests for fetch_issue, fetch_project_issues, resolve_issue and tool handler (with respx)."""

import pytest
import httpx
import respx

from server import (
    GlitchTipIssueData,
    create_app,
    fetch_issue,
    fetch_organizations,
    fetch_project_issues,
    fetch_projects,
    normalize_status,
    resolve_issue,
    validate_issue_id,
)

BASE_URL = "https://glitchtip.example.com/api/0/"


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
    respx_mock.put("/issues/456/").mock(return_value=httpx.Response(200, json={"status": "resolved"}))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await resolve_issue(client, "token", "456")

    assert "resolved" in result
    assert "456" in result


@respx.mock(base_url=BASE_URL)
@pytest.mark.asyncio
async def test_resolve_issue_404_returns_not_found(respx_mock):
    respx_mock.put("/issues/999/").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        result = await resolve_issue(client, "token", "999")

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