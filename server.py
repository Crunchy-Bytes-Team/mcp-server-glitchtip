#!/usr/bin/env python3
"""
mcp-server-glitchtip - MCP server enabling LLMs to query issues, stacktraces,
and resolve errors in GlitchTip.

GlitchTip is an open-source, self-hosted error tracking platform that's
API-compatible with Sentry. This MCP server lets AI assistants directly
access your error data to help debug and fix issues faster.

https://github.com/hffmnnj/mcp-server-glitchtip
"""

import ipaddress
import logging
import os
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
import mcp.types as types
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

ALLOWED_STATUSES = frozenset({"unresolved", "resolved", "ignored"})

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


def normalize_status(value: str | None) -> str:
    """Return value if in ALLOWED_STATUSES, else 'unresolved'."""
    if value in ALLOWED_STATUSES:
        return value
    return "unresolved"


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

    @mcp.tool(
        description="""Mark a GlitchTip issue as resolved after fixing it.
Use this after you've fixed the bug causing the error.
Pass organization_slug and project_slug (same as get_glitchtip_issues), or set GLITCHTIP_ORGANIZATION and GLITCHTIP_PROJECT as defaults.""",
    )
    async def resolve_glitchtip_issue(
        issue_id: str,
        organization_slug: str | None = None,
        project_slug: str | None = None,
    ) -> str:
        if not issue_id:
            return "Error: Missing issue_id argument"
        if not validate_issue_id(issue_id):
            return "Error: issue_id must be a numeric ID."
        org = (organization_slug or _default_org) or ""
        proj = (project_slug or _default_proj) or ""
        if not org or not proj:
            return "Error: organization_slug and project_slug are required (or set GLITCHTIP_ORGANIZATION and GLITCHTIP_PROJECT). Use list_glitchtip_organizations and list_glitchtip_projects to discover values."
        if not validate_slug(org):
            return "Error: organization_slug must contain only letters, numbers, hyphens, and underscores."
        if not validate_slug(proj):
            return "Error: project_slug must contain only letters, numbers, hyphens, and underscores."
        return await resolve_issue(http_client, auth_token, issue_id, org, proj)

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
