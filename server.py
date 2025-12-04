#!/usr/bin/env python3
"""
mcp-server-glitchtip - MCP server enabling LLMs to query issues, stacktraces,
and resolve errors in GlitchTip.

GlitchTip is an open-source, self-hosted error tracking platform that's
API-compatible with Sentry. This MCP server lets AI assistants directly
access your error data to help debug and fix issues faster.

https://github.com/hffmnnj/mcp-server-glitchtip
"""

import asyncio
import os
from dataclasses import dataclass

import httpx
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio


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
        return f"Error fetching issue: {e}"
    except Exception as e:
        return f"Error: {e}"


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
        return f"Error fetching issues: {e}"
    except Exception as e:
        return f"Error: {e}"


async def resolve_issue(
    http_client: httpx.AsyncClient,
    auth_token: str,
    issue_id: str
) -> str:
    """Mark an issue as resolved."""
    try:
        response = await http_client.put(
            f"issues/{issue_id}/",
            json={"status": "resolved"},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            return "Error: Unauthorized. Check your GLITCHTIP_AUTH_TOKEN."
        if response.status_code == 404:
            return f"Error: Issue {issue_id} not found."
        response.raise_for_status()
        return f"Issue {issue_id} marked as resolved."
    except httpx.HTTPStatusError as e:
        return f"Error resolving issue: {e}"
    except Exception as e:
        return f"Error: {e}"


async def serve(
    api_base: str,
    auth_token: str,
    organization_slug: str,
    project_slug: str
) -> Server:
    """Create and configure the MCP server."""
    server = Server("glitchtip")
    http_client = httpx.AsyncClient(base_url=api_base, timeout=30.0)

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="get_glitchtip_issues",
                description="""List all issues from GlitchTip for the configured project.
                Use this to see all current errors and exceptions in production.
                Returns issue titles, counts, status, and when they were first/last seen.""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "description": "Filter by status: 'unresolved', 'resolved', 'ignored'",
                            "default": "unresolved"
                        }
                    },
                    "required": []
                }
            ),
            types.Tool(
                name="get_glitchtip_issue",
                description="""Get detailed information about a specific GlitchTip issue including full stacktrace.
                Use this when you need to investigate a specific error in detail.
                Provides the complete stacktrace, error counts, and timing information.""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "issue_id": {
                            "type": "string",
                            "description": "The GlitchTip issue ID (numeric)"
                        }
                    },
                    "required": ["issue_id"]
                }
            ),
            types.Tool(
                name="resolve_glitchtip_issue",
                description="""Mark a GlitchTip issue as resolved after fixing it.
                Use this after you've fixed the bug causing the error.""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "issue_id": {
                            "type": "string",
                            "description": "The GlitchTip issue ID to resolve"
                        }
                    },
                    "required": ["issue_id"]
                }
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent]:
        arguments = arguments or {}

        if name == "get_glitchtip_issues":
            status = arguments.get("status", "unresolved")
            result = await fetch_project_issues(
                http_client, auth_token, organization_slug, project_slug, status
            )
            # Handle error string
            if isinstance(result, str):
                return [types.TextContent(type="text", text=result)]

            issues = result
            if not issues:
                return [types.TextContent(type="text", text=f"No {status} issues found.")]

            text = f"GlitchTip Issues ({status}):\n\n"
            for issue in issues:
                text += f"---\n"
                text += f"ID: {issue.issue_id} ({issue.short_id})\n"
                text += f"Title: {issue.title}\n"
                text += f"Level: {issue.level} | Count: {issue.count}\n"
                text += f"Culprit: {issue.culprit}\n"
                text += f"First: {issue.first_seen} | Last: {issue.last_seen}\n\n"
            return [types.TextContent(type="text", text=text)]

        elif name == "get_glitchtip_issue":
            issue_id = arguments.get("issue_id")
            if not issue_id:
                return [types.TextContent(type="text", text="Error: Missing issue_id argument")]
            result = await fetch_issue(http_client, auth_token, issue_id)
            # Handle error string
            if isinstance(result, str):
                return [types.TextContent(type="text", text=result)]
            return result.to_tool_result()

        elif name == "resolve_glitchtip_issue":
            issue_id = arguments.get("issue_id")
            if not issue_id:
                return [types.TextContent(type="text", text="Error: Missing issue_id argument")]
            result = await resolve_issue(http_client, auth_token, issue_id)
            return [types.TextContent(type="text", text=result)]

        else:
            return [types.TextContent(type="text", text=f"Error: Unknown tool: {name}")]

    return server


def main():
    """Main entry point."""
    # Configuration from environment variables
    api_base = os.environ.get("GLITCHTIP_API_URL", "")
    auth_token = os.environ.get("GLITCHTIP_AUTH_TOKEN", "")
    organization_slug = os.environ.get("GLITCHTIP_ORGANIZATION", "")
    project_slug = os.environ.get("GLITCHTIP_PROJECT", "")

    missing = []
    if not api_base:
        missing.append("GLITCHTIP_API_URL")
    if not auth_token:
        missing.append("GLITCHTIP_AUTH_TOKEN")
    if not organization_slug:
        missing.append("GLITCHTIP_ORGANIZATION")
    if not project_slug:
        missing.append("GLITCHTIP_PROJECT")

    if missing:
        print(f"Error: Missing required environment variables: {', '.join(missing)}")
        print("\nRequired configuration:")
        print("  GLITCHTIP_API_URL       - Your GlitchTip API URL (e.g., https://glitchtip.example.com/api/0/)")
        print("  GLITCHTIP_AUTH_TOKEN    - API token from your GlitchTip settings")
        print("  GLITCHTIP_ORGANIZATION  - Your organization slug")
        print("  GLITCHTIP_PROJECT       - Your project slug")
        return

    async def _run():
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            server = await serve(api_base, auth_token, organization_slug, project_slug)
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="glitchtip",
                    server_version="1.0.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    asyncio.run(_run())


if __name__ == "__main__":
    main()
