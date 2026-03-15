# Security Analysis: mcp-server-glitchtip

This document summarizes a security review of the GlitchTip MCP server (`server.py`) and related configuration.

---

## Executive Summary

The server is a small, focused MCP that proxies tools to the GlitchTip API. Several issues were identified: **input validation** (path traversal and parameter injection), **URL/scheme validation**, **error information disclosure**, and **operational** considerations (secrets, TLS, dependencies). Recommendations are listed for each finding.

---

## 1. Input Validation

### 1.1 Path Traversal via `issue_id` (Medium)

**Location:** `fetch_issue()`, `resolve_issue()` — paths built as `f"issues/{issue_id}/"`, etc.

**Issue:** `issue_id` is taken from MCP tool arguments and concatenated into URL path segments. HTTPX joins paths with the base URL and **resolves relative segments** (e.g. `..`). A client could pass:

- `issue_id = "../admin/users"` → request to `.../api/0/issues/../admin/users/` → `.../api/0/admin/users/`
- `issue_id = "123/../../../other"` → traversal outside the intended path

This can lead to **server-side request path manipulation** and access to API endpoints or resources the token was not intended to access.

**Recommendation:**

- Validate `issue_id` before use:
  - Allow only digits (e.g. `^\d+$`) if the GlitchTip API uses numeric IDs only.
  - Or allow a strict alphanumeric/slug pattern and **reject** any value containing `/`, `\`, `..`, or `%` (to avoid encoded path traversal).
- Apply the same idea to **organization_slug** and **project_slug** (no path separators or `..`).

**Example:**

```python
import re

def validate_issue_id(issue_id: str) -> bool:
    return bool(issue_id and re.match(r"^\d+$", str(issue_id).strip()))

# In handle_call_tool, before calling fetch_issue / resolve_issue:
if not validate_issue_id(issue_id):
    return [types.TextContent(type="text", text="Error: issue_id must be a numeric ID")]
```

---

### 1.2 Status Parameter Injection (Low)

**Location:** `fetch_project_issues()` — `params={"query": f"is:{status}"}` and tool handler with `status = arguments.get("status", "unresolved")`.

**Issue:** `status` is user-controlled and interpolated into the query string. If an attacker can pass values like `resolved" or "1"="1` or newline, the resulting query might change API behavior or cause unexpected parsing (depending on GlitchTip’s query parser).

**Recommendation:**

- Restrict `status` to a fixed set of allowed values:

```python
ALLOWED_STATUSES = {"unresolved", "resolved", "ignored"}

status = arguments.get("status", "unresolved")
if status not in ALLOWED_STATUSES:
    status = "unresolved"
```

Use only this validated `status` in `params={"query": f"is:{status}"}`.

---

## 2. Configuration and Network

### 2.1 API URL Scheme and SSRF (Medium)

**Location:** `main()` — `api_base = os.environ.get("GLITCHTIP_API_URL", "")` and `httpx.AsyncClient(base_url=api_base, ...)`.

**Issues:**

- **No URL validation:** A typo or misconfiguration could use `http://` instead of `https://`, sending the API token over cleartext.
- **SSRF:** If an attacker can control the environment (e.g. in a shared or compromised host), setting `GLITCHTIP_API_URL` to an internal URL (e.g. `http://169.254.169.254/`) could make the server send the bearer token to internal or metadata endpoints.

**Recommendations:**

- Parse `api_base` with `urllib.parse.urlparse` and:
  - Require `scheme == "https"` unless the host is `localhost` or `127.0.0.1` (or another explicitly allowed dev list).
  - Optionally block private/internal IP ranges if you ever support non-local URLs.
- Reject malformed or unexpected URLs at startup and exit with a clear message.

---

### 2.2 TLS Verification (Informational)

**Location:** `httpx.AsyncClient(base_url=api_base, timeout=30.0)`.

**Observation:** HTTPX verifies TLS by default. No custom `verify=False` or adapter was found, which is good.

**Recommendation:** Keep default TLS verification; do not disable it for production.

---

## 3. Secrets and Error Handling

### 3.1 Auth Token Handling (Low / Good)

**Observation:** The token is read from the environment and only passed in the `Authorization` header. Error messages say “Check your GLITCHTIP_AUTH_TOKEN” without echoing the value. No logging of the token was seen.

**Recommendation:** Ensure no future logging or error reporting includes headers or request bodies that could contain the token.

---

### 3.2 Sensitive Data in API Responses (Informational)

**Location:** `create_stacktrace()` and all code that returns issue/event data to the MCP client (and thus to the LLM/user).

**Issue:** GlitchTip events can contain arbitrary application data (local variables, request headers, environment snippets, user input). The server forwards this to the client without redaction. That may expose:

- PII (names, emails, IPs)
- Secrets (tokens, API keys, passwords in env or headers)
- Internal URLs or infrastructure details

**Recommendation:** Treat this as a **data handling / compliance** topic:

- Document that the server returns raw error/stacktrace data and may include sensitive content.
- Consider optional redaction (e.g. strip known header names like `Authorization`, `Cookie`, or configurable patterns) or truncation of large context blocks.
- Rely on GlitchTip and deployment practices (network, token scope) to limit what can be reported.

The README has been updated with a "Security and data" section describing this.

---

### 3.3 Exception Message Disclosure (Low)

**Location:** Multiple `except Exception as e: return f"Error: {e}"` (e.g. in `fetch_issue`, `fetch_project_issues`, `resolve_issue`).

**Issue:** Generic exception messages are returned to the MCP client. They can include:

- File paths and line numbers
- Library or OS messages
- Stack traces (if `e` is later rendered with traceback)

That could aid reconnaissance or confuse users.

**Recommendation:**

- Catch specific exceptions (e.g. `httpx.HTTPStatusError`, `httpx.RequestError`, `ValueError`) and return stable, minimal messages.
- For unexpected exceptions, log the full traceback server-side and return a generic message (e.g. “An unexpected error occurred.”) without `str(e)` to the client.

---

## 4. Operational and Dependency Security

### 4.1 Dependency Pinning (Informational)

**Location:** `pyproject.toml` — `mcp>=1.0.0`, `httpx>=0.27.0`.

**Observation:** Minimum versions are specified; exact versions are not pinned.

**Recommendation:** Use a lockfile (e.g. `pip-tools`, `uv`, or `poetry`) and pin exact versions in CI and production to reduce supply-chain and compatibility risk. The README recommends installing from a lockfile when available.

---

### 4.2 Timeout (Good)

**Observation:** `httpx.AsyncClient(..., timeout=30.0)` sets a request timeout, limiting hang and resource abuse.

**Recommendation:** Keep a finite timeout; consider making it configurable for strict environments.

---

## 5. Summary Table

| Area              | Finding                         | Severity   | Mitigation |
|-------------------|----------------------------------|------------|------------|
| Input validation  | Path traversal via `issue_id`    | Medium     | Strict allow-list (e.g. digits only) and reject `/`, `..`, `%` in IDs/slugs |
| Input validation  | `status` query injection         | Low        | Restrict to allowed set (`unresolved`, `resolved`, `ignored`) |
| Config / network  | No URL/scheme validation        | Medium     | Require HTTPS (except allowed dev hosts); validate with `urlparse` |
| Config / network  | SSRF via `GLITCHTIP_API_URL`     | Medium     | Same URL validation; optionally block private IPs |
| Secrets           | Token in errors                 | Low (none found) | Avoid logging or returning headers/body |
| Data handling     | PII/secrets in stacktraces      | Informational | Document; consider redaction/truncation |
| Error handling    | Raw exception messages to client| Low        | Catch specific exceptions; generic message for unknown |
| Dependencies      | No lockfile                     | Informational | Use lockfile and pin versions |

---

## 6. Positive Notes

- No use of `verify=False`; TLS verification is enabled by default.
- Auth token is not logged or echoed in responses.
- Request timeout is set (30s).
- Required configuration is enforced at startup (missing env vars prevent run).
- Small, readable codebase with a narrow API surface.

---

*Analysis date: 2025-03-15. Codebase: server.py (single-file MCP server), pyproject.toml, .env.example, README.md.*
