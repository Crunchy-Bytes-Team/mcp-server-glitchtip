# mcp-server-glitchtip - MCP server for GlitchTip
# Supports stdio (default) and streamable-http (set MCP_TRANSPORT=streamable-http).
# Example stdio: docker run --rm -i -e GLITCHTIP_API_URL=... -e GLITCHTIP_AUTH_TOKEN=... ...
# Example HTTP:  docker run -p 8000:8000 -e MCP_TRANSPORT=streamable-http -e GLITCHTIP_* ...

FROM python:3.12-slim

WORKDIR /app

EXPOSE 8000

# Install package and runtime dependencies only (no test deps)
COPY pyproject.toml README.md server.py ./
RUN pip install --no-cache-dir .

# Run as non-root
RUN useradd --create-home --shell /bin/bash appuser && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["mcp-server-glitchtip"]
