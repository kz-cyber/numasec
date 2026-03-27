"""JSON-RPC worker for the TypeScript agent bridge.

Long-lived subprocess that receives JSON-RPC requests on stdin,
dispatches them to the ToolRegistry, and writes responses to stdout.

Protocol:
  - One JSON object per line (newline-delimited JSON-RPC)
  - Sends {"ready": true} on startup
  - Request:  {"id": "...", "method": "tool_name", "params": {...}}
  - Response: {"id": "...", "result": {...}} or {"id": "...", "error": {"message": "..."}}

Special methods (not tool calls):
  - "list_tools": Returns available tool names and schemas
  - "create_session": Creates a new session
  - "save_finding": Saves a finding
  - "get_findings": Retrieves findings
  - "generate_report": Generates a report
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import traceback
from typing import Any

logger = logging.getLogger("numasec.worker")

# State management imports (lazy to avoid import-time side effects)
_registry = None
_session_store = None


def _get_registry():
    global _registry
    if _registry is None:
        from numasec.mcp._singletons import get_tool_registry
        _registry = get_tool_registry()
    return _registry


def _get_session_store():
    global _session_store
    if _session_store is None:
        from numasec.mcp._singletons import get_session_store
        _session_store = get_session_store()
    return _session_store


async def _handle_list_tools() -> dict[str, Any]:
    """Return available tools and their schemas."""
    reg = _get_registry()
    return {
        "tools": reg.available_tools,
        "schemas": reg.get_schemas(),
    }


async def _handle_create_session(params: dict) -> dict[str, Any]:
    """Create a new pentest session."""
    from numasec.mcp.state_tools import create_session
    return await create_session(
        target_url=params.get("target_url", ""),
        session_name=params.get("session_name", ""),
        scope=params.get("scope", ""),
    )


async def _handle_save_finding(params: dict) -> dict[str, Any]:
    """Save a security finding."""
    from numasec.mcp.state_tools import save_finding
    return await save_finding(**params)


async def _handle_get_findings(params: dict) -> dict[str, Any]:
    """Retrieve findings."""
    from numasec.mcp.state_tools import get_findings
    return await get_findings(**params)


async def _handle_generate_report(params: dict) -> dict[str, Any]:
    """Generate a security report."""
    from numasec.mcp.state_tools import generate_report
    return await generate_report(**params)


async def _handle_relay_credentials(params: dict) -> dict[str, Any]:
    """Store discovered credentials."""
    from numasec.mcp.state_tools import relay_credentials
    return await relay_credentials(**params)


async def _handle_kb_search(params: dict) -> dict[str, Any]:
    """Search the knowledge base."""
    from numasec.mcp.intel_tools import kb_search
    return await kb_search(**params)


async def _handle_plan(params: dict) -> dict[str, Any]:
    """Get pentest plan / coverage."""
    from numasec.mcp.intel_tools import plan
    return await plan(**params)


# Method dispatch table
SPECIAL_METHODS = {
    "list_tools": _handle_list_tools,
    "create_session": _handle_create_session,
    "save_finding": _handle_save_finding,
    "get_findings": _handle_get_findings,
    "generate_report": _handle_generate_report,
    "relay_credentials": _handle_relay_credentials,
    "kb_search": _handle_kb_search,
    "plan": _handle_plan,
}


async def dispatch(method: str, params: dict) -> Any:
    """Route a JSON-RPC call to the appropriate handler."""
    # Check special methods first
    if method in SPECIAL_METHODS:
        handler = SPECIAL_METHODS[method]
        if method == "list_tools":
            return await handler()
        return await handler(params)

    # Otherwise dispatch to ToolRegistry
    reg = _get_registry()
    if method not in reg.available_tools:
        raise ValueError(f"Unknown tool: {method}")
    return await reg.call(method, **params)


def _write_json(obj: dict) -> None:
    """Write a JSON object to stdout as a single line."""
    sys.stdout.write(json.dumps(obj, default=str) + "\n")
    sys.stdout.flush()


async def main() -> None:
    """Main worker loop — read JSON-RPC requests, dispatch, respond."""
    # Configure logging to stderr so stdout stays clean for JSON-RPC
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    logger.info("numasec worker starting...")

    # Signal readiness
    _write_json({"ready": True})

    # Read stdin line by line
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line = await reader.readline()
        if not line:
            logger.info("stdin closed, shutting down")
            break

        line_str = line.decode("utf-8").strip()
        if not line_str:
            continue

        try:
            request = json.loads(line_str)
        except json.JSONDecodeError as e:
            logger.error("invalid JSON: %s", e)
            continue

        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        try:
            result = await dispatch(method, params)
            # Ensure result is JSON-serializable
            if not isinstance(result, (dict, list, str, int, float, bool, type(None))):
                result = str(result)
            _write_json({"id": req_id, "result": result})
        except Exception as e:
            logger.error("error dispatching %s: %s", method, traceback.format_exc())
            _write_json({
                "id": req_id,
                "error": {
                    "message": str(e),
                    "type": type(e).__name__,
                },
            })


if __name__ == "__main__":
    asyncio.run(main())
