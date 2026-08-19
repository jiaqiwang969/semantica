"""Compatibility stdio loop for Semantica's canonical MCP adapter.

Implements the Model Context Protocol so any MCP-compatible AI tool
(Claude Code, Cursor, Windsurf, Cline, Continue, VS Code Copilot, etc.)
can interact with Semantica. Protocol dispatch is owned exclusively by
``semantica.mcp_server.handle_mcp_request``.

Run:
    python -m mcp                  # via __main__.py
    python -m mcp.server           # direct
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from semantica.mcp_server import handle_mcp_request

log = logging.getLogger("semantica.mcp.server")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _err(request_id: Any, code: int, message: str, data: Any = None) -> dict:
    error: dict = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


# JSON-RPC error codes
_PARSE_ERROR = -32700
_INTERNAL_ERROR = -32603

# ---------------------------------------------------------------------------
# Compatibility request handlers, all delegated to the canonical adapter
# ---------------------------------------------------------------------------

def _canonical(req_id: Any, method: str, params: dict) -> dict:
    response = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }
    )
    if response is None:
        return _ok(req_id, {})
    return response


def _handle_initialize(req_id: Any, params: dict) -> dict:
    return _canonical(req_id, "initialize", params)


def _handle_tools_list(req_id: Any, _params: dict) -> dict:
    return _canonical(req_id, "tools/list", _params)


def _handle_tools_call(req_id: Any, params: dict) -> dict:
    return _canonical(req_id, "tools/call", params)


def _handle_resources_list(req_id: Any, _params: dict) -> dict:
    return _canonical(req_id, "resources/list", _params)


def _handle_resources_read(req_id: Any, params: dict) -> dict:
    return _canonical(req_id, "resources/read", params)


def _handle_ping(req_id: Any, _params: dict) -> dict:
    return _canonical(req_id, "ping", _params)


# ---------------------------------------------------------------------------
# Main server class
# ---------------------------------------------------------------------------

class SemanticaMCPServer:
    """Semantica MCP server — reads JSON-RPC requests from stdin, writes to stdout."""

    def __init__(self, *, debug: bool = False) -> None:
        level = logging.DEBUG if debug else logging.WARNING
        logging.basicConfig(stream=sys.stderr, level=level,
                            format="%(name)s %(levelname)s %(message)s")

    # ------------------------------------------------------------------
    def dispatch(self, request: dict) -> dict | None:
        """Process one JSON-RPC request and return a response dict (or None for notifications)."""
        try:
            return handle_mcp_request(request)
        except Exception as exc:
            method = request.get("method", "")
            req_id = request.get("id")
            log.exception("Unhandled error in canonical method %s", method)
            if req_id is None:
                return None
            return _err(
                req_id, _INTERNAL_ERROR,
                f"Method '{method}' failed ({type(exc).__name__}). See server logs for details.",
            )

    # ------------------------------------------------------------------
    def run(self) -> None:
        """Start the stdio event loop."""
        log.info("Semantica MCP server starting (stdio)")
        for raw_line in sys.stdin:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                request = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                response = _err(None, _PARSE_ERROR, f"Parse error: {exc}")
                _write(response)
                continue

            if isinstance(request, list):
                # Batch request
                responses = []
                for req in request:
                    resp = self.dispatch(req)
                    if resp is not None:
                        responses.append(resp)
                if responses:
                    _write(responses)
            else:
                resp = self.dispatch(request)
                if resp is not None:
                    _write(resp)


def _write(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Semantica MCP Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    SemanticaMCPServer(debug=args.debug).run()


if __name__ == "__main__":
    main()
