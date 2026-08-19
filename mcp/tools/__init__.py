"""Compatibility view of the canonical Semantica MCP tool registry.

The active registry lives in :mod:`semantica.mcp_server`.  The historical
top-level ``mcp.tools`` import remains available, but it no longer assembles a
second set of handlers.
"""

from semantica.mcp_server import TOOLS as TOOL_DEFINITIONS


__all__ = ["TOOL_DEFINITIONS"] + [
    tool["name"] for tool in TOOL_DEFINITIONS
]
for _tool in TOOL_DEFINITIONS:
    globals()[_tool["name"]] = _tool["_handler"]

del _tool
