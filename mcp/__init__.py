"""Compatibility package for Semantica's canonical MCP server.

All protocol dispatch, tool registration, and resource registration live in
``semantica.mcp_server``.  This top-level package preserves the historical
``python -m mcp`` command without maintaining a second implementation.

Run the server:
    python -m mcp.server        # from repo root
    python -m semantica.mcp_server  # canonical installed entry

Configure in Claude Desktop, Windsurf, Cline, Continue, VS Code:
    {
        "mcpServers": {
            "semantica": {
                "command": "python",
                "args": ["-m", "mcp.server"],
                "cwd": "/path/to/semantica"
            }
        }
    }
"""

# `semantica.__version__` is the authoritative package version — see
# semantica/mcp_server/__init__.py for why it is used directly rather than
# importlib.metadata.version("semantica").
from semantica import __version__

from .server import SemanticaMCPServer, main

__all__ = ["SemanticaMCPServer", "main", "__version__"]
