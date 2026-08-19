"""Compatibility view of the canonical Semantica MCP resource registry.

All resource definitions and reads delegate to :mod:`semantica.mcp_server` so
``python -m mcp`` and ``python -m semantica.mcp_server`` expose identical
package manifests, registry data, and error semantics.
"""

from __future__ import annotations

import json

from semantica.mcp_server import list_mcp_resources, read_mcp_resource


def _canonical_resource(uri: str) -> dict:
    data = read_mcp_resource(uri)
    return {
        "uri": uri,
        "mimeType": "application/json",
        "text": json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    }


def _read_graph_summary(uri: str) -> dict:
    return _canonical_resource(uri)


def _read_decisions_list(uri: str) -> dict:
    return _canonical_resource(uri)


def _read_schema_info(uri: str) -> dict:
    return _canonical_resource(uri)


def _read_ontology_schema(uri: str) -> dict:
    return _canonical_resource(uri)


RESOURCE_DEFINITIONS = list_mcp_resources()


def handle_resource_read(uri: str) -> dict:
    """Read through the canonical registry; user input never becomes a path."""

    return _canonical_resource(uri)
