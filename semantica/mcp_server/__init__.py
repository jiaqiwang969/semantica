"""
Semantica MCP Server

Exposes Semantica's knowledge graph, decision intelligence, semantic extraction,
reasoning, analytics, and built-in semantic package lifecycle as an MCP (Model
Context Protocol) server over stdio — compatible with Claude Desktop, Windsurf,
Cline, Continue, VS Code, Roo Code, and any other MCP-aware tool.

Usage
-----
Configure in your tool's MCP settings:

    Claude Desktop / Windsurf / Cline / Continue / VS Code:
    {
        "mcpServers": {
            "semantica": {
                "command": "semantica-mcp"
            }
        }
    }

Or using python -m:
    {
        "mcpServers": {
            "semantica": {
                "command": "python",
                "args": ["-m", "semantica.mcp_server"]
            }
        }
    }

Run directly for testing:
    semantica-mcp
    # or
    python -m semantica.mcp_server

Environment variables:
    SEMANTICA_KG_PATH   — path to a persisted graph to load on start (optional)
    SEMANTICA_LOG_LEVEL — log level: DEBUG, INFO, WARNING (default: WARNING)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Mapping

# `semantica.__version__` is the authoritative package version — it is kept in
# sync with pyproject.toml's static `version` field by the release process and
# is always present whenever this submodule is importable.  Using it directly
# is simpler and more reliable than `importlib.metadata.version("semantica")`,
# which reads dist-info written at install time and can lag the source in
# editable installs (egg-info / dist-info is not regenerated on every version
# bump, so it can reflect a stale value).
from semantica import __version__ as _SEMANTICA_VERSION

# ── logging ────────────────────────────────────────────────────────────────
_log_level = getattr(logging, os.environ.get("SEMANTICA_LOG_LEVEL", "WARNING").upper(), logging.WARNING)
logging.basicConfig(stream=sys.stderr, level=_log_level,
                    format="%(asctime)s [semantica-mcp] %(levelname)s %(message)s")
log = logging.getLogger("semantica.mcp_server")

# ── lazy graph session ──────────────────────────────────────────────────────
_graph: Any = None


def _get_graph():
    global _graph
    if _graph is None:
        from semantica.context import ContextGraph
        _graph = ContextGraph(advanced_analytics=True)
        kg_path = os.environ.get("SEMANTICA_KG_PATH")
        if kg_path and os.path.exists(kg_path):
            try:
                _graph.load(kg_path)
                log.info("Loaded graph from %s", kg_path)
            except Exception as exc:
                log.warning("Could not load graph from %s: %s", kg_path, exc)
    return _graph


# ══════════════════════════════════════════════════════════════════════════════
# Tool implementations
# ══════════════════════════════════════════════════════════════════════════════

def _tool_extract_entities(args: dict) -> dict:
    """Extract named entities from text."""
    text = args.get("text", "")
    if not text:
        return {"error": "text is required"}
    from semantica.semantic_extract import NamedEntityRecognizer
    entities = NamedEntityRecognizer().extract_entities(text)
    return {
        "entities": [
            {"label": getattr(e, "label", str(e)),
             "type": getattr(e, "type", None),
             "start": getattr(e, "start", None),
             "end": getattr(e, "end", None)}
            for e in (entities or [])
        ]
    }


def _tool_extract_relations(args: dict) -> dict:
    """Extract relations and triplets from text."""
    text = args.get("text", "")
    if not text:
        return {"error": "text is required"}
    from semantica.semantic_extract import RelationExtractor, TripletExtractor
    relations = RelationExtractor().extract_relations(text)
    triplets = TripletExtractor().extract_triplets(text)
    return {
        "relations": [
            {"source": getattr(r, "source", None),
             "type": getattr(r, "type", None),
             "target": getattr(r, "target", None)}
            for r in (relations or [])
        ],
        "triplets": [
            {"subject": getattr(t, "subject", None),
             "predicate": getattr(t, "predicate", None),
             "object": getattr(t, "object", None)}
            for t in (triplets or [])
        ],
    }


def _tool_record_decision(args: dict) -> dict:
    """Record a decision with full context into the graph."""
    required = ["category", "scenario", "reasoning", "outcome", "confidence"]
    for field in required:
        if field not in args:
            return {"error": f"missing required field: {field}"}
    graph = _get_graph()
    decision_id = graph.record_decision(
        category=args["category"],
        scenario=args["scenario"],
        reasoning=args["reasoning"],
        outcome=args["outcome"],
        confidence=float(args["confidence"]),
        entities=args.get("entities", []),
        decision_maker=args.get("decision_maker", "mcp_client"),
        valid_from=args.get("valid_from"),
        valid_until=args.get("valid_until"),
    )
    return {"decision_id": decision_id, "status": "recorded"}


def _tool_query_decisions(args: dict) -> dict:
    """Query decisions by natural language or structured filters."""
    query = args.get("query", "")
    category = args.get("category")
    limit = int(args.get("limit", 10))
    graph = _get_graph()
    try:
        if query:
            results = graph.find_similar_decisions(query, max_results=limit)
        elif category:
            nodes = graph.find_nodes(node_type="decision")
            results = [n for n in nodes if n.get("category") == category][:limit]
        else:
            results = graph.find_nodes(node_type="decision")[:limit]
        return {"decisions": results if isinstance(results, list) else list(results)}
    except Exception as exc:
        return {"error": str(exc), "decisions": []}


def _tool_find_precedents(args: dict) -> dict:
    """Find past decisions similar to a given scenario."""
    scenario = args.get("scenario", "")
    if not scenario:
        return {"error": "scenario is required"}
    max_results = int(args.get("max_results", 5))
    graph = _get_graph()
    try:
        precedents = graph.find_similar_decisions(scenario, max_results=max_results)
        return {"precedents": precedents if isinstance(precedents, list) else list(precedents)}
    except Exception as exc:
        return {"error": str(exc), "precedents": []}


def _tool_get_causal_chain(args: dict) -> dict:
    """Get the causal chain for a decision."""
    decision_id = args.get("decision_id", "")
    if not decision_id:
        return {"error": "decision_id is required"}
    direction = args.get("direction", "downstream")
    max_depth = int(args.get("max_depth", 5))
    graph = _get_graph()
    try:
        from semantica.context.causal_analyzer import CausalChainAnalyzer
        analyzer = CausalChainAnalyzer(graph_store=graph)
        chain = analyzer.get_causal_chain(decision_id, direction=direction, max_depth=max_depth)
        return {"chain": chain if isinstance(chain, list) else list(chain)}
    except Exception as exc:
        return {"error": str(exc), "chain": []}


def _tool_add_entity(args: dict) -> dict:
    """Add a node/entity to the knowledge graph."""
    node_id = args.get("id", "")
    label = args.get("label", node_id)
    node_type = args.get("type", "Entity")
    if not node_id:
        return {"error": "id is required"}
    graph = _get_graph()
    graph.add_node(node_id=node_id, label=label, node_type=node_type,
                   metadata=args.get("metadata", {}))
    return {"status": "added", "id": node_id}


def _tool_add_relationship(args: dict) -> dict:
    """Add a relationship (edge) between two entities."""
    source = args.get("source", "")
    target = args.get("target", "")
    rel_type = args.get("type", "RELATED_TO")
    if not source or not target:
        return {"error": "source and target are required"}
    graph = _get_graph()
    graph.add_edge(source_id=source, target_id=target, edge_type=rel_type,
                   metadata=args.get("metadata", {}))
    return {"status": "added", "source": source, "target": target, "type": rel_type}


def _tool_run_reasoning(args: dict) -> dict:
    """Run forward-chaining reasoning rules over a set of facts."""
    facts = args.get("facts", [])
    rules = args.get("rules", [])
    if not facts or not rules:
        return {"error": "facts and rules are required"}
    from semantica.reasoning import Reasoner
    reasoner = Reasoner()
    for rule in rules:
        reasoner.add_rule(rule)
    derived = reasoner.infer_facts(facts)
    return {"derived_facts": derived if isinstance(derived, list) else list(derived)}


def _tool_get_graph_analytics(args: dict) -> dict:
    """Compute graph analytics: centrality, community detection, metrics."""
    graph = _get_graph()
    try:
        from semantica.kg import CentralityCalculator, CommunityDetector
        centrality = CentralityCalculator().calculate_pagerank(graph)
        communities = CommunityDetector().detect_communities(graph)
        node_count = len(list(graph.find_nodes()))
        edge_count = getattr(graph, "edge_count", lambda: 0)()
        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "top_nodes_by_pagerank": sorted(
                centrality.items() if hasattr(centrality, "items") else [],
                key=lambda x: x[1], reverse=True
            )[:10],
            "community_count": len(communities) if isinstance(communities, (list, dict)) else 0,
        }
    except Exception as exc:
        return {"error": str(exc)}


def _tool_export_graph(args: dict) -> dict:
    """Export the current knowledge graph to a serialised format."""
    fmt = args.get("format", "json-ld")
    graph = _get_graph()
    try:
        from semantica.export import RDFExporter, JSONExporter
        if fmt in ("turtle", "ttl", "nt", "xml", "json-ld"):
            result = RDFExporter().export_to_rdf(graph, format=fmt)
        else:
            result = JSONExporter().export(graph)
        return {"format": fmt, "data": result}
    except Exception as exc:
        return {"error": str(exc)}


def _tool_get_graph_summary(args: dict) -> dict:
    """Return a high-level summary of the current graph."""
    graph = _get_graph()
    try:
        node_count = len(list(graph.find_nodes()))
        decisions = graph.find_nodes(node_type="decision")
        return {
            "node_count": node_count,
            "decision_count": len(list(decisions)),
            "graph_ready": True,
        }
    except Exception as exc:
        return {"error": str(exc), "graph_ready": False}


# ── built-in semantic packages ──────────────────────────────────────────────────


_NORMATIVE_PACKAGE_ID = "semantica.chapter_packages.vol2.normative"
_PACKAGE_RESOURCE_PREFIX = "semantica://packages/manifest/"


class _PackageMCPError(RuntimeError):
    """Controlled package error with a stable public code and message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _package_error(code: str, message: str) -> dict:
    return {
        "error": {"code": code, "message": message},
        "ok": False,
        "schema_version": "1.0",
    }


def _chapter_record(descriptor: Any) -> dict:
    """Return public registry fields without its local manifest path."""

    return {
        "chapter": descriptor.chapter,
        "key": descriptor.key,
        "kind": "chapter",
        "package_id": descriptor.package_id,
        "release_status": descriptor.release_status,
        "status": descriptor.status,
        "title": descriptor.title,
        "version": descriptor.version,
        "volume": descriptor.volume,
    }


def _normative_package() -> tuple[dict, Mapping[str, Any]]:
    """Read the fixed normative domain package; no caller path is accepted."""

    import yaml
    from semantica import chapter_packages as chapter_package_module

    root = Path(chapter_package_module.__file__).resolve().parent
    manifest_path = root / "vol2" / "normative" / "manifest.yaml"
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise _PackageMCPError(
            "package_metadata_invalid",
            "The built-in normative package manifest cannot be read.",
        ) from exc
    if not isinstance(manifest, Mapping) or manifest.get("package_id") != _NORMATIVE_PACKAGE_ID:
        raise _PackageMCPError(
            "package_metadata_invalid",
            "The built-in normative package manifest has an invalid identity.",
        )
    record = {
        "chapter": None,
        "key": "vol2.normative",
        "kind": "domain",
        "package_id": _NORMATIVE_PACKAGE_ID,
        "release_status": str(manifest.get("release_status", "blocked")),
        "status": str(manifest.get("status", "partial")),
        "title": str(
            manifest.get("title")
            or manifest.get("domain")
            or "ISO 26262 normative derived layer"
        ),
        "version": str(manifest.get("version", "")),
        "volume": "vol2",
    }
    return record, manifest


def _package_catalog(
    *, volume: str | None = None, include_domain_packages: bool = True
) -> tuple[dict, ...]:
    from semantica.chapter_packages import list_chapter_packages

    if volume not in (None, "vol1", "vol2"):
        raise _PackageMCPError(
            "invalid_argument", "volume must be 'vol1' or 'vol2'"
        )
    records = tuple(
        _chapter_record(item) for item in list_chapter_packages(volume)
    )
    if include_domain_packages and volume in (None, "vol2"):
        records += (_normative_package()[0],)
    return records


def _resolve_package(package_id: Any) -> tuple[dict, Mapping[str, Any]]:
    from semantica.chapter_packages import (
        list_chapter_packages,
        read_chapter_manifest,
    )

    if not isinstance(package_id, str) or not package_id:
        raise _PackageMCPError(
            "invalid_argument", "package_id must be a non-empty string"
        )
    if package_id == _NORMATIVE_PACKAGE_ID:
        return _normative_package()
    for descriptor in list_chapter_packages():
        if descriptor.package_id == package_id:
            try:
                manifest = read_chapter_manifest(
                    descriptor.volume, descriptor.chapter
                )
            except Exception as exc:
                raise _PackageMCPError(
                    "package_metadata_invalid",
                    "The registered package manifest cannot be read.",
                ) from exc
            return _chapter_record(descriptor), manifest
    raise _PackageMCPError(
        "package_not_found", "Unknown built-in package ID: {}".format(package_id)
    )


def _package_runner() -> Any:
    try:
        from semantica.chapter_packages import SemanticPackageRunner
    except ImportError as exc:
        raise _PackageMCPError(
            "execution_blocked",
            "SemanticPackageRunner is unavailable; package execution is blocked.",
        ) from exc
    return SemanticPackageRunner()


def _public_json_value(value: Any) -> Any:
    """Project DTO output into JSON values; reject opaque backend objects."""

    if hasattr(value, "as_dict") and callable(value.as_dict):
        value = value.as_dict()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise _PackageMCPError(
                "invalid_runner_result", "Runner DTO keys must be strings."
            )
        return {key: _public_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_public_json_value(item) for item in value]
    raise _PackageMCPError(
        "invalid_runner_result",
        "SemanticPackageRunner returned a non-public result; operation is blocked.",
    )


def _public_dto(value: Any) -> dict:
    projected = _public_json_value(value)
    if not isinstance(projected, dict):
        raise _PackageMCPError(
            "invalid_runner_result",
            "SemanticPackageRunner returned a non-DTO result; operation is blocked.",
        )
    return projected


def _package_execution_arguments(args: Mapping[str, Any]) -> dict:
    allowed = {
        "package_id",
        "runtime_artifact_sha256",
        "runtime_commit",
        "scenario_id",
    }
    extras = set(args) - allowed
    if extras:
        raise _PackageMCPError(
            "invalid_argument", "Unsupported package execution argument."
        )
    package_id = args.get("package_id")
    _resolve_package(package_id)
    scenario_id = args.get("scenario_id")
    if scenario_id is not None and not isinstance(scenario_id, str):
        raise _PackageMCPError(
            "invalid_argument", "scenario_id must be a string when provided"
        )
    runtime_commit = args.get("runtime_commit")
    if not isinstance(runtime_commit, str) or not runtime_commit.strip():
        raise _PackageMCPError(
            "invalid_argument", "runtime_commit must be a non-empty string"
        )
    digest = args.get("runtime_artifact_sha256")
    if not isinstance(digest, str):
        raise _PackageMCPError(
            "invalid_argument", "runtime_artifact_sha256 must be a string"
        )
    digest = digest.lower()
    if len(digest) != 64 or any(
        char not in "0123456789abcdef" for char in digest
    ):
        raise _PackageMCPError(
            "invalid_argument",
            "runtime_artifact_sha256 must be exactly 64 hexadecimal characters",
        )
    return {
        "package_id": package_id,
        "runtime_artifact_sha256": digest,
        "runtime_commit": runtime_commit,
        "scenario_id": scenario_id,
    }


def _execute_package_tool(operation: str, args: Mapping[str, Any]) -> dict:
    try:
        if not isinstance(args, Mapping):
            raise _PackageMCPError(
                "invalid_argument", "tool arguments must be an object"
            )
        kwargs = _package_execution_arguments(args)
        runner = _package_runner()
        run_method = getattr(runner, "run", None)
        if run_method is None or not callable(run_method):
            raise _PackageMCPError(
                "execution_blocked",
                "SemanticPackageRunner does not provide 'run'; operation is blocked.",
            )
        execution = run_method(**kwargs)
        result = _public_dto(execution)
        if operation == "verify":
            verify_method = getattr(runner, "verify", None)
            if verify_method is None or not callable(verify_method):
                raise _PackageMCPError(
                    "execution_blocked",
                    "SemanticPackageRunner does not provide 'verify'; operation is blocked.",
                )
            verdict = _public_dto(verify_method(execution))
            result = {
                "execution": result,
                "release_verdict": verdict,
            }
        elif operation != "run":
            raise _PackageMCPError(
                "invalid_argument", "Unknown package operation."
            )
        payload = {
            "ok": True,
            "operation": operation,
            "package_id": kwargs["package_id"],
            "result": result,
            "schema_version": "1.0",
        }
        if (
            operation == "verify"
            and result["release_verdict"].get("status") != "complete"
        ):
            payload["ok"] = False
            payload["error"] = {
                "code": "release_blocked",
                "message": "Package release verification is blocked.",
            }
        return payload
    except _PackageMCPError as exc:
        return _package_error(exc.code, exc.message)
    except Exception:
        log.exception("Built-in package %s failed closed", operation)
        return _package_error(
            "package_operation_failed", "Package operation failed closed."
        )


def _tool_list_chapter_packages(args: dict) -> dict:
    try:
        if not isinstance(args, Mapping):
            raise _PackageMCPError(
                "invalid_argument", "tool arguments must be an object"
            )
        if set(args) - {"include_domain_packages", "volume"}:
            raise _PackageMCPError(
                "invalid_argument", "Unsupported package-list argument."
            )
        include_domains = args.get("include_domain_packages", True)
        if not isinstance(include_domains, bool):
            raise _PackageMCPError(
                "invalid_argument", "include_domain_packages must be boolean"
            )
        packages = _package_catalog(
            volume=args.get("volume"),
            include_domain_packages=include_domains,
        )
        return {
            "chapter_package_count": sum(
                item["kind"] == "chapter" for item in packages
            ),
            "domain_package_count": sum(
                item["kind"] == "domain" for item in packages
            ),
            "ok": True,
            "package_count": len(packages),
            "packages": list(packages),
            "schema_version": "1.0",
        }
    except _PackageMCPError as exc:
        return _package_error(exc.code, exc.message)
    except Exception:
        log.exception("Built-in package discovery failed closed")
        return _package_error(
            "package_operation_failed", "Package discovery failed closed."
        )


def _tool_get_chapter_package(args: dict) -> dict:
    try:
        if not isinstance(args, Mapping):
            raise _PackageMCPError(
                "invalid_argument", "tool arguments must be an object"
            )
        if set(args) - {"package_id"}:
            raise _PackageMCPError(
                "invalid_argument", "Unsupported package-get argument."
            )
        record, manifest = _resolve_package(args.get("package_id"))
        return {
            "manifest": _public_json_value(manifest),
            "ok": True,
            "package": record,
            "schema_version": "1.0",
        }
    except _PackageMCPError as exc:
        return _package_error(exc.code, exc.message)
    except Exception:
        log.exception("Built-in package lookup failed closed")
        return _package_error(
            "package_operation_failed", "Package lookup failed closed."
        )


def _tool_verify_book_sources(args: dict) -> dict:
    """Verify the external Markdown/TeX stones against all chapter packages."""

    try:
        if not isinstance(args, Mapping):
            raise _PackageMCPError(
                "invalid_argument", "tool arguments must be an object"
            )
        if set(args) - {"book_root", "volume"}:
            raise _PackageMCPError(
                "invalid_argument", "Unsupported book-verification argument."
            )
        book_root = args.get("book_root")
        if not isinstance(book_root, str) or not book_root.strip():
            raise _PackageMCPError(
                "invalid_argument", "book_root must be a non-empty string"
            )
        volume = args.get("volume")
        if volume not in (None, "vol1", "vol2"):
            raise _PackageMCPError(
                "invalid_argument", "volume must be 'vol1' or 'vol2'"
            )
        from semantica.chapter_packages import verify_book_source_bindings

        result = verify_book_source_bindings(Path(book_root), volume=volume)
        payload = {
            "ok": result.passed,
            "operation": "verify_book_sources",
            "result": _public_dto(result),
            "schema_version": "1.0",
        }
        if not result.passed:
            payload["error"] = {
                "code": "book_source_binding_failed",
                "message": "Book-to-Semantica source verification is blocked.",
            }
        return payload
    except _PackageMCPError as exc:
        return _package_error(exc.code, exc.message)
    except Exception:
        log.exception("Book-to-Semantica verification failed closed")
        return _package_error(
            "package_operation_failed", "Book source verification failed closed."
        )


def _tool_run_chapter_package(args: dict) -> dict:
    return _execute_package_tool("run", args)


def _tool_verify_chapter_package(args: dict) -> dict:
    return _execute_package_tool("verify", args)


# ══════════════════════════════════════════════════════════════════════════════
# MCP protocol tables
# ══════════════════════════════════════════════════════════════════════════════

TOOLS = [
    {
        "name": "extract_entities",
        "description": "Extract named entities (people, places, organisations, concepts) from text using Semantica NER.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Input text to extract entities from"}
            },
            "required": ["text"],
        },
        "_handler": _tool_extract_entities,
    },
    {
        "name": "extract_relations",
        "description": "Extract relations and (subject, predicate, object) triplets from text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Input text to extract relations from"}
            },
            "required": ["text"],
        },
        "_handler": _tool_extract_relations,
    },
    {
        "name": "record_decision",
        "description": "Record a decision into the Semantica knowledge graph with full context, causal links, and metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category":      {"type": "string", "description": "Decision category, e.g. 'loan_approval'"},
                "scenario":      {"type": "string", "description": "Natural-language situation description"},
                "reasoning":     {"type": "string", "description": "Why this decision was made"},
                "outcome":       {"type": "string", "description": "Decision outcome, e.g. 'approved'"},
                "confidence":    {"type": "number", "description": "Confidence score 0–1"},
                "decision_maker":{"type": "string", "description": "Who/what made the decision"},
                "valid_from":    {"type": "string", "description": "ISO date validity start (optional)"},
                "valid_until":   {"type": "string", "description": "ISO date validity end (optional)"},
            },
            "required": ["category", "scenario", "reasoning", "outcome", "confidence"],
        },
        "_handler": _tool_record_decision,
    },
    {
        "name": "query_decisions",
        "description": "Query recorded decisions by natural language, category, or get all recent decisions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":    {"type": "string", "description": "Natural language query (optional)"},
                "category": {"type": "string", "description": "Filter by category (optional)"},
                "limit":    {"type": "integer", "description": "Max results (default 10)"},
            },
        },
        "_handler": _tool_query_decisions,
    },
    {
        "name": "find_precedents",
        "description": "Find past decisions similar to a given scenario using hybrid similarity search.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scenario":    {"type": "string", "description": "Scenario description to find precedents for"},
                "max_results": {"type": "integer", "description": "Max results (default 5)"},
            },
            "required": ["scenario"],
        },
        "_handler": _tool_find_precedents,
    },
    {
        "name": "get_causal_chain",
        "description": "Trace the causal chain upstream or downstream from a decision.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "decision_id": {"type": "string", "description": "Decision ID to trace"},
                "direction":   {"type": "string", "enum": ["upstream", "downstream"], "description": "Trace direction"},
                "max_depth":   {"type": "integer", "description": "Max chain depth (default 5)"},
            },
            "required": ["decision_id"],
        },
        "_handler": _tool_get_causal_chain,
    },
    {
        "name": "add_entity",
        "description": "Add a node/entity to the Semantica knowledge graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id":       {"type": "string", "description": "Unique node ID"},
                "label":    {"type": "string", "description": "Human-readable label"},
                "type":     {"type": "string", "description": "Node type, e.g. 'Person', 'Organisation'"},
                "metadata": {"type": "object", "description": "Additional properties"},
            },
            "required": ["id"],
        },
        "_handler": _tool_add_entity,
    },
    {
        "name": "add_relationship",
        "description": "Add a directed relationship (edge) between two entities in the knowledge graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source":   {"type": "string", "description": "Source node ID"},
                "target":   {"type": "string", "description": "Target node ID"},
                "type":     {"type": "string", "description": "Relationship type, e.g. 'WORKS_AT'"},
                "metadata": {"type": "object", "description": "Additional edge properties"},
            },
            "required": ["source", "target"],
        },
        "_handler": _tool_add_relationship,
    },
    {
        "name": "run_reasoning",
        "description": "Run forward-chaining IF/THEN rules over a set of facts to derive new facts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "facts": {
                    "type": "array", "items": {"type": "string"},
                    "description": "List of fact strings, e.g. ['Person(John)', 'Employee(John)']",
                },
                "rules": {
                    "type": "array", "items": {"type": "string"},
                    "description": "IF/THEN rule strings, e.g. ['IF Employee(?x) THEN WorkerBee(?x)']",
                },
            },
            "required": ["facts", "rules"],
        },
        "_handler": _tool_run_reasoning,
    },
    {
        "name": "get_graph_analytics",
        "description": "Compute PageRank centrality and community detection over the knowledge graph.",
        "inputSchema": {"type": "object", "properties": {}},
        "_handler": _tool_get_graph_analytics,
    },
    {
        "name": "export_graph",
        "description": "Export the current knowledge graph. Formats: turtle, ttl, nt, xml, json-ld, json.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["turtle", "ttl", "nt", "xml", "json-ld", "json"],
                    "description": "Export format (default: json-ld)",
                }
            },
        },
        "_handler": _tool_export_graph,
    },
    {
        "name": "get_graph_summary",
        "description": "Return a high-level summary of the current knowledge graph: node count, decision count, status.",
        "inputSchema": {"type": "object", "properties": {}},
        "_handler": _tool_get_graph_summary,
    },
    {
        "name": "list_chapter_packages",
        "description": "List Semantica's 29 built-in chapter packages and optional normative domain package.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "volume": {
                    "type": "string",
                    "enum": ["vol1", "vol2"],
                    "description": "Optional book-volume filter.",
                },
                "include_domain_packages": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include the fixed ISO 26262 normative domain package.",
                },
            },
            "additionalProperties": False,
        },
        "_handler": _tool_list_chapter_packages,
    },
    {
        "name": "get_chapter_package",
        "description": "Get one allowlisted chapter or normative package manifest by stable package ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_id": {
                    "type": "string",
                    "description": "Exact built-in Semantica package ID.",
                }
            },
            "required": ["package_id"],
            "additionalProperties": False,
        },
        "_handler": _tool_get_chapter_package,
    },
    {
        "name": "verify_book_sources",
        "description": "Fail closed if any of the 29 book, guide, TeX, contract, or derived-source bindings has drifted.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "book_root": {
                    "type": "string",
                    "description": "Root of the ontology-engineering checkout containing both books.",
                },
                "volume": {
                    "type": "string",
                    "enum": ["vol1", "vol2"],
                    "description": "Optional book-volume filter.",
                },
            },
            "required": ["book_root"],
            "additionalProperties": False,
        },
        "_handler": _tool_verify_book_sources,
    },
    {
        "name": "run_chapter_package",
        "description": "Execute a built-in package scenario through SemanticPackageRunner and return only public DTO data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_id": {"type": "string"},
                "scenario_id": {"type": "string"},
                "runtime_commit": {"type": "string"},
                "runtime_artifact_sha256": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{64}$",
                },
            },
            "required": [
                "package_id",
                "runtime_commit",
                "runtime_artifact_sha256",
            ],
            "additionalProperties": False,
        },
        "_handler": _tool_run_chapter_package,
    },
    {
        "name": "verify_chapter_package",
        "description": "Execute and release-verify a built-in package through SemanticPackageRunner.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_id": {"type": "string"},
                "scenario_id": {"type": "string"},
                "runtime_commit": {"type": "string"},
                "runtime_artifact_sha256": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{64}$",
                },
            },
            "required": [
                "package_id",
                "runtime_commit",
                "runtime_artifact_sha256",
            ],
            "additionalProperties": False,
        },
        "_handler": _tool_verify_chapter_package,
    },
]

RESOURCES = [
    {
        "uri": "semantica://graph/summary",
        "name": "Graph Summary",
        "description": "High-level statistics about the current knowledge graph",
        "mimeType": "application/json",
    },
    {
        "uri": "semantica://decisions/list",
        "name": "Decisions",
        "description": "List of all recorded decisions in the graph",
        "mimeType": "application/json",
    },
    {
        "uri": "semantica://schema/info",
        "name": "Schema Info",
        "description": "Semantica server info and available capabilities",
        "mimeType": "application/json",
    },
    {
        "uri": "semantica://packages/registry",
        "name": "Built-in Semantic Package Registry",
        "description": "The 29 chapter packages and normative domain package exposed by Semantica.",
        "mimeType": "application/json",
    },
]


def _listed_resources() -> list[dict]:
    """List fixed resources and one manifest URI per allowlisted package."""

    resources = list(RESOURCES)
    try:
        for package in _package_catalog():
            resources.append(
                {
                    "uri": _PACKAGE_RESOURCE_PREFIX + package["package_id"],
                    "name": "Package manifest: {}".format(package["package_id"]),
                    "description": "Source-grounded built-in semantic package manifest.",
                    "mimeType": "application/json",
                }
            )
    except Exception:
        # Discovery errors remain observable through the registry resource/tool;
        # the MCP server itself must still initialize and list its fixed resources.
        log.exception("Could not enumerate built-in package manifest resources")
    return resources


def _read_resource(uri: str) -> dict:
    if uri == "semantica://graph/summary":
        return _tool_get_graph_summary({})
    if uri == "semantica://decisions/list":
        return _tool_query_decisions({"limit": 50})
    if uri == "semantica://schema/info":
        return {
            "name": "Semantica",
            "version": _SEMANTICA_VERSION,
            "tools": [t["name"] for t in TOOLS],
            "resources": [r["uri"] for r in _listed_resources()],
        }
    if uri == "semantica://packages/registry":
        return _tool_list_chapter_packages({})
    if uri.startswith(_PACKAGE_RESOURCE_PREFIX):
        package_id = uri[len(_PACKAGE_RESOURCE_PREFIX):]
        # Resolution compares against exact package IDs.  Slashes, percent
        # escapes, dot segments, and arbitrary filesystem paths never resolve.
        return _tool_get_chapter_package({"package_id": package_id})
    return _package_error("resource_not_found", "Unknown resource URI.")


class MCPToolNotFoundError(LookupError):
    """Raised by the canonical adapter for an unknown MCP tool name."""


class MCPInvalidArgumentsError(ValueError):
    """Raised when an MCP tool call does not carry an argument object."""


def list_mcp_tools() -> list[dict]:
    """Return public tool definitions from the one canonical registry."""

    return [
        {
            "name": tool["name"],
            "description": tool["description"],
            "inputSchema": tool["inputSchema"],
        }
        for tool in TOOLS
    ]


def call_mcp_tool(name: str, arguments: Mapping[str, Any] | None = None) -> dict:
    """Call one canonical tool handler and return its public JSON DTO."""

    handler = next(
        (tool["_handler"] for tool in TOOLS if tool["name"] == name), None
    )
    if handler is None:
        raise MCPToolNotFoundError("Unknown tool: {}".format(name))
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, Mapping):
        raise MCPInvalidArgumentsError("tool arguments must be an object")
    result = handler(dict(arguments))
    if not isinstance(result, dict):
        raise TypeError("MCP tool handlers must return a JSON object")
    return result


def list_mcp_resources() -> list[dict]:
    """Return fixed and allowlisted dynamic resources from one registry."""

    return [dict(resource) for resource in _listed_resources()]


def read_mcp_resource(uri: str) -> dict:
    """Read one canonical MCP resource without accepting filesystem paths."""

    if not isinstance(uri, str):
        return _package_error(
            "invalid_argument", "Resource URI must be a string."
        )
    return _read_resource(uri)


# ══════════════════════════════════════════════════════════════════════════════
# JSON-RPC / MCP protocol handler
# ══════════════════════════════════════════════════════════════════════════════

SERVER_INFO = {
    "name": "semantica",
    "version": _SEMANTICA_VERSION,
}

CAPABILITIES = {
    "tools":     {"listChanged": False},
    "resources": {"listChanged": False, "subscribe": False},
}


def _handle(req: dict) -> dict | None:
    """Dispatch a single JSON-RPC request; return None for notifications."""
    method = req.get("method", "")
    params = req.get("params") or {}
    req_id = req.get("id")

    def ok(result):
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def err(code, message):
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    # Notifications (no id) — acknowledge silently
    if req_id is None and method.startswith("notifications/"):
        return None

    if method == "initialize":
        return ok({
            "protocolVersion": "2024-11-05",
            "capabilities": CAPABILITIES,
            "serverInfo": SERVER_INFO,
        })

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return ok({})

    if method == "tools/list":
        return ok({"tools": list_mcp_tools()})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        try:
            result = call_mcp_tool(name, arguments)
            text = json.dumps(
                result, ensure_ascii=False, indent=2, sort_keys=True
            )
            payload = {"content": [{"type": "text", "text": text}]}
            if isinstance(result, dict) and (
                result.get("ok") is False or "error" in result
            ):
                payload["isError"] = True
            return ok(payload)
        except MCPToolNotFoundError:
            return err(-32601, f"Unknown tool: {name}")
        except MCPInvalidArgumentsError:
            return err(-32602, "Tool arguments must be an object")
        except Exception as exc:
            log.exception("Tool %s raised", name)
            return err(
                -32603,
                "Tool {!r} failed ({}). See server logs for details.".format(
                    name, type(exc).__name__
                ),
            )

    if method == "resources/list":
        return ok({"resources": list_mcp_resources()})

    if method == "resources/read":
        uri = params.get("uri", "")
        data = read_mcp_resource(uri)
        text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
        return ok({"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]})

    if method == "prompts/list":
        return ok({"prompts": []})

    return err(-32601, f"Method not found: {method}")


def handle_mcp_request(request: dict) -> dict | None:
    """Public canonical JSON-RPC adapter used by every Semantica MCP entry."""

    return _handle(request)


# ══════════════════════════════════════════════════════════════════════════════
# stdio event loop
# ══════════════════════════════════════════════════════════════════════════════

def _run_stdio():
    log.info("Semantica MCP server starting on stdio")
    # Use binary stdin/stdout for reliable newline handling on Windows
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        try:
            line = stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as exc:
                resp = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {exc}"}}
                stdout.write(json.dumps(resp).encode() + b"\n")
                stdout.flush()
                continue

            resp = _handle(req)
            if resp is not None:
                stdout.write(json.dumps(resp, ensure_ascii=False).encode() + b"\n")
                stdout.flush()
        except EOFError:
            break
        except KeyboardInterrupt:
            break
        except Exception as exc:
            log.exception("Unhandled error in MCP loop: %s", exc)

    log.info("Semantica MCP server stopped")


def main():
    _run_stdio()
