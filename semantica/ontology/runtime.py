"""Stable, lossless semantic runtime for ontology workloads.

``SemanticRuntime`` is the application-facing boundary for RDF datasets,
SPARQL, SHACL, and bounded positive forward rules.  Backend objects from
:mod:`rdflib`, :mod:`pyshacl`, or Semantica's internal reasoner never cross
this module's public API; callers receive small immutable DTOs instead.

The first implementation deliberately uses an in-process ``rdflib.Dataset``
for predictable offline behaviour.  The public contract is backend-neutral so
that a future PyOxigraph implementation can be introduced without changing
callers or result shapes.
"""

from __future__ import annotations

import importlib.util
import hashlib
import json
import math
import os
import re
import warnings
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from importlib import metadata as importlib_metadata
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from urllib.parse import urlsplit

from rdflib import BNode, ConjunctiveGraph, Dataset, Graph, Literal, Namespace, URIRef
from rdflib.namespace import RDF
from rdflib.term import Identifier, Node

from ..utils.exceptions import SemanticaError
from .lifecycle import (
    DatasetDiffDTO,
    DatasetSnapshotDTO,
    ExecutionReportDTO,
    PackageExecutionReceiptDTO,
    ProvenanceBundleDTO,
    ReleaseCheckDTO,
    ReleaseVerdictDTO,
    build_execution_receipt,
    build_provenance_bundle,
    diff_snapshots,
    execution_report,
    is_sha256,
    missing_execution_report,
    receipt_bindings,
    snapshot_dataset,
    utc_now,
)

# ---------------------------------------------------------------------------
# Public errors


class SemanticRuntimeError(SemanticaError):
    """Base error for the stable semantic runtime boundary."""


class UnsupportedProfileError(SemanticRuntimeError):
    """Raised when a runtime profile is unknown."""


class UnsupportedBackendError(SemanticRuntimeError):
    """Raised when a requested runtime backend is not implemented."""


class UnsupportedCapabilityError(SemanticRuntimeError):
    """Raised when a capability name is unknown."""


class CapabilityUnavailableError(SemanticRuntimeError):
    """Raised when a known capability is unavailable in the active profile."""


class SemanticInputError(SemanticRuntimeError):
    """Raised when RDF, SPARQL, or SHACL input is invalid or ambiguous."""


class UnsupportedQueryTypeError(SemanticRuntimeError):
    """Raised when a query is not SELECT, ASK, or CONSTRUCT."""


class LossySerializationError(SemanticRuntimeError):
    """Raised when a requested serialization would discard dataset contexts."""


# ---------------------------------------------------------------------------
# Stable DTOs


@dataclass(frozen=True)
class RDFTermDTO:
    """Backend-neutral representation of one RDF term."""

    value: str
    term_type: str
    datatype: Optional[str] = None
    language: Optional[str] = None

    def __post_init__(self) -> None:
        if self.term_type not in {"iri", "blank_node", "literal"}:
            raise ValueError("term_type must be 'iri', 'blank_node', or 'literal'")
        if self.term_type != "literal" and (self.datatype or self.language):
            raise ValueError("only literal terms may have datatype or language")
        if self.datatype and self.language:
            raise ValueError("an RDF literal cannot have both datatype and language")

    def __str__(self) -> str:
        return self.value

    @classmethod
    def iri(cls, value: str) -> "RDFTermDTO":
        return cls(value=str(value), term_type="iri")

    @classmethod
    def blank_node(cls, value: str) -> "RDFTermDTO":
        return cls(value=str(value), term_type="blank_node")

    @classmethod
    def literal(
        cls,
        value: Any,
        *,
        datatype: Optional[str] = None,
        language: Optional[str] = None,
    ) -> "RDFTermDTO":
        return cls(
            value=str(value),
            term_type="literal",
            datatype=str(datatype) if datatype is not None else None,
            language=str(language) if language is not None else None,
        )

    def as_dict(self) -> Dict[str, Optional[str]]:
        return {
            "value": self.value,
            "term_type": self.term_type,
            "datatype": self.datatype,
            "language": self.language,
        }


@dataclass(frozen=True)
class QueryRowDTO(Mapping[str, RDFTermDTO]):
    """Immutable mapping from SPARQL variable names to RDF terms."""

    values: Tuple[Tuple[str, RDFTermDTO], ...]

    def __getitem__(self, key: str) -> RDFTermDTO:
        for name, value in self.values:
            if name == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (name for name, _ in self.values)

    def __len__(self) -> int:
        return len(self.values)

    def as_dict(self) -> Dict[str, RDFTermDTO]:
        return dict(self.values)


@dataclass(frozen=True)
class RDFTripleDTO:
    """Backend-neutral RDF triple used by CONSTRUCT results."""

    subject: RDFTermDTO
    predicate: RDFTermDTO
    object: RDFTermDTO

    def __post_init__(self) -> None:
        if self.subject.term_type == "literal":
            raise ValueError("an RDF triple subject cannot be a literal")
        if self.predicate.term_type != "iri":
            raise ValueError("an RDF triple predicate must be an IRI")


@dataclass(frozen=True)
class SelectResultDTO:
    """Stable SELECT result."""

    variables: Tuple[str, ...]
    rows: Tuple[QueryRowDTO, ...]
    revision: int
    cache_hit: bool = False
    query_type: str = "SELECT"

    @property
    def bindings(self) -> Tuple[QueryRowDTO, ...]:
        """Compatibility alias for callers accustomed to ``bindings``."""

        return self.rows


@dataclass(frozen=True)
class AskResultDTO:
    """Stable ASK result with an explicit boolean field."""

    boolean: bool
    revision: int
    cache_hit: bool = False
    query_type: str = "ASK"


@dataclass(frozen=True)
class ConstructResultDTO:
    """Stable CONSTRUCT result that can be serialized or loaded again."""

    triples: Tuple[RDFTripleDTO, ...]
    revision: int
    cache_hit: bool = False
    query_type: str = "CONSTRUCT"

    def serialize(self, format: str = "turtle", base_uri: Optional[str] = None) -> str:
        graph = Graph()
        for triple in self.triples:
            graph.add(
                (
                    _dto_to_term(triple.subject),
                    _dto_to_term(triple.predicate),
                    _dto_to_term(triple.object),
                )
            )
        normalized = _normalize_rdf_format(format)
        if normalized in _DATASET_FORMATS:
            raise LossySerializationError(
                "CONSTRUCT returns one RDF graph; use a graph format such as "
                "'turtle', 'nt', 'xml', or 'json-ld'"
            )
        serialized = graph.serialize(format=normalized, base=base_uri)
        return _ensure_text(serialized)


QueryResultDTO = Union[SelectResultDTO, AskResultDTO, ConstructResultDTO]


@dataclass(frozen=True)
class MutationResultDTO:
    """Result of loading RDF or clearing the dataset."""

    operation: str
    added: int
    removed: int
    quad_count: int
    revision: int


@dataclass(frozen=True)
class UpdateResultDTO:
    """Result of a SPARQL UPDATE operation."""

    added: int
    removed: int
    quad_count: int
    revision: int


@dataclass(frozen=True)
class ValidationViolationDTO:
    """Normalized SHACL validation result."""

    focus: str
    path: Optional[str]
    source_constraint: str
    severity: str
    message: str

    @property
    def focus_node(self) -> str:
        return self.focus

    @property
    def result_path(self) -> Optional[str]:
        return self.path


@dataclass(frozen=True)
class ValidationReportDTO:
    """Stable, backend-neutral SHACL report."""

    conforms: bool
    text: str
    violations: Tuple[ValidationViolationDTO, ...]
    inference: str
    advanced: bool
    abort_on_first: bool
    revision: int

    @property
    def violation_count(self) -> int:
        return len(self.violations)


@dataclass(frozen=True)
class CapabilityProfileDTO:
    """Resolved runtime profile and the exact capabilities it enables."""

    name: str
    backend: str
    capabilities: Tuple[str, ...]
    versions: Tuple[Tuple[str, str], ...]
    fail_closed: bool = True

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "backend": self.backend,
            "capabilities": list(self.capabilities),
            "versions": dict(self.versions),
            "fail_closed": self.fail_closed,
        }


@dataclass(frozen=True)
class SemanticPackageIdentityDTO:
    """Content-bound identity for a built-in chapter or domain package."""

    package_id: str
    version: str
    namespace: Optional[str]
    digest: str
    schema_version: str = "1.0"


@dataclass(frozen=True)
class SemanticPackageAssetDTO:
    """Losslessly retained package asset and its declared semantic role."""

    asset_id: str
    role: str
    content: bytes
    sha256: str
    format: Optional[str] = None
    graph_name: Optional[str] = None
    loaded_into_dataset: bool = False

    def text(self, encoding: str = "utf-8") -> str:
        return self.content.decode(encoding)


@dataclass(frozen=True)
class PackageLoadResultDTO:
    """Result of loading and registering one content-bound semantic package."""

    identity: SemanticPackageIdentityDTO
    assets: Tuple[SemanticPackageAssetDTO, ...]
    rdf_added: int
    revision: int


@dataclass(frozen=True)
class ForwardRuleDTO:
    """One deterministic rule in Semantica's bounded text-rule language.

    ``text`` must use ``IF <atom> [AND <atom> ...] THEN <atom>``.  This DTO
    deliberately does not model SWRL, description-logic entailment, negation,
    arithmetic built-ins, or callable rule handlers.
    """

    rule_id: str
    text: str
    confidence: float = 1.0
    priority: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id.strip():
            raise ValueError("rule_id must be a non-empty string")
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("rule text must be a non-empty string")
        if not isinstance(self.confidence, (int, float)) or isinstance(
            self.confidence, bool
        ):
            raise ValueError("rule confidence must be a finite number from 0 to 1")
        confidence = float(self.confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("rule confidence must be a finite number from 0 to 1")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise ValueError("rule priority must be an integer")


@dataclass(frozen=True)
class ForwardInferenceDTO:
    """Backend-neutral evidence for one forward-chain conclusion."""

    conclusion: str
    rule_id: str
    rule_text: str
    premises: Tuple[str, ...]
    confidence: float
    explanation: str


@dataclass(frozen=True)
class ForwardChainResultDTO:
    """Complete deterministic closure for one stateless reasoning call."""

    input_facts: Tuple[str, ...]
    rules: Tuple[ForwardRuleDTO, ...]
    inferences: Tuple[ForwardInferenceDTO, ...]
    all_facts: Tuple[str, ...]
    max_iterations: int
    semantics: str = "semantica.textual-forward-chain.v1"
    complete: bool = True

    @property
    def conclusions(self) -> Tuple[str, ...]:
        return tuple(item.conclusion for item in self.inferences)


# ---------------------------------------------------------------------------
# Runtime implementation


CAP_RDF_LOAD = "rdf.dataset.load"
CAP_RDF_SERIALIZE = "rdf.dataset.serialize"
CAP_SPARQL_SELECT = "sparql.select"
CAP_SPARQL_ASK = "sparql.ask"
CAP_SPARQL_CONSTRUCT = "sparql.construct"
CAP_SPARQL_UPDATE = "sparql.update"
CAP_SHACL_VALIDATE = "shacl.validate"
CAP_CACHE_REVISION = "cache.revision"
CAP_PACKAGE_LOAD = "semantic.package.load"
CAP_DATASET_SNAPSHOT = "rdf.dataset.snapshot"
CAP_DATASET_DIFF = "rdf.dataset.diff"
CAP_EXECUTION_RECEIPT = "semantic.package.receipt"
CAP_PROVENANCE_BUNDLE = "provenance.bundle"
CAP_RELEASE_VERIFY = "semantic.release.verify"
CAP_RULE_FORWARD_CHAIN = "rule.forward_chain"

_RDF_CAPABILITIES = (
    CAP_RDF_LOAD,
    CAP_RDF_SERIALIZE,
    CAP_SPARQL_SELECT,
    CAP_SPARQL_ASK,
    CAP_SPARQL_CONSTRUCT,
    CAP_SPARQL_UPDATE,
    CAP_CACHE_REVISION,
    CAP_PACKAGE_LOAD,
    CAP_DATASET_SNAPSHOT,
    CAP_DATASET_DIFF,
    CAP_EXECUTION_RECEIPT,
    CAP_PROVENANCE_BUNDLE,
    CAP_RELEASE_VERIFY,
)
_FULL_CAPABILITIES = _RDF_CAPABILITIES + (
    CAP_SHACL_VALIDATE,
    CAP_RULE_FORWARD_CHAIN,
)
_KNOWN_CAPABILITIES = frozenset(_FULL_CAPABILITIES)
_PROFILES = {
    "rdf": _RDF_CAPABILITIES,
    "ontology-runtime": _FULL_CAPABILITIES,
    "ontology-engineering": _FULL_CAPABILITIES,
}

_FORMAT_ALIASES = {
    "ttl": "turtle",
    "turtle": "turtle",
    "nt": "nt",
    "ntriples": "nt",
    "n-triples": "nt",
    "rdfxml": "xml",
    "rdf/xml": "xml",
    "xml": "xml",
    "jsonld": "json-ld",
    "json_ld": "json-ld",
    "json-ld": "json-ld",
    "trig": "trig",
    "nq": "nquads",
    "n-quads": "nquads",
    "nquads": "nquads",
    "trix": "trix",
}
_DATASET_FORMATS = frozenset({"trig", "nquads", "trix"})
_INFERENCE_OPTIONS = frozenset({"none", "rdfs", "owlrl", "both"})
_PATH_FORMATS = {
    ".ttl": "turtle",
    ".nt": "nt",
    ".rdf": "xml",
    ".owl": "xml",
    ".xml": "xml",
    ".jsonld": "json-ld",
    ".trig": "trig",
    ".nq": "nquads",
    ".trix": "trix",
}


class SemanticRuntime:
    """Lossless RDF/SPARQL/SHACL and bounded forward-rule runtime.

    Args:
        profile: One of ``"ontology-runtime"`` (default),
            ``"ontology-engineering"``, or ``"rdf"``.  Unknown names fail
            closed instead of silently selecting a smaller profile.
        backend: ``"rdflib"`` is the only backend implemented in this
            release.  Other names fail closed; no backend fallback occurs.
        required_capabilities: Optional explicit capability contract.  Every
            name must be known and enabled by the selected profile.
        cache_queries: Cache immutable SELECT/ASK/CONSTRUCT DTOs.  Every
            successful mutation increments ``revision`` and clears the cache.
    """

    def __init__(
        self,
        *,
        profile: str = "ontology-runtime",
        backend: str = "rdflib",
        required_capabilities: Optional[Iterable[str]] = None,
        cache_queries: bool = True,
    ) -> None:
        if backend != "rdflib":
            raise UnsupportedBackendError(
                "Unsupported semantic runtime backend: {!r}. This release "
                "implements only 'rdflib'; no fallback was attempted.".format(backend)
            )
        if profile not in _PROFILES:
            raise UnsupportedProfileError(
                (
                    "Unsupported semantic runtime profile: {!r}. Supported profiles: {}"
                ).format(profile, ", ".join(sorted(_PROFILES)))
            )

        enabled = tuple(_PROFILES[profile])
        requested = tuple(required_capabilities or ())
        for capability in requested:
            if capability not in _KNOWN_CAPABILITIES:
                raise UnsupportedCapabilityError(
                    "Unknown semantic runtime capability: {!r}".format(capability)
                )
            if capability not in enabled:
                raise CapabilityUnavailableError(
                    "Capability {!r} is not enabled by profile {!r}".format(
                        capability, profile
                    )
                )

        if CAP_SHACL_VALIDATE in enabled and not _module_available("pyshacl"):
            raise CapabilityUnavailableError(
                "Profile {!r} requires SHACL validation, but pyshacl is not "
                "installed. Install semantica[ontology-runtime].".format(profile)
            )

        self._dataset = Dataset()
        self._lock = RLock()
        self._cache_queries = bool(cache_queries)
        self._query_cache: Dict[Tuple[Any, ...], QueryResultDTO] = {}
        # Pure-data canonical snapshots are expensive for large ontology
        # packages.  Cache only the immutable DTO for the current revision;
        # backend graphs/iterators never enter the public or cached surface.
        self._snapshot_cache: Optional[DatasetSnapshotDTO] = None
        self._packages: Dict[
            Tuple[str, str],
            Tuple[SemanticPackageIdentityDTO, Tuple[SemanticPackageAssetDTO, ...]],
        ] = {}
        self._revision = 0
        self._profile = CapabilityProfileDTO(
            name=profile,
            backend="rdflib",
            capabilities=enabled,
            versions=_runtime_versions(),
        )

    @property
    def profile(self) -> CapabilityProfileDTO:
        return self._profile

    @property
    def capabilities(self) -> Tuple[str, ...]:
        return self._profile.capabilities

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def quad_count(self) -> int:
        with self._lock:
            return self._quad_count()

    def supports(self, capability: str) -> bool:
        if capability not in _KNOWN_CAPABILITIES:
            raise UnsupportedCapabilityError(
                "Unknown semantic runtime capability: {!r}".format(capability)
            )
        return self._profile.supports(capability)

    def require(self, capability: str) -> None:
        if capability not in _KNOWN_CAPABILITIES:
            raise UnsupportedCapabilityError(
                "Unknown semantic runtime capability: {!r}".format(capability)
            )
        if not self._profile.supports(capability):
            raise CapabilityUnavailableError(
                "Capability {!r} is unavailable in profile {!r}".format(
                    capability, self._profile.name
                )
            )

    @property
    def packages(self) -> Tuple[SemanticPackageIdentityDTO, ...]:
        """Registered semantic package identities in deterministic order."""

        with self._lock:
            return tuple(
                value[0]
                for _, value in sorted(self._packages.items(), key=lambda item: item[0])
            )

    # ------------------------------------------------------------------ RDF IO

    def load(
        self,
        source: Union[str, bytes, os.PathLike, ConstructResultDTO],
        *,
        format: Optional[str] = None,
        base_uri: Optional[str] = None,
        graph_name: Optional[str] = None,
    ) -> MutationResultDTO:
        """Load RDF from a path, text/bytes payload, or CONSTRUCT result.

        Dataset syntaxes (TriG, N-Quads, TriX) preserve named graphs and may
        not be combined with ``graph_name``.  Triple syntaxes load into the
        default graph unless a named graph IRI is supplied.
        """

        self.require(CAP_RDF_LOAD)
        if graph_name is not None:
            _validate_graph_name(graph_name)

        if isinstance(source, ConstructResultDTO):
            if format is not None:
                raise SemanticInputError(
                    "format is not accepted when loading a ConstructResultDTO"
                )
            triples = [
                (
                    _dto_to_term(item.subject),
                    _dto_to_term(item.predicate),
                    _dto_to_term(item.object),
                )
                for item in source.triples
            ]
            with self._lock:
                before = self._quad_count()
                target = self._target_graph(graph_name)
                for triple in triples:
                    target.add(triple)
                after = self._quad_count()
                revision = self._record_mutation()
                return MutationResultDTO(
                    operation="load",
                    added=max(0, after - before),
                    removed=0,
                    quad_count=after,
                    revision=revision,
                )

        payload, inferred_format = _read_source(source)
        normalized = _normalize_rdf_format(format or inferred_format or "turtle")
        if graph_name is not None and normalized in _DATASET_FORMATS:
            raise SemanticInputError(
                "graph_name cannot be combined with a dataset syntax; the "
                "payload already defines its graph contexts"
            )

        # Parse away from live state so malformed RDF cannot partially mutate it.
        parsed_quads: List[Tuple[Node, Node, Node, Optional[Identifier]]] = []
        try:
            if normalized in _DATASET_FORMATS:
                staged = Dataset()
                staged.parse(data=payload, format=normalized, publicID=base_uri)
                default_id = _default_graph(staged).identifier
                for subject, predicate, obj, context in staged.quads(
                    (None, None, None, None)
                ):
                    parsed_quads.append(
                        (
                            subject,
                            predicate,
                            obj,
                            None if context == default_id else context,
                        )
                    )
            else:
                staged_graph = Graph()
                staged_graph.parse(data=payload, format=normalized, publicID=base_uri)
                context = URIRef(graph_name) if graph_name is not None else None
                parsed_quads.extend(
                    (subject, predicate, obj, context)
                    for subject, predicate, obj in staged_graph
                )
        except Exception as exc:
            raise SemanticInputError(
                "Failed to parse RDF as {}: {}".format(normalized, exc)
            ) from exc

        with self._lock:
            before = self._quad_count()
            for subject, predicate, obj, context in parsed_quads:
                if context is None:
                    _default_graph(self._dataset).add((subject, predicate, obj))
                else:
                    self._dataset.graph(context).add((subject, predicate, obj))
            after = self._quad_count()
            revision = self._record_mutation()
            return MutationResultDTO(
                operation="load",
                added=max(0, after - before),
                removed=0,
                quad_count=after,
                revision=revision,
            )

    def load_rdf(
        self,
        source: Union[str, bytes, os.PathLike, ConstructResultDTO],
        *,
        format: Optional[str] = None,
        base_uri: Optional[str] = None,
        graph_name: Optional[str] = None,
    ) -> MutationResultDTO:
        """Explicit alias for :meth:`load`."""

        return self.load(
            source,
            format=format,
            base_uri=base_uri,
            graph_name=graph_name,
        )

    def serialize(
        self,
        *,
        format: str = "trig",
        base_uri: Optional[str] = None,
        graph_name: Optional[str] = None,
    ) -> str:
        """Serialize the dataset without silently discarding graph names."""

        self.require(CAP_RDF_SERIALIZE)
        normalized = _normalize_rdf_format(format)
        if graph_name is not None:
            _validate_graph_name(graph_name)
            if normalized in _DATASET_FORMATS:
                raise SemanticInputError(
                    "a selected graph must use a graph syntax, not {}".format(
                        normalized
                    )
                )
            with self._lock:
                serialized = self._dataset.graph(URIRef(graph_name)).serialize(
                    format=normalized, base=base_uri
                )
            return _ensure_text(serialized)

        with self._lock:
            if normalized not in _DATASET_FORMATS and self._named_graph_ids():
                raise LossySerializationError(
                    "Dataset contains named graphs; serializing the whole dataset "
                    "as {!r} would lose graph names. Use 'trig' or 'nquads', or "
                    "select graph_name explicitly.".format(normalized)
                )
            target: Union[Dataset, Graph]
            if normalized in _DATASET_FORMATS:
                target = self._dataset
            else:
                target = _default_graph(self._dataset)
            serialized = target.serialize(format=normalized, base=base_uri)
        return _ensure_text(serialized)

    def clear(self, graph_name: Optional[str] = None) -> MutationResultDTO:
        """Clear the whole dataset or one named graph and invalidate caches."""

        self.require(CAP_RDF_LOAD)
        if graph_name is not None:
            _validate_graph_name(graph_name)
        with self._lock:
            before = self._quad_count()
            if graph_name is None:
                for graph in list(_dataset_graphs(self._dataset)):
                    graph.remove((None, None, None))
            else:
                self._dataset.graph(URIRef(graph_name)).remove((None, None, None))
            after = self._quad_count()
            revision = self._record_mutation()
            return MutationResultDTO(
                operation="clear",
                added=0,
                removed=max(0, before - after),
                quad_count=after,
                revision=revision,
            )

    # ---------------------------------------------------------- Package loading

    def load_package(
        self,
        package: Union[Mapping[str, Any], os.PathLike, str],
        *,
        base_path: Optional[os.PathLike] = None,
    ) -> PackageLoadResultDTO:
        """Load a content-bound chapter/domain package.

        The stage-1 manifest contract is intentionally small and registry-ready::

            {
              "schema_version": "1.0",
              "package_id": "semantica.chapter.vol1.ch04",
              "version": "1.0.0",
              "namespace": "https://example.org/ch04#",
              "assets": [
                {"asset_id": "ontology", "role": "ontology",
                 "path": "ontology.trig", "format": "trig",
                 "load_into_dataset": true},
                {"asset_id": "cq-01", "role": "sparql",
                 "path": "cq01.rq"}
              ]
            }

        Every asset is retained byte-for-byte and content-hashed.  RDF assets
        explicitly marked ``load_into_dataset`` (or roles ``ontology``,
        ``data``, ``instances``, ``rdf``) are staged atomically before the live
        dataset is mutated.  Other assets such as CQ, SHACL, rules, and chapter
        contracts are registered losslessly for the next package-registry layer.
        """

        self.require(CAP_PACKAGE_LOAD)
        manifest, root = _read_package_manifest(package, base_path=base_path)
        schema_version = str(manifest.get("schema_version", ""))
        if schema_version != "1.0":
            raise SemanticInputError(
                (
                    "Unsupported semantic package schema_version {!r}; expected '1.0'"
                ).format(schema_version)
            )
        package_id = _required_manifest_text(manifest, "package_id")
        version = _required_manifest_text(manifest, "version")
        namespace_value = manifest.get("namespace")
        namespace = str(namespace_value) if namespace_value is not None else None
        raw_assets = manifest.get("assets")
        if not isinstance(raw_assets, list) or not raw_assets:
            raise SemanticInputError(
                "semantic package manifest requires a non-empty assets list"
            )

        assets: List[SemanticPackageAssetDTO] = []
        seen_asset_ids = set()
        for raw_asset in raw_assets:
            if not isinstance(raw_asset, Mapping):
                raise SemanticInputError(
                    "each semantic package asset must be a mapping"
                )
            asset_id = _required_manifest_text(raw_asset, "asset_id")
            if asset_id in seen_asset_ids:
                raise SemanticInputError(
                    "duplicate semantic package asset_id: {!r}".format(asset_id)
                )
            seen_asset_ids.add(asset_id)
            role = _required_manifest_text(raw_asset, "role")
            content, inferred_format = _read_package_asset(raw_asset, root)
            digest = hashlib.sha256(content).hexdigest()
            declared_digest = raw_asset.get("sha256")
            if declared_digest is not None and str(declared_digest).lower() != digest:
                raise SemanticInputError(
                    "semantic package asset {!r} sha256 mismatch".format(asset_id)
                )
            format_value = raw_asset.get("format") or inferred_format
            normalized_format = (
                _normalize_rdf_format(str(format_value))
                if format_value is not None and _asset_is_rdf(raw_asset, role)
                else (str(format_value) if format_value is not None else None)
            )
            graph_value = raw_asset.get("graph_name")
            graph_name = str(graph_value) if graph_value is not None else None
            should_load = bool(
                raw_asset.get(
                    "load_into_dataset",
                    role.lower() in {"ontology", "data", "instances", "rdf"},
                )
            )
            if should_load and not _asset_is_rdf(raw_asset, role):
                raise SemanticInputError(
                    (
                        "asset {!r} requests dataset loading but is not declared as RDF"
                    ).format(asset_id)
                )
            assets.append(
                SemanticPackageAssetDTO(
                    asset_id=asset_id,
                    role=role,
                    content=content,
                    sha256=digest,
                    format=normalized_format,
                    graph_name=graph_name,
                    loaded_into_dataset=should_load,
                )
            )

        canonical = {
            "schema_version": schema_version,
            "package_id": package_id,
            "version": version,
            "namespace": namespace,
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "role": asset.role,
                    "sha256": asset.sha256,
                    "format": asset.format,
                    "graph_name": asset.graph_name,
                    "loaded_into_dataset": asset.loaded_into_dataset,
                }
                for asset in sorted(assets, key=lambda item: item.asset_id)
            ],
        }
        package_digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        declared_package_digest = manifest.get("digest")
        if (
            declared_package_digest is not None
            and str(declared_package_digest).lower() != package_digest
        ):
            raise SemanticInputError("semantic package digest mismatch")
        identity = SemanticPackageIdentityDTO(
            package_id=package_id,
            version=version,
            namespace=namespace,
            digest=package_digest,
            schema_version=schema_version,
        )

        key = (package_id, version)
        with self._lock:
            existing = self._packages.get(key)
            if existing is not None:
                if existing[0].digest != package_digest:
                    raise SemanticInputError(
                        "semantic package {}@{} is already registered with a "
                        "different digest".format(package_id, version)
                    )
                return PackageLoadResultDTO(
                    identity=existing[0],
                    assets=existing[1],
                    rdf_added=0,
                    revision=self._revision,
                )

        # Parse all RDF assets in a detached runtime first.  A bad final asset
        # therefore cannot leave the live dataset partially updated.
        staged = SemanticRuntime(profile="rdf", backend="rdflib", cache_queries=False)
        for asset in assets:
            if asset.loaded_into_dataset:
                staged.load(
                    asset.content,
                    format=asset.format,
                    base_uri=namespace,
                    graph_name=asset.graph_name,
                )

        before = self.quad_count
        if staged.quad_count:
            self.load(staged.serialize(format="trig"), format="trig")
        after = self.quad_count
        assets_tuple = tuple(sorted(assets, key=lambda item: item.asset_id))
        with self._lock:
            self._packages[key] = (identity, assets_tuple)
        return PackageLoadResultDTO(
            identity=identity,
            assets=assets_tuple,
            rdf_added=max(0, after - before),
            revision=self._revision,
        )

    def package_identity(
        self, package_id: str, version: str
    ) -> SemanticPackageIdentityDTO:
        """Resolve one exact package identity; absence is fail-closed."""

        key = (str(package_id), str(version))
        with self._lock:
            value = self._packages.get(key)
        if value is None:
            raise SemanticInputError(
                "semantic package is not registered: {}@{}".format(*key)
            )
        return value[0]

    def package_asset(
        self, package_id: str, version: str, asset_id: str
    ) -> SemanticPackageAssetDTO:
        """Return the exact retained bytes and metadata for one package asset."""

        key = (str(package_id), str(version))
        with self._lock:
            value = self._packages.get(key)
        if value is None:
            raise SemanticInputError(
                "semantic package is not registered: {}@{}".format(*key)
            )
        for asset in value[1]:
            if asset.asset_id == asset_id:
                return asset
        raise SemanticInputError(
            "semantic package asset is not registered: {}@{}:{}".format(
                package_id, version, asset_id
            )
        )

    # ------------------------------------------------------ Lifecycle evidence

    def snapshot(self, *, created_at: Optional[str] = None) -> DatasetSnapshotDTO:
        """Capture a canonical, content-addressed RDF Dataset snapshot.

        Blank-node identifiers are canonicalized across the complete dataset,
        including named-graph context.  The semantic hash therefore remains
        stable across parse order, backend-assigned blank-node labels, and RDF
        serialization order.
        """

        self.require(CAP_DATASET_SNAPSHOT)
        when = created_at or utc_now()
        with self._lock:
            cached = self._snapshot_cache
            if cached is not None and cached.revision == self._revision:
                # ``created_at`` is observation metadata, not part of the
                # canonical dataset identity.  Rebind it per call while
                # retaining byte-identical semantic content.
                return replace(cached, created_at=when)
            default_identifier = _default_graph(self._dataset).identifier
            snapshot = snapshot_dataset(
                self._dataset.quads((None, None, None, None)),
                default_graph_identifier=default_identifier,
                revision=self._revision,
                created_at=when,
            )
            self._snapshot_cache = snapshot
            return snapshot

    def diff(
        self,
        before: DatasetSnapshotDTO,
        after: Optional[DatasetSnapshotDTO] = None,
        *,
        created_at: Optional[str] = None,
    ) -> DatasetDiffDTO:
        """Diff two snapshots, or one snapshot against the live dataset."""

        self.require(CAP_DATASET_DIFF)
        if not isinstance(before, DatasetSnapshotDTO):
            raise SemanticInputError("before must be a DatasetSnapshotDTO")
        if after is None:
            after = self.snapshot(created_at=created_at)
        if not isinstance(after, DatasetSnapshotDTO):
            raise SemanticInputError("after must be a DatasetSnapshotDTO")
        try:
            return diff_snapshots(before, after, created_at=created_at)
        except ValueError as exc:
            raise SemanticInputError(str(exc)) from exc

    def execution_report(
        self,
        kind: str,
        payload: Any,
        *,
        status: str,
    ) -> ExecutionReportDTO:
        """Create one immutable, content-bound lifecycle report."""

        self.require(CAP_EXECUTION_RECEIPT)
        try:
            return execution_report(kind, payload, status=status)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SemanticInputError(
                "invalid execution report: {}".format(exc)
            ) from exc

    def record_provenance(
        self,
        bindings: Mapping[str, Any],
        *,
        generated_at: Optional[str] = None,
    ) -> ProvenanceBundleDTO:
        """Create a deterministic, storage-free PROV bundle.

        Package receipts call this lifecycle primitive internally.  It is also
        public for callers that need to bind an intermediate semantic activity
        before a final release receipt is assembled.
        """

        self.require(CAP_PROVENANCE_BUNDLE)
        if not isinstance(bindings, Mapping):
            raise SemanticInputError("provenance bindings must be a mapping")
        try:
            return build_provenance_bundle(bindings, generated_at=generated_at)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SemanticInputError(
                "invalid provenance bindings: {}".format(exc)
            ) from exc

    def create_execution_receipt(
        self,
        package_id: str,
        version: str,
        *,
        runtime_commit: Optional[str] = None,
        runtime_artifact_sha256: Optional[str] = None,
        runtime_version: Optional[str] = None,
        chapter_contract_sha256: Optional[str] = None,
        required_capabilities: Optional[Iterable[str]] = None,
        cq_report: Optional[Any] = None,
        shacl_report: Optional[Any] = None,
        oracle_report: Optional[Any] = None,
        output_hashes: Optional[Mapping[str, str]] = None,
        created_at: Optional[str] = None,
    ) -> PackageExecutionReceiptDTO:
        """Create provenance-bound evidence for one package execution.

        Missing source identity, reports, or chapter-contract evidence are
        retained explicitly as empty/``blocked`` evidence.  Receipt creation
        therefore never manufactures a green result; :meth:`verify_release`
        is the sole fail-closed release decision.
        """

        self.require(CAP_EXECUTION_RECEIPT)
        self.require(CAP_PROVENANCE_BUNDLE)
        identity = self.package_identity(package_id, version)
        with self._lock:
            registered = self._packages[(str(package_id), str(version))][1]
        asset_hashes = {asset.asset_id: asset.sha256 for asset in registered}
        inferred_contract = _chapter_contract_hash(registered)
        contract_digest = (
            str(chapter_contract_sha256)
            if chapter_contract_sha256 is not None
            else (inferred_contract or "")
        )
        resolved_runtime_version = runtime_version
        if resolved_runtime_version is None:
            resolved_runtime_version = dict(self._profile.versions).get("semantica", "")
        when = created_at or utc_now()
        snapshot = self.snapshot(created_at=when)
        capability = self._capability_execution_report(required_capabilities)
        cq = self._coerce_execution_report("cq", cq_report)
        shacl = self._coerce_execution_report("shacl", shacl_report)
        oracle = self._coerce_execution_report("oracle", oracle_report)
        try:
            return build_execution_receipt(
                created_at=when,
                runtime_version=str(resolved_runtime_version or ""),
                runtime_commit=str(runtime_commit or ""),
                runtime_artifact_sha256=str(runtime_artifact_sha256 or ""),
                package_id=identity.package_id,
                package_version=identity.version,
                package_digest=identity.digest,
                asset_hashes=asset_hashes,
                chapter_contract_sha256=contract_digest,
                snapshot=snapshot,
                capability_report=capability,
                cq_report=cq,
                shacl_report=shacl,
                oracle_report=oracle,
                output_hashes=output_hashes,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SemanticInputError(
                "failed to create package execution receipt: {}".format(exc)
            ) from exc

    def verify_release(
        self,
        receipt: PackageExecutionReceiptDTO,
        *,
        checked_at: Optional[str] = None,
    ) -> ReleaseVerdictDTO:
        """Evaluate every release requirement and default to ``blocked``.

        The receipt must match the exact registered package assets and current
        RDF Dataset.  All required reports must be present, intact, and
        ``passed``.  No exception or absent field is treated as success.
        """

        self.require(CAP_RELEASE_VERIFY)
        when = checked_at or utc_now()
        if not isinstance(receipt, PackageExecutionReceiptDTO):
            raise SemanticInputError(
                "verify_release requires a PackageExecutionReceiptDTO"
            )

        checks: List[ReleaseCheckDTO] = []

        def check(check_id: str, passed: bool, message: str) -> None:
            checks.append(
                ReleaseCheckDTO(check_id=check_id, passed=bool(passed), message=message)
            )

        check(
            "receipt.integrity",
            receipt.verify_integrity(),
            "receipt, reports, and provenance hashes must verify",
        )
        check(
            "runtime.version",
            bool(receipt.runtime_version)
            and receipt.runtime_version not in {"unknown", "not-installed"},
            "runtime_version must identify the executing Semantica build",
        )
        check(
            "runtime.commit",
            _is_source_revision(receipt.runtime_commit),
            "runtime_commit must be an injected Git-style source revision",
        )
        check(
            "runtime.artifact_sha256",
            is_sha256(receipt.runtime_artifact_sha256),
            "runtime_artifact_sha256 must bind the installed wheel/artifact",
        )

        key = (receipt.package_id, receipt.package_version)
        with self._lock:
            registered = self._packages.get(key)
        package_matches = (
            registered is not None
            and registered[0].digest == receipt.package_digest
            and is_sha256(receipt.package_digest)
        )
        check(
            "package.identity",
            package_matches,
            "receipt package id, version, and digest must match a registered package",
        )
        expected_assets = (
            tuple(sorted((asset.asset_id, asset.sha256) for asset in registered[1]))
            if registered is not None
            else ()
        )
        assets_match = (
            bool(receipt.asset_hashes)
            and receipt.asset_hashes == expected_assets
            and all(is_sha256(digest) for _, digest in receipt.asset_hashes)
        )
        check(
            "package.asset_hashes",
            assets_match,
            "every registered package asset must be content-bound",
        )
        expected_contract = (
            _chapter_contract_hash(registered[1]) if registered is not None else None
        )
        check(
            "package.chapter_contract_sha256",
            expected_contract is not None
            and receipt.chapter_contract_sha256 == expected_contract
            and is_sha256(receipt.chapter_contract_sha256),
            "exactly one registered chapter contract must match the receipt",
        )

        current_snapshot = self.snapshot(created_at=when)
        check(
            "dataset.integrity",
            is_sha256(receipt.dataset_sha256)
            and receipt.dataset_sha256 == current_snapshot.dataset_sha256
            and receipt.dataset_quad_count == current_snapshot.quad_count
            and receipt.dataset_revision == current_snapshot.revision,
            "receipt dataset must match the current canonical runtime dataset",
        )

        expected_report_kinds = (
            ("capability", receipt.capability_report),
            ("cq", receipt.cq_report),
            ("shacl", receipt.shacl_report),
            ("oracle", receipt.oracle_report),
        )
        for expected_kind, report in expected_report_kinds:
            check(
                "report.{}".format(expected_kind),
                report.kind == expected_kind
                and report.status == "passed"
                and report.verify_integrity(),
                "{} report must be present, intact, and passed".format(expected_kind),
            )

        capability_payload = receipt.capability_report.payload
        capability_matches = (
            isinstance(capability_payload, Mapping)
            and capability_payload.get("profile") == self._profile.as_dict()
            and capability_payload.get("missing") == []
            and capability_payload.get("unknown") == []
        )
        check(
            "report.capability_profile",
            capability_matches,
            "capability report must describe this runtime profile without gaps",
        )
        check(
            "output.hashes",
            all(is_sha256(digest) for _, digest in receipt.output_hashes),
            "every declared output hash must be a SHA-256 digest",
        )
        check(
            "provenance.bundle",
            receipt.provenance_bundle.verify_integrity()
            and receipt.provenance_bundle.bindings == receipt_bindings(receipt),
            "provenance bundle must be intact and bind the exact receipt evidence",
        )

        status = "complete" if all(item.passed for item in checks) else "blocked"
        return ReleaseVerdictDTO(
            status=status,
            receipt_sha256=receipt.receipt_sha256,
            checked_at=when,
            checks=tuple(checks),
        )

    def _capability_execution_report(
        self, required_capabilities: Optional[Iterable[str]]
    ) -> ExecutionReportDTO:
        required = tuple(
            sorted(set(str(item) for item in (required_capabilities or ())))
        )
        unknown = [item for item in required if item not in _KNOWN_CAPABILITIES]
        missing = [
            item
            for item in required
            if item in _KNOWN_CAPABILITIES and item not in self.capabilities
        ]
        status = "passed" if not unknown and not missing else "failed"
        return execution_report(
            "capability",
            {
                "profile": self._profile.as_dict(),
                "required": list(required),
                "unknown": unknown,
                "missing": missing,
            },
            status=status,
        )

    def _coerce_execution_report(
        self, kind: str, value: Optional[Any]
    ) -> ExecutionReportDTO:
        if value is None:
            return missing_execution_report(kind)
        if isinstance(value, ExecutionReportDTO):
            if value.kind != kind:
                raise SemanticInputError(
                    "expected {!r} report, received {!r}".format(kind, value.kind)
                )
            return value
        if isinstance(value, ValidationReportDTO):
            if kind != "shacl":
                raise SemanticInputError(
                    "ValidationReportDTO can only be used as a SHACL report"
                )
            # A non-conforming graph can be the expected single-fault negative
            # oracle.  Here ``passed`` means SHACL execution completed and the
            # normalized result was captured; oracle_report decides whether
            # that result was expected.
            return execution_report(
                kind,
                {
                    "conforms": value.conforms,
                    "violations": [
                        {
                            "focus": item.focus,
                            "path": item.path,
                            "source_constraint": item.source_constraint,
                            "severity": item.severity,
                            "message": item.message,
                        }
                        for item in value.violations
                    ],
                    "inference": value.inference,
                    "advanced": value.advanced,
                    "abort_on_first": value.abort_on_first,
                    "revision": value.revision,
                },
                status="passed",
            )
        if isinstance(value, Mapping):
            raw_status = value.get("status")
            if raw_status is None and isinstance(value.get("passed"), bool):
                raw_status = "passed" if value.get("passed") else "failed"
            status = str(raw_status) if raw_status is not None else "blocked"
            return execution_report(kind, value, status=status)
        as_dict = getattr(value, "as_dict", None)
        if callable(as_dict):
            payload = as_dict()
            raw_status = getattr(value, "status", None)
            status = str(raw_status) if raw_status is not None else "blocked"
            return execution_report(kind, payload, status=status)
        raise SemanticInputError(
            "{} report must be ExecutionReportDTO or JSON-compatible mapping".format(
                kind
            )
        )

    # --------------------------------------------------------------- SPARQL API

    def query(
        self,
        sparql: str,
        *,
        namespaces: Optional[Mapping[str, str]] = None,
        bindings: Optional[Mapping[str, Union[RDFTermDTO, str]]] = None,
        use_cache: bool = True,
    ) -> QueryResultDTO:
        """Execute SELECT, ASK, or CONSTRUCT and return an immutable DTO."""

        if not isinstance(sparql, str) or not sparql.strip():
            raise SemanticInputError("SPARQL query must be a non-empty string")

        namespace_key = tuple(sorted((namespaces or {}).items()))
        binding_key = tuple(
            sorted(
                (name, _binding_cache_value(value))
                for name, value in (bindings or {}).items()
            )
        )
        cache_key = (self._revision, sparql, namespace_key, binding_key)
        with self._lock:
            if self._cache_queries and use_cache and cache_key in self._query_cache:
                return replace(self._query_cache[cache_key], cache_hit=True)

            init_ns = {
                str(prefix): Namespace(str(uri))
                for prefix, uri in (namespaces or {}).items()
            }
            init_bindings = {
                str(name): _binding_to_term(value)
                for name, value in (bindings or {}).items()
            }
            try:
                result = self._dataset.query(
                    sparql, initNs=init_ns, initBindings=init_bindings
                )
            except Exception as exc:
                raise SemanticInputError("SPARQL query failed: {}".format(exc)) from exc

            query_type = str(getattr(result, "type", "")).upper()
            if query_type == "SELECT":
                self.require(CAP_SPARQL_SELECT)
                variables = tuple(str(var) for var in (result.vars or ()))
                rows: List[QueryRowDTO] = []
                for row in result:
                    pairs: List[Tuple[str, RDFTermDTO]] = []
                    for variable in result.vars or ():
                        value = row.get(variable)
                        if value is not None:
                            pairs.append((str(variable), _term_to_dto(value)))
                    rows.append(QueryRowDTO(tuple(pairs)))
                dto: QueryResultDTO = SelectResultDTO(
                    variables=variables,
                    rows=tuple(rows),
                    revision=self._revision,
                )
            elif query_type == "ASK":
                self.require(CAP_SPARQL_ASK)
                dto = AskResultDTO(
                    boolean=bool(getattr(result, "askAnswer", False)),
                    revision=self._revision,
                )
            elif query_type == "CONSTRUCT":
                self.require(CAP_SPARQL_CONSTRUCT)
                graph = result.graph
                triples = tuple(
                    sorted(
                        (
                            RDFTripleDTO(
                                subject=_term_to_dto(subject),
                                predicate=_term_to_dto(predicate),
                                object=_term_to_dto(obj),
                            )
                            for subject, predicate, obj in graph
                        ),
                        key=_triple_sort_key,
                    )
                )
                dto = ConstructResultDTO(
                    triples=triples,
                    revision=self._revision,
                )
            else:
                raise UnsupportedQueryTypeError(
                    "SemanticRuntime.query supports SELECT, ASK, and CONSTRUCT; "
                    "received {!r}. Use update() for SPARQL UPDATE.".format(
                        query_type or "unknown"
                    )
                )

            if self._cache_queries and use_cache:
                self._query_cache[cache_key] = dto
            return dto

    def select(
        self,
        sparql: str,
        *,
        namespaces: Optional[Mapping[str, str]] = None,
        bindings: Optional[Mapping[str, Union[RDFTermDTO, str]]] = None,
        use_cache: bool = True,
    ) -> SelectResultDTO:
        result = self.query(
            sparql,
            namespaces=namespaces,
            bindings=bindings,
            use_cache=use_cache,
        )
        if not isinstance(result, SelectResultDTO):
            raise UnsupportedQueryTypeError(
                "select() requires a SELECT query, received {}".format(
                    result.query_type
                )
            )
        return result

    def ask(
        self,
        sparql: str,
        *,
        namespaces: Optional[Mapping[str, str]] = None,
        bindings: Optional[Mapping[str, Union[RDFTermDTO, str]]] = None,
        use_cache: bool = True,
    ) -> AskResultDTO:
        result = self.query(
            sparql,
            namespaces=namespaces,
            bindings=bindings,
            use_cache=use_cache,
        )
        if not isinstance(result, AskResultDTO):
            raise UnsupportedQueryTypeError(
                "ask() requires an ASK query, received {}".format(result.query_type)
            )
        return result

    def construct(
        self,
        sparql: str,
        *,
        namespaces: Optional[Mapping[str, str]] = None,
        bindings: Optional[Mapping[str, Union[RDFTermDTO, str]]] = None,
        use_cache: bool = True,
    ) -> ConstructResultDTO:
        result = self.query(
            sparql,
            namespaces=namespaces,
            bindings=bindings,
            use_cache=use_cache,
        )
        if not isinstance(result, ConstructResultDTO):
            raise UnsupportedQueryTypeError(
                "construct() requires a CONSTRUCT query, received {}".format(
                    result.query_type
                )
            )
        return result

    def update(
        self,
        sparql: str,
        *,
        namespaces: Optional[Mapping[str, str]] = None,
        bindings: Optional[Mapping[str, Union[RDFTermDTO, str]]] = None,
    ) -> UpdateResultDTO:
        """Execute SPARQL UPDATE and always invalidate cached query results."""

        self.require(CAP_SPARQL_UPDATE)
        if not isinstance(sparql, str) or not sparql.strip():
            raise SemanticInputError("SPARQL update must be a non-empty string")
        init_ns = {
            str(prefix): Namespace(str(uri))
            for prefix, uri in (namespaces or {}).items()
        }
        init_bindings = {
            str(name): _binding_to_term(value)
            for name, value in (bindings or {}).items()
        }
        with self._lock:
            before = self._quad_count()
            try:
                # rdflib Dataset.update() currently routes INSERT DATA through
                # Dataset.__iadd__, which expects quads and rejects ordinary
                # triples.  A ConjunctiveGraph over the exact same store and
                # default-graph identifier provides correct SPARQL Update
                # dataset semantics without copying or exposing the backend.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    update_view = ConjunctiveGraph(
                        store=self._dataset.store,
                        identifier=_default_graph(self._dataset).identifier,
                    )
                update_view.update(sparql, initNs=init_ns, initBindings=init_bindings)
            except Exception as exc:
                # A backend may have partially mutated before reporting an error.
                # Clearing both caches is therefore mandatory even on failure;
                # revision equality alone cannot prove a rolled-back dataset.
                self._query_cache.clear()
                self._snapshot_cache = None
                raise SemanticInputError(
                    "SPARQL update failed: {}".format(exc)
                ) from exc
            after = self._quad_count()
            revision = self._record_mutation()
            return UpdateResultDTO(
                added=max(0, after - before),
                removed=max(0, before - after),
                quad_count=after,
                revision=revision,
            )

    # ------------------------------------------------------ Forward-rule API

    def reason(
        self,
        facts: Union[
            str,
            bytes,
            SemanticPackageAssetDTO,
            Iterable[str],
        ],
        rules: Union[
            str,
            bytes,
            SemanticPackageAssetDTO,
            Iterable[Union[str, ForwardRuleDTO]],
        ],
        *,
        max_iterations: int = 50,
    ) -> ForwardChainResultDTO:
        """Compute a stateless closure with Semantica's text-rule reasoner.

        The supported semantics are deliberately narrow: positive, monotonic
        ``IF ... [AND ...] THEN ...`` forward rules over opaque textual atoms.
        This method is not a SWRL, OWL/DL, negation, arithmetic-built-in, or
        truth-maintenance interface.  A package ``rules`` asset may be passed
        directly when its format is exactly ``semantica-rule``.

        A fresh :class:`~semantica.reasoning.reasoner.Reasoner` and explanation
        generator are created for every call.  The runtime RDF Dataset,
        revision, cache, and package registry are never mutated.  Hitting the
        iteration bound with more facts still derivable raises instead of
        returning an incomplete result.
        """

        self.require(CAP_RULE_FORWARD_CHAIN)
        if (
            not isinstance(max_iterations, int)
            or isinstance(max_iterations, bool)
            or max_iterations < 1
        ):
            raise SemanticInputError("max_iterations must be a positive integer")

        normalized_facts = _normalize_forward_facts(facts)
        normalized_rules = _normalize_forward_rules(rules)
        if not normalized_facts:
            raise SemanticInputError("forward reasoning requires at least one fact")
        if not normalized_rules:
            raise SemanticInputError("forward reasoning requires at least one rule")

        # These imports stay inside the capability method.  Constructing an
        # RDF/SHACL runtime never initializes reasoning or any LLM provider.
        from ..reasoning.explanation_generator import ExplanationGenerator
        from ..reasoning.reasoner import Reasoner, Rule

        reasoner = Reasoner(max_iterations=max_iterations)
        internal_rules: Dict[str, Any] = {}
        for rule_dto in normalized_rules:
            conditions, conclusion = _parse_forward_rule_text(rule_dto.text)
            internal = Rule(
                rule_id=rule_dto.rule_id,
                name=rule_dto.rule_id,
                conditions=list(conditions),
                conclusion=conclusion,
                confidence=float(rule_dto.confidence),
                priority=rule_dto.priority,
            )
            retained = reasoner.add_rule(internal)
            if retained is not internal:
                # Normalization rejects semantic duplicates, so reaching the
                # legacy Reasoner dedup path would be an adapter defect.
                raise SemanticRuntimeError(
                    "forward-rule normalization produced an ambiguous duplicate"
                )
            internal_rules[rule_dto.rule_id] = internal
        for fact in normalized_facts:
            reasoner.add_fact(fact)

        try:
            inferred = reasoner.forward_chain()
            # A second closure attempt is an explicit convergence probe.  Any
            # additional result proves that the first call stopped at the
            # caller's bound and therefore must not be reported as complete.
            if reasoner.forward_chain():
                raise SemanticRuntimeError(
                    "forward reasoning did not converge within max_iterations={}".format(
                        max_iterations
                    )
                )
            explainer = ExplanationGenerator(
                config={"generate_nl": True, "detail_level": "detailed"}
            )
            rule_contract = {item.rule_id: item for item in normalized_rules}
            normalized_inferences: List[ForwardInferenceDTO] = []
            for item in inferred:
                internal_rule = item.rule_used
                if internal_rule is None or internal_rule.rule_id not in internal_rules:
                    raise SemanticRuntimeError(
                        "forward reasoner returned an inference without a registered rule"
                    )
                contract = rule_contract[internal_rule.rule_id]
                explanation = explainer.generate_explanation(item)
                normalized_inferences.append(
                    ForwardInferenceDTO(
                        conclusion=str(item.conclusion),
                        rule_id=contract.rule_id,
                        rule_text=contract.text,
                        premises=tuple(str(value) for value in item.premises),
                        confidence=float(item.confidence),
                        explanation=str(explanation.natural_language),
                    )
                )
        except SemanticRuntimeError:
            raise
        except Exception as exc:
            raise SemanticRuntimeError(
                "forward reasoning failed: {}".format(exc)
            ) from exc

        return ForwardChainResultDTO(
            input_facts=normalized_facts,
            rules=normalized_rules,
            inferences=tuple(normalized_inferences),
            all_facts=tuple(sorted(str(value) for value in reasoner.facts)),
            max_iterations=max_iterations,
        )

    # --------------------------------------------------------------- SHACL API

    def validate(
        self,
        shapes: Union[str, bytes, os.PathLike],
        *,
        shapes_format: Optional[str] = None,
        shapes_base_uri: Optional[str] = None,
        graph_name: Optional[str] = None,
        inference: str = "none",
        advanced: bool = False,
        abort_on_first: bool = False,
    ) -> ValidationReportDTO:
        """Validate runtime data with SHACL and return normalized violations."""

        self.require(CAP_SHACL_VALIDATE)
        normalized_inference = str(inference).lower().strip()
        if normalized_inference not in _INFERENCE_OPTIONS:
            raise SemanticInputError(
                "Unsupported SHACL inference mode {!r}; expected one of {}".format(
                    inference, ", ".join(sorted(_INFERENCE_OPTIONS))
                )
            )
        if not isinstance(advanced, bool) or not isinstance(abort_on_first, bool):
            raise SemanticInputError(
                "advanced and abort_on_first must be boolean values"
            )
        if graph_name is not None:
            _validate_graph_name(graph_name)

        payload, inferred_format = _read_source(shapes)
        normalized_shapes_format = _normalize_rdf_format(
            shapes_format or inferred_format or "turtle"
        )
        if normalized_shapes_format in _DATASET_FORMATS:
            raise SemanticInputError("SHACL shapes must be supplied as one RDF graph")
        shape_graph = Graph()
        try:
            shape_graph.parse(
                data=payload,
                format=normalized_shapes_format,
                publicID=shapes_base_uri,
            )
        except Exception as exc:
            raise SemanticInputError(
                "Failed to parse SHACL shapes as {}: {}".format(
                    normalized_shapes_format, exc
                )
            ) from exc

        # Lazy import is intentional: importing SemanticRuntime never initializes
        # optional SHACL, LLM, or model components.
        import pyshacl

        with self._lock:
            data_graph: Union[Dataset, Graph]
            if graph_name is None:
                data_graph = self._dataset
            else:
                data_graph = self._dataset.graph(URIRef(graph_name))
            try:
                conforms, results_graph, results_text = pyshacl.validate(
                    data_graph=data_graph,
                    shacl_graph=shape_graph,
                    inference=normalized_inference,
                    advanced=advanced,
                    abort_on_first=abort_on_first,
                )
            except Exception as exc:
                raise SemanticRuntimeError(
                    "SHACL validation failed: {}".format(exc)
                ) from exc

            violations = _normalize_validation_results(results_graph)
            return ValidationReportDTO(
                conforms=bool(conforms),
                text=_ensure_text(results_text),
                violations=violations,
                inference=normalized_inference,
                advanced=advanced,
                abort_on_first=abort_on_first,
                revision=self._revision,
            )

    def validate_shacl(
        self,
        shapes: Union[str, bytes, os.PathLike],
        **options: Any,
    ) -> ValidationReportDTO:
        """Explicit alias for :meth:`validate`."""

        return self.validate(shapes, **options)

    # -------------------------------------------------------------- internals

    def _target_graph(self, graph_name: Optional[str]) -> Graph:
        if graph_name is None:
            return _default_graph(self._dataset)
        return self._dataset.graph(URIRef(graph_name))

    def _quad_count(self) -> int:
        return sum(1 for _ in self._dataset.quads((None, None, None, None)))

    def _named_graph_ids(self) -> Tuple[str, ...]:
        default_id = _default_graph(self._dataset).identifier
        names = {
            str(graph.identifier)
            for graph in _dataset_graphs(self._dataset)
            if graph.identifier != default_id and len(graph) > 0
        }
        return tuple(sorted(names))

    def _record_mutation(self) -> int:
        self._revision += 1
        self._query_cache.clear()
        self._snapshot_cache = None
        return self._revision


# ---------------------------------------------------------------------------
# Internal conversion helpers


_FORWARD_RULE_PATTERN = re.compile(r"^IF\s+(.+?)\s+THEN\s+(.+)$", re.IGNORECASE)
_FORWARD_VARIABLE_PATTERN = re.compile(r"\?([A-Za-z_]\w*)")


def _decode_forward_text(value: Union[str, bytes], label: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SemanticInputError(
                "{} text must be valid UTF-8".format(label)
            ) from exc
    raise SemanticInputError("{} input must be text or UTF-8 bytes".format(label))


def _forward_text_lines(value: Union[str, bytes], label: str) -> Tuple[str, ...]:
    text = _decode_forward_text(value, label)
    return tuple(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _normalize_forward_facts(
    source: Union[str, bytes, SemanticPackageAssetDTO, Iterable[str]],
) -> Tuple[str, ...]:
    if isinstance(source, SemanticPackageAssetDTO):
        if str(source.format or "").lower() != "semantica-fact":
            raise SemanticInputError(
                "fact package assets must declare format 'semantica-fact'; "
                "RDF, SWRL, and generic text are not implicit rule facts"
            )
        values = list(_forward_text_lines(source.content, "fact asset"))
    elif isinstance(source, (str, bytes)):
        values = list(_forward_text_lines(source, "fact"))
    else:
        if isinstance(source, (Mapping, set, frozenset)):
            raise SemanticInputError(
                "facts must use an ordered iterable, not a mapping or set"
            )
        try:
            raw_values = list(source)
        except TypeError as exc:
            raise SemanticInputError(
                "facts must be text, a semantica-fact asset, or an ordered iterable"
            ) from exc
        values = []
        for value in raw_values:
            if not isinstance(value, str):
                raise SemanticInputError("every forward fact must be a string")
            lines = _forward_text_lines(value, "fact")
            if len(lines) != 1:
                raise SemanticInputError(
                    "each fact iterable item must contain exactly one fact"
                )
            values.append(lines[0])

    normalized = []
    for fact in values:
        if "?" in fact:
            raise SemanticInputError(
                "forward facts must be ground atoms without variables: {!r}".format(
                    fact
                )
            )
        if re.match(r"^IF\s+", fact, re.IGNORECASE):
            raise SemanticInputError(
                "a forward rule was supplied where a ground fact was required"
            )
        normalized.append(fact)
    return tuple(sorted(set(normalized)))


def _parse_forward_rule_text(text: str) -> Tuple[Tuple[str, ...], str]:
    if not isinstance(text, str) or not text.strip():
        raise SemanticInputError("forward rule text must be a non-empty string")
    normalized = text.strip()
    if "\n" in normalized or "\r" in normalized:
        raise SemanticInputError("each forward rule must occupy exactly one line")
    lowered = normalized.lower()
    if "swrlb:" in lowered or "→" in normalized or "∧" in normalized:
        raise SemanticInputError(
            "SWRL syntax and built-ins are outside rule.forward_chain; "
            "provide an explicit semantica-rule adaptation"
        )
    match = _FORWARD_RULE_PATTERN.fullmatch(normalized)
    if match is None:
        raise SemanticInputError(
            "forward rules must use 'IF <conditions> THEN <conclusion>'"
        )
    conditions = tuple(
        item.strip()
        for item in re.split(r"\s+AND\s+", match.group(1), flags=re.IGNORECASE)
    )
    conclusion = match.group(2).strip()
    if not conditions or any(not item for item in conditions) or not conclusion:
        raise SemanticInputError(
            "forward rule conditions and conclusion cannot be empty"
        )
    antecedent_variables = {
        value
        for condition in conditions
        for value in _FORWARD_VARIABLE_PATTERN.findall(condition)
    }
    conclusion_variables = set(_FORWARD_VARIABLE_PATTERN.findall(conclusion))
    unbound = sorted(conclusion_variables - antecedent_variables)
    if unbound:
        raise SemanticInputError(
            "forward rule conclusion contains unbound variables: {}".format(
                ", ".join("?" + value for value in unbound)
            )
        )
    return conditions, conclusion


def _normalize_forward_rules(
    source: Union[
        str,
        bytes,
        SemanticPackageAssetDTO,
        Iterable[Union[str, ForwardRuleDTO]],
    ],
) -> Tuple[ForwardRuleDTO, ...]:
    raw: List[Union[str, ForwardRuleDTO]]
    if isinstance(source, SemanticPackageAssetDTO):
        if str(source.format or "").lower() != "semantica-rule":
            raise SemanticInputError(
                "rule package assets must declare format 'semantica-rule'; "
                "SWRL and generic engineering prose are not executable here"
            )
        raw = list(_forward_text_lines(source.content, "rule asset"))
    elif isinstance(source, (str, bytes)):
        raw = list(_forward_text_lines(source, "rule"))
    else:
        if isinstance(source, (Mapping, set, frozenset)):
            raise SemanticInputError(
                "rules must use an ordered iterable, not a mapping or set"
            )
        try:
            raw = list(source)
        except TypeError as exc:
            raise SemanticInputError(
                "rules must be text, a semantica-rule asset, or an ordered iterable"
            ) from exc

    normalized: List[ForwardRuleDTO] = []
    next_id = 1
    for value in raw:
        if isinstance(value, ForwardRuleDTO):
            if value.rule_id != value.rule_id.strip():
                raise SemanticInputError(
                    "forward rule IDs cannot have outer whitespace"
                )
            contract = ForwardRuleDTO(
                rule_id=value.rule_id,
                text=value.text.strip(),
                confidence=float(value.confidence),
                priority=value.priority,
            )
        elif isinstance(value, str):
            lines = _forward_text_lines(value, "rule")
            if len(lines) != 1:
                raise SemanticInputError(
                    "each rule iterable item must contain exactly one rule"
                )
            contract = ForwardRuleDTO(
                rule_id="rule_{}".format(next_id),
                text=lines[0],
            )
            next_id += 1
        else:
            raise SemanticInputError("every rule must be a string or ForwardRuleDTO")
        _parse_forward_rule_text(contract.text)
        normalized.append(contract)

    seen_ids = set()
    seen_semantics = set()
    for contract in normalized:
        if contract.rule_id in seen_ids:
            raise SemanticInputError(
                "duplicate forward rule ID: {!r}".format(contract.rule_id)
            )
        seen_ids.add(contract.rule_id)
        semantics = _parse_forward_rule_text(contract.text)
        if semantics in seen_semantics:
            raise SemanticInputError(
                "duplicate forward rule conditions/conclusion are ambiguous"
            )
        seen_semantics.add(semantics)

    # Python's sort is stable: priority is explicit, and equal-priority rules
    # retain the caller's required ordered-iterable contract.
    return tuple(sorted(normalized, key=lambda item: -item.priority))


def _term_to_dto(term: Node) -> RDFTermDTO:
    if isinstance(term, URIRef):
        return RDFTermDTO.iri(str(term))
    if isinstance(term, BNode):
        return RDFTermDTO.blank_node(str(term))
    if isinstance(term, Literal):
        return RDFTermDTO.literal(
            str(term),
            datatype=str(term.datatype) if term.datatype is not None else None,
            language=term.language,
        )
    raise SemanticRuntimeError(
        "Unsupported RDF term returned by backend: {}".format(type(term).__name__)
    )


def _dto_to_term(term: RDFTermDTO) -> Node:
    if term.term_type == "iri":
        return URIRef(term.value)
    if term.term_type == "blank_node":
        return BNode(term.value)
    return Literal(
        term.value,
        datatype=URIRef(term.datatype) if term.datatype is not None else None,
        lang=term.language,
    )


def _binding_to_term(value: Union[RDFTermDTO, str]) -> Node:
    if isinstance(value, RDFTermDTO):
        return _dto_to_term(value)
    if isinstance(value, str):
        return Literal(value)
    raise SemanticInputError(
        "SPARQL binding values must be RDFTermDTO or str, not {}".format(
            type(value).__name__
        )
    )


def _binding_cache_value(value: Union[RDFTermDTO, str]) -> Tuple[Any, ...]:
    if isinstance(value, RDFTermDTO):
        return (value.term_type, value.value, value.datatype, value.language)
    if isinstance(value, str):
        return ("literal", value, None, None)
    raise SemanticInputError(
        "SPARQL binding values must be RDFTermDTO or str, not {}".format(
            type(value).__name__
        )
    )


def _triple_sort_key(triple: RDFTripleDTO) -> Tuple[str, ...]:
    return (
        triple.subject.term_type,
        triple.subject.value,
        triple.predicate.value,
        triple.object.term_type,
        triple.object.value,
        triple.object.datatype or "",
        triple.object.language or "",
    )


def _normalize_validation_results(
    results_graph: Any,
) -> Tuple[ValidationViolationDTO, ...]:
    if not isinstance(results_graph, Graph):
        raise SemanticRuntimeError("SHACL backend did not return an RDF results graph")
    sh = Namespace("http://www.w3.org/ns/shacl#")
    normalized: List[ValidationViolationDTO] = []
    for result in results_graph.subjects(RDF.type, sh.ValidationResult):
        focus = results_graph.value(result, sh.focusNode)
        path = results_graph.value(result, sh.resultPath)
        source_constraint = results_graph.value(result, sh.sourceConstraintComponent)
        severity = results_graph.value(result, sh.resultSeverity)
        messages = sorted(
            str(message) for message in results_graph.objects(result, sh.resultMessage)
        )
        normalized.append(
            ValidationViolationDTO(
                focus=str(focus) if focus is not None else "",
                path=str(path) if path is not None else None,
                source_constraint=_local_name(source_constraint),
                severity=_local_name(severity) or "Violation",
                message="\n".join(messages),
            )
        )
    return tuple(
        sorted(
            normalized,
            key=lambda item: (
                item.focus,
                item.path or "",
                item.source_constraint,
                item.severity,
                item.message,
            ),
        )
    )


def _local_name(term: Optional[Node]) -> str:
    if term is None:
        return ""
    value = str(term)
    return value.rsplit("#", 1)[-1].rsplit("/", 1)[-1]


def _default_graph(dataset: Dataset) -> Graph:
    if hasattr(dataset, "default_graph"):
        return dataset.default_graph
    # rdflib 6.x compatibility.
    return dataset.default_context


def _dataset_graphs(dataset: Dataset) -> Iterable[Graph]:
    graphs = getattr(dataset, "graphs", None)
    if callable(graphs):
        return graphs()
    # rdflib 6.x compatibility.
    return dataset.contexts()


def _normalize_rdf_format(format: str) -> str:
    if not isinstance(format, str) or not format.strip():
        raise SemanticInputError("RDF format must be a non-empty string")
    normalized = _FORMAT_ALIASES.get(format.lower().strip())
    if normalized is None:
        raise SemanticInputError(
            "Unsupported RDF format {!r}; supported formats: {}".format(
                format, ", ".join(sorted(_FORMAT_ALIASES))
            )
        )
    return normalized


def _read_source(
    source: Union[str, bytes, os.PathLike],
) -> Tuple[Union[str, bytes], Optional[str]]:
    if isinstance(source, bytes):
        return source, None
    if isinstance(source, os.PathLike):
        path = Path(source)
        if not path.is_file():
            raise SemanticInputError("RDF source path does not exist: {}".format(path))
        return path.read_bytes(), _PATH_FORMATS.get(path.suffix.lower())
    if not isinstance(source, str):
        raise SemanticInputError(
            "RDF source must be a path, text, bytes, or ConstructResultDTO"
        )

    # A short, newline-free existing path is treated as a path.  Everything
    # else is RDF text, avoiding accidental filesystem probes for large input.
    if "\n" not in source and "\r" not in source and len(source) < 4096:
        candidate = Path(source)
        try:
            if candidate.is_file():
                return candidate.read_bytes(), _PATH_FORMATS.get(
                    candidate.suffix.lower()
                )
        except OSError:
            pass
    return source, None


def _read_package_manifest(
    package: Union[Mapping[str, Any], os.PathLike, str],
    *,
    base_path: Optional[os.PathLike],
) -> Tuple[Mapping[str, Any], Optional[Path]]:
    if isinstance(package, Mapping):
        root = Path(base_path).resolve() if base_path is not None else None
        return package, root
    path = Path(package).resolve()
    if not path.is_file():
        raise SemanticInputError(
            "semantic package manifest does not exist: {}".format(path)
        )
    try:
        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            parsed = json.loads(content)
        elif path.suffix.lower() in {".yaml", ".yml"}:
            import yaml

            parsed = yaml.safe_load(content)
        else:
            raise SemanticInputError("semantic package manifest must be JSON or YAML")
    except SemanticRuntimeError:
        raise
    except Exception as exc:
        raise SemanticInputError(
            "failed to parse semantic package manifest: {}".format(exc)
        ) from exc
    if not isinstance(parsed, Mapping):
        raise SemanticInputError("semantic package manifest root must be a mapping")
    return parsed, path.parent


def _required_manifest_text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SemanticInputError(
            "semantic package field {!r} must be a non-empty string".format(key)
        )
    return value.strip()


def _read_package_asset(
    asset: Mapping[str, Any], root: Optional[Path]
) -> Tuple[bytes, Optional[str]]:
    has_path = "path" in asset
    has_data = "data" in asset
    if has_path == has_data:
        raise SemanticInputError(
            "semantic package asset requires exactly one of 'path' or 'data'"
        )
    if has_data:
        data = asset.get("data")
        if isinstance(data, bytes):
            return data, None
        if isinstance(data, str):
            return data.encode("utf-8"), None
        raise SemanticInputError("semantic package asset data must be text or bytes")

    if root is None:
        raise SemanticInputError(
            "semantic package asset paths require a manifest path or base_path"
        )
    relative = Path(str(asset.get("path")))
    if relative.is_absolute():
        raise SemanticInputError("semantic package asset path must be relative")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise SemanticInputError(
            "semantic package asset path escapes the package root"
        ) from exc
    if not resolved.is_file():
        raise SemanticInputError(
            "semantic package asset does not exist: {}".format(relative)
        )
    return resolved.read_bytes(), _PATH_FORMATS.get(resolved.suffix.lower())


def _asset_is_rdf(asset: Mapping[str, Any], role: str) -> bool:
    kind = str(asset.get("kind", "")).lower().strip()
    return kind == "rdf" or role.lower() in {
        "ontology",
        "data",
        "instances",
        "rdf",
        "shapes",
    }


def _validate_graph_name(graph_name: str) -> None:
    if not isinstance(graph_name, str) or not graph_name.strip():
        raise SemanticInputError("graph_name must be a non-empty absolute IRI")
    if not urlsplit(graph_name).scheme or any(char.isspace() for char in graph_name):
        raise SemanticInputError(
            "graph_name must be an absolute IRI: {!r}".format(graph_name)
        )


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _distribution_version(name: str) -> str:
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return "not-installed"


def _runtime_versions() -> Tuple[Tuple[str, str], ...]:
    return tuple(
        sorted(
            {
                "semantica": _distribution_version("semantica"),
                "rdflib": _distribution_version("rdflib"),
                "pyshacl": _distribution_version("pyshacl"),
                "pyoxigraph": _distribution_version("pyoxigraph"),
            }.items()
        )
    )


def _chapter_contract_hash(
    assets: Iterable[SemanticPackageAssetDTO],
) -> Optional[str]:
    contract_roles = {"chapter_contract", "chapter_manifest", "contract"}
    matches = tuple(
        asset.sha256 for asset in assets if asset.role.lower().strip() in contract_roles
    )
    if len(matches) != 1:
        return None
    return matches[0]


def _is_source_revision(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.lower().strip()
    return 7 <= len(normalized) <= 64 and all(
        character in "0123456789abcdef" for character in normalized
    )


def _ensure_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


__all__ = [
    "AskResultDTO",
    "CapabilityProfileDTO",
    "CapabilityUnavailableError",
    "ConstructResultDTO",
    "DatasetDiffDTO",
    "DatasetSnapshotDTO",
    "ExecutionReportDTO",
    "ForwardChainResultDTO",
    "ForwardInferenceDTO",
    "ForwardRuleDTO",
    "LossySerializationError",
    "MutationResultDTO",
    "PackageLoadResultDTO",
    "PackageExecutionReceiptDTO",
    "ProvenanceBundleDTO",
    "QueryResultDTO",
    "QueryRowDTO",
    "RDFTermDTO",
    "RDFTripleDTO",
    "SemanticPackageAssetDTO",
    "SemanticPackageIdentityDTO",
    "SelectResultDTO",
    "SemanticInputError",
    "SemanticRuntime",
    "SemanticRuntimeError",
    "ReleaseCheckDTO",
    "ReleaseVerdictDTO",
    "UnsupportedBackendError",
    "UnsupportedCapabilityError",
    "UnsupportedProfileError",
    "UnsupportedQueryTypeError",
    "UpdateResultDTO",
    "ValidationReportDTO",
    "ValidationViolationDTO",
    "CAP_CACHE_REVISION",
    "CAP_DATASET_DIFF",
    "CAP_DATASET_SNAPSHOT",
    "CAP_EXECUTION_RECEIPT",
    "CAP_RULE_FORWARD_CHAIN",
    "CAP_PACKAGE_LOAD",
    "CAP_PROVENANCE_BUNDLE",
    "CAP_RDF_LOAD",
    "CAP_RDF_SERIALIZE",
    "CAP_SHACL_VALIDATE",
    "CAP_SPARQL_ASK",
    "CAP_SPARQL_CONSTRUCT",
    "CAP_SPARQL_SELECT",
    "CAP_SPARQL_UPDATE",
    "CAP_RELEASE_VERIFY",
]
