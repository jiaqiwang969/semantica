"""Deterministic lifecycle evidence for :class:`SemanticRuntime`.

This module provides the pure-data side of the ontology runtime lifecycle:

* graph-isomorphism-stable RDF Dataset snapshots;
* deterministic snapshot diffs;
* content-bound execution reports and package receipts;
* W3C PROV-inspired, hash-chained provenance bundles; and
* fail-closed release verdict DTOs.

The implementation deliberately has no dependency on a consuming project or
on Git.  Runtime source and artifact identities are supplied by the caller and
are therefore usable in offline builds.  Timestamps are also injectable so an
identical execution can produce byte-identical evidence in tests and
reproducible release pipelines.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from rdflib import BNode, Graph, Literal, Namespace
from rdflib.compare import to_canonical_graph
from rdflib.namespace import RDF
from rdflib.term import Identifier, Node

from ..provenance import ProvenanceEntry
from ..provenance.integrity import compute_checksum, verify_checksum


SNAPSHOT_SCHEMA_VERSION = "1.0"
SNAPSHOT_ALGORITHM = "semantica-rdf-dataset-c14n-v1"
RECEIPT_SCHEMA_VERSION = "1.0"
PROVENANCE_SCHEMA_VERSION = "1.0"
RELEASE_SCHEMA_VERSION = "1.0"

REPORT_STATUSES = frozenset({"passed", "failed", "blocked"})
RELEASE_STATUSES = frozenset({"complete", "blocked"})

_C14N = Namespace("urn:semantica:dataset-c14n:v1:")
_HEX_CHARS = frozenset("0123456789abcdef")


def utc_now() -> str:
    """Return a timezone-explicit UTC timestamp.

    Public builders accept an explicit timestamp; this helper is only their
    default.  Keeping the clock at the boundary makes deterministic evidence
    straightforward without monkeypatching global time.
    """

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    """Serialize JSON-compatible data with one deterministic representation."""

    normalized = _normalize_json_value(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_text(value: str) -> str:
    """Hash UTF-8 text with SHA-256."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DatasetSnapshotDTO:
    """Canonical, content-addressed RDF Dataset snapshot.

    ``canonical_nquads`` is a sorted N-Quads-compatible representation.  Its
    blank-node labels are derived from the whole RDF Dataset, including graph
    context, rather than from backend-assigned identifiers.  ``dataset_sha256``
    hashes only those canonical bytes; metadata such as revision and time does
    not change the semantic dataset identity.
    """

    dataset_sha256: str
    quad_count: int
    canonical_nquads: str
    revision: int
    created_at: str
    algorithm: str = SNAPSHOT_ALGORITHM
    schema_version: str = SNAPSHOT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not is_sha256(self.dataset_sha256):
            raise ValueError("dataset_sha256 must be a lowercase SHA-256 digest")
        if self.quad_count < 0 or self.revision < 0:
            raise ValueError("quad_count and revision must be non-negative")
        if self.algorithm != SNAPSHOT_ALGORITHM:
            raise ValueError("unsupported RDF Dataset canonicalization algorithm")
        if self.schema_version != SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("unsupported dataset snapshot schema_version")

    @property
    def snapshot_id(self) -> str:
        return "urn:sha256:{}".format(self.dataset_sha256)

    def verify_integrity(self) -> bool:
        lines = tuple(self.canonical_nquads.splitlines())
        expected_count = len(lines) if self.canonical_nquads else 0
        return (
            expected_count == self.quad_count
            and tuple(sorted(lines)) == lines
            and sha256_text(self.canonical_nquads) == self.dataset_sha256
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "dataset_sha256": self.dataset_sha256,
            "quad_count": self.quad_count,
            "revision": self.revision,
            "created_at": self.created_at,
            "canonical_nquads": self.canonical_nquads,
        }

    def to_json(self) -> str:
        return canonical_json(self.as_dict())


@dataclass(frozen=True)
class DatasetDiffDTO:
    """Deterministic set difference between two canonical snapshots."""

    before_sha256: str
    after_sha256: str
    added_quads: Tuple[str, ...]
    removed_quads: Tuple[str, ...]
    unchanged_count: int
    created_at: str
    schema_version: str = SNAPSHOT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not is_sha256(self.before_sha256) or not is_sha256(self.after_sha256):
            raise ValueError("snapshot diff identities must be SHA-256 digests")
        if self.unchanged_count < 0:
            raise ValueError("unchanged_count must be non-negative")
        if tuple(sorted(set(self.added_quads))) != self.added_quads:
            raise ValueError("added_quads must be unique and sorted")
        if tuple(sorted(set(self.removed_quads))) != self.removed_quads:
            raise ValueError("removed_quads must be unique and sorted")

    @property
    def changed(self) -> bool:
        return bool(self.added_quads or self.removed_quads)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "added_quads": list(self.added_quads),
            "removed_quads": list(self.removed_quads),
            "unchanged_count": self.unchanged_count,
            "changed": self.changed,
            "created_at": self.created_at,
        }

    def to_json(self) -> str:
        return canonical_json(self.as_dict())


@dataclass(frozen=True)
class ExecutionReportDTO:
    """Immutable, content-bound CQ/SHACL/oracle/capability report."""

    kind: str
    status: str
    payload_json: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.kind.strip():
            raise ValueError("execution report kind must be non-empty")
        if self.status not in REPORT_STATUSES:
            raise ValueError(
                "execution report status must be passed, failed, or blocked"
            )
        if not is_sha256(self.sha256):
            raise ValueError("execution report sha256 must be a SHA-256 digest")
        # Validate that the retained payload is canonical JSON, not merely
        # parseable JSON whose whitespace/key order could vary by producer.
        if canonical_json(json.loads(self.payload_json)) != self.payload_json:
            raise ValueError("execution report payload_json must be canonical JSON")

    @property
    def payload(self) -> Any:
        return json.loads(self.payload_json)

    def verify_integrity(self) -> bool:
        return self.sha256 == sha256_text(
            canonical_json(
                {"kind": self.kind, "status": self.status, "payload": self.payload}
            )
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "status": self.status,
            "payload": self.payload,
            "sha256": self.sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.as_dict())


@dataclass(frozen=True)
class ProvenanceRecordDTO:
    """One immutable projection of a Semantica ``ProvenanceEntry``."""

    entry_json: str
    checksum: str

    def __post_init__(self) -> None:
        parsed = json.loads(self.entry_json)
        if canonical_json(parsed) != self.entry_json:
            raise ValueError("provenance entry_json must be canonical JSON")
        if not is_sha256(self.checksum):
            raise ValueError("provenance checksum must be a SHA-256 digest")
        if parsed.get("checksum") != self.checksum:
            raise ValueError("provenance checksum does not match retained entry")

    @property
    def entry(self) -> Dict[str, Any]:
        return json.loads(self.entry_json)

    @property
    def entity_id(self) -> str:
        return str(self.entry.get("entity_id", ""))

    def verify_integrity(self) -> bool:
        return verify_checksum(self.entry, self.checksum)

    def as_dict(self) -> Dict[str, Any]:
        return self.entry


@dataclass(frozen=True)
class ProvenanceBundleDTO:
    """Deterministic PROV bundle that binds every execution input/output."""

    bundle_id: str
    generated_at: str
    bindings_json: str
    records: Tuple[ProvenanceRecordDTO, ...]
    bundle_sha256: str
    schema_version: str = PROVENANCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        parsed = json.loads(self.bindings_json)
        if canonical_json(parsed) != self.bindings_json:
            raise ValueError("provenance bindings_json must be canonical JSON")
        if not self.bundle_id.strip():
            raise ValueError("provenance bundle_id must be non-empty")
        if not self.records:
            raise ValueError("provenance bundle must contain at least one record")
        if not is_sha256(self.bundle_sha256):
            raise ValueError("bundle_sha256 must be a SHA-256 digest")

    @property
    def bindings(self) -> Dict[str, Any]:
        return json.loads(self.bindings_json)

    def verify_integrity(self) -> bool:
        previous_checksum: Optional[str] = None
        expected_sequence = 1
        for record in self.records:
            entry = record.entry
            if not record.verify_integrity():
                return False
            if entry.get("sequence_id") != expected_sequence:
                return False
            if entry.get("previous_checksum") != previous_checksum:
                return False
            previous_checksum = record.checksum
            expected_sequence += 1
        return self.bundle_sha256 == sha256_text(canonical_json(self._content_dict()))

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "bundle_id": self.bundle_id,
            "generated_at": self.generated_at,
            "bindings": self.bindings,
            "records": [record.as_dict() for record in self.records],
        }

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "bundle_sha256": self.bundle_sha256}

    def to_json(self) -> str:
        return canonical_json(self.as_dict())


@dataclass(frozen=True)
class PackageExecutionReceiptDTO:
    """Content-addressed evidence for one semantic package execution."""

    created_at: str
    runtime_version: str
    runtime_commit: str
    runtime_artifact_sha256: str
    package_id: str
    package_version: str
    package_digest: str
    asset_hashes: Tuple[Tuple[str, str], ...]
    chapter_contract_sha256: str
    dataset_sha256: str
    dataset_quad_count: int
    dataset_revision: int
    capability_report: ExecutionReportDTO
    cq_report: ExecutionReportDTO
    shacl_report: ExecutionReportDTO
    oracle_report: ExecutionReportDTO
    output_hashes: Tuple[Tuple[str, str], ...]
    provenance_bundle: ProvenanceBundleDTO
    receipt_sha256: str
    schema_version: str = RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported package execution receipt schema_version")
        if tuple(sorted(self.asset_hashes)) != self.asset_hashes:
            raise ValueError("asset_hashes must be sorted by asset id")
        if tuple(sorted(self.output_hashes)) != self.output_hashes:
            raise ValueError("output_hashes must be sorted by output id")
        if len({name for name, _ in self.asset_hashes}) != len(self.asset_hashes):
            raise ValueError("asset_hashes contains duplicate asset ids")
        if len({name for name, _ in self.output_hashes}) != len(self.output_hashes):
            raise ValueError("output_hashes contains duplicate output ids")
        if not is_sha256(self.receipt_sha256):
            raise ValueError("receipt_sha256 must be a SHA-256 digest")

    @property
    def receipt_id(self) -> str:
        return "urn:sha256:{}".format(self.receipt_sha256)

    @property
    def reports(self) -> Tuple[ExecutionReportDTO, ...]:
        return (
            self.capability_report,
            self.cq_report,
            self.shacl_report,
            self.oracle_report,
        )

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "runtime_version": self.runtime_version,
            "runtime_commit": self.runtime_commit,
            "runtime_artifact_sha256": self.runtime_artifact_sha256,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "package_digest": self.package_digest,
            "asset_hashes": dict(self.asset_hashes),
            "chapter_contract_sha256": self.chapter_contract_sha256,
            "dataset_sha256": self.dataset_sha256,
            "dataset_quad_count": self.dataset_quad_count,
            "dataset_revision": self.dataset_revision,
            "capability_report": self.capability_report.as_dict(),
            "cq_report": self.cq_report.as_dict(),
            "shacl_report": self.shacl_report.as_dict(),
            "oracle_report": self.oracle_report.as_dict(),
            "output_hashes": dict(self.output_hashes),
            "provenance_bundle": self.provenance_bundle.as_dict(),
        }

    def verify_integrity(self) -> bool:
        return (
            all(report.verify_integrity() for report in self.reports)
            and self.provenance_bundle.verify_integrity()
            and self.receipt_sha256 == sha256_text(canonical_json(self._content_dict()))
        )

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "receipt_sha256": self.receipt_sha256}

    def to_json(self) -> str:
        return canonical_json(self.as_dict())


@dataclass(frozen=True)
class ReleaseCheckDTO:
    """One deterministic release-gate check."""

    check_id: str
    passed: bool
    message: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "passed": self.passed,
            "message": self.message,
        }


@dataclass(frozen=True)
class ReleaseVerdictDTO:
    """Fail-closed verdict for a package execution receipt."""

    status: str
    receipt_sha256: str
    checked_at: str
    checks: Tuple[ReleaseCheckDTO, ...]
    schema_version: str = RELEASE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in RELEASE_STATUSES:
            raise ValueError("release status must be complete or blocked")
        if not self.checks:
            raise ValueError("release verdict must retain its checks")
        expected = "complete" if all(item.passed for item in self.checks) else "blocked"
        if self.status != expected:
            raise ValueError("release verdict status does not match checks")

    @property
    def complete(self) -> bool:
        return self.status == "complete"

    @property
    def reasons(self) -> Tuple[str, ...]:
        return tuple(item.check_id for item in self.checks if not item.passed)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "receipt_sha256": self.receipt_sha256,
            "checked_at": self.checked_at,
            "checks": [item.as_dict() for item in self.checks],
            "reasons": list(self.reasons),
        }

    def to_json(self) -> str:
        return canonical_json(self.as_dict())


def snapshot_dataset(
    quads: Iterable[Tuple[Node, Node, Node, Identifier]],
    *,
    default_graph_identifier: Identifier,
    revision: int,
    created_at: Optional[str] = None,
) -> DatasetSnapshotDTO:
    """Create a canonical snapshot from backend quads.

    The dataset is encoded as one RDF graph whose statement nodes retain the
    original subject, predicate, object, and graph-name identities.  RDFLib's
    graph canonicalizer then assigns stable identifiers across that complete
    structure.  This avoids independently canonicalizing named graphs, which
    would lose the identity of blank nodes shared across graph boundaries.
    """

    encoded = Graph()
    for subject, predicate, obj, context in quads:
        statement = BNode()
        encoded.add((statement, RDF.type, _C14N.Quad))
        encoded.add((statement, _C14N.subject, subject))
        encoded.add((statement, _C14N.predicate, predicate))
        encoded.add((statement, _C14N.object, obj))
        if context == default_graph_identifier:
            encoded.add((statement, _C14N.defaultGraph, Literal(True)))
        else:
            encoded.add((statement, _C14N.graph, context))

    canonical = to_canonical_graph(encoded)
    lines: List[str] = []
    for statement in canonical.subjects(RDF.type, _C14N.Quad):
        subject = canonical.value(statement, _C14N.subject)
        predicate = canonical.value(statement, _C14N.predicate)
        obj = canonical.value(statement, _C14N.object)
        graph_name = canonical.value(statement, _C14N.graph)
        is_default = canonical.value(statement, _C14N.defaultGraph)
        if subject is None or predicate is None or obj is None:
            raise ValueError("canonical dataset statement is incomplete")
        if graph_name is not None and is_default is not None:
            raise ValueError("canonical dataset statement has two graph contexts")
        if graph_name is None and is_default is None:
            raise ValueError("canonical dataset statement has no graph context")
        terms: List[Node] = [subject, predicate, obj]
        if graph_name is not None:
            terms.append(graph_name)
        lines.append("{} .".format(" ".join(_term_nquad(term) for term in terms)))

    canonical_nquads = "\n".join(sorted(lines))
    return DatasetSnapshotDTO(
        dataset_sha256=sha256_text(canonical_nquads),
        quad_count=len(lines),
        canonical_nquads=canonical_nquads,
        revision=revision,
        created_at=created_at or utc_now(),
    )


def diff_snapshots(
    before: DatasetSnapshotDTO,
    after: DatasetSnapshotDTO,
    *,
    created_at: Optional[str] = None,
) -> DatasetDiffDTO:
    """Compare two verified canonical RDF Dataset snapshots."""

    if not before.verify_integrity() or not after.verify_integrity():
        raise ValueError("cannot diff a dataset snapshot with invalid integrity")
    before_lines = (
        set(before.canonical_nquads.splitlines()) if before.canonical_nquads else set()
    )
    after_lines = (
        set(after.canonical_nquads.splitlines()) if after.canonical_nquads else set()
    )
    return DatasetDiffDTO(
        before_sha256=before.dataset_sha256,
        after_sha256=after.dataset_sha256,
        added_quads=tuple(sorted(after_lines - before_lines)),
        removed_quads=tuple(sorted(before_lines - after_lines)),
        unchanged_count=len(before_lines & after_lines),
        created_at=created_at or utc_now(),
    )


def execution_report(
    kind: str,
    payload: Any,
    *,
    status: str,
) -> ExecutionReportDTO:
    """Build a content-bound report from JSON-compatible pure data."""

    payload_json = canonical_json(payload)
    digest = sha256_text(
        canonical_json(
            {"kind": kind, "status": status, "payload": json.loads(payload_json)}
        )
    )
    return ExecutionReportDTO(
        kind=str(kind), status=str(status), payload_json=payload_json, sha256=digest
    )


def missing_execution_report(kind: str) -> ExecutionReportDTO:
    """Represent absent evidence explicitly instead of inventing a green result."""

    return execution_report(
        kind,
        {"reason": "required execution report was not supplied"},
        status="blocked",
    )


def build_provenance_bundle(
    bindings: Mapping[str, Any],
    *,
    generated_at: Optional[str] = None,
) -> ProvenanceBundleDTO:
    """Build an in-memory, deterministic PROV bundle for receipt evidence.

    This reuses Semantica's ``ProvenanceEntry`` schema and checksum algorithm,
    but intentionally avoids ``ProvenanceManager`` storage and implicit clocks.
    The resulting bundle is a stable DTO and has no external side effects.
    """

    when = generated_at or utc_now()
    normalized_bindings = _normalize_json_value(dict(bindings))
    bindings_json = canonical_json(normalized_bindings)
    binding_digest = sha256_text(bindings_json)
    bundle_id = "urn:semantica:provenance-bundle:{}".format(
        sha256_text(canonical_json({"bindings": normalized_bindings, "time": when}))
    )
    runtime_version = str(normalized_bindings.get("runtime_version", ""))
    package_id = str(normalized_bindings.get("package_id", ""))
    package_version = str(normalized_bindings.get("package_version", ""))
    package_digest = str(normalized_bindings.get("package_digest", ""))
    dataset_sha256 = str(normalized_bindings.get("dataset_sha256", ""))
    asset_hashes = normalized_bindings.get("asset_hashes", {})
    reports = normalized_bindings.get("report_hashes", {})

    entries: List[ProvenanceEntry] = []
    package_entity_id = "urn:semantica:package:{}".format(package_digest or "missing")
    entries.append(
        _provenance_entry(
            entity_id=package_entity_id,
            entity_type="semantic_package",
            activity_id="semantic.package.load",
            agent_id="semantica:{}".format(runtime_version or "unknown"),
            source_document="{}@{}".format(package_id, package_version),
            timestamp=when,
            bundle_id=bundle_id,
            metadata={"package_digest": package_digest},
        )
    )

    asset_entity_ids: List[str] = []
    if isinstance(asset_hashes, Mapping):
        for asset_id, digest in sorted(asset_hashes.items()):
            entity_id = "urn:semantica:asset:{}".format(
                sha256_text("{}:{}:{}".format(package_digest, asset_id, digest))
            )
            asset_entity_ids.append(entity_id)
            entries.append(
                _provenance_entry(
                    entity_id=entity_id,
                    entity_type="semantic_package_asset",
                    activity_id="semantic.package.load",
                    agent_id="semantica:{}".format(runtime_version or "unknown"),
                    source_document="{}@{}".format(package_id, package_version),
                    timestamp=when,
                    bundle_id=bundle_id,
                    parent_entity_id=package_entity_id,
                    derived_from_id=package_entity_id,
                    metadata={"asset_id": asset_id, "sha256": digest},
                )
            )

    dataset_entity_id = "urn:semantica:dataset:{}".format(dataset_sha256 or "missing")
    entries.append(
        _provenance_entry(
            entity_id=dataset_entity_id,
            entity_type="rdf_dataset_snapshot",
            activity_id="semantic.package.execute",
            agent_id="semantica:{}".format(runtime_version or "unknown"),
            source_document="{}@{}".format(package_id, package_version),
            timestamp=when,
            bundle_id=bundle_id,
            parent_entity_id=package_entity_id,
            used_entities=asset_entity_ids,
            metadata={"dataset_sha256": dataset_sha256},
        )
    )

    report_entity_ids: List[str] = []
    if isinstance(reports, Mapping):
        for kind, digest in sorted(reports.items()):
            entity_id = "urn:semantica:execution-report:{}".format(digest)
            report_entity_ids.append(entity_id)
            entries.append(
                _provenance_entry(
                    entity_id=entity_id,
                    entity_type="semantic_execution_report",
                    activity_id="semantic.package.verify",
                    agent_id="semantica:{}".format(runtime_version or "unknown"),
                    source_document="{}@{}".format(package_id, package_version),
                    timestamp=when,
                    bundle_id=bundle_id,
                    parent_entity_id=dataset_entity_id,
                    derived_from_id=dataset_entity_id,
                    metadata={"report_kind": kind, "sha256": digest},
                )
            )

    entries.append(
        _provenance_entry(
            entity_id="urn:semantica:execution:{}".format(binding_digest),
            entity_type="semantic_package_execution",
            activity_id="semantic.release.evidence",
            agent_id="semantica:{}".format(runtime_version or "unknown"),
            source_document="{}@{}".format(package_id, package_version),
            timestamp=when,
            bundle_id=bundle_id,
            parent_entity_id=dataset_entity_id,
            used_entities=[package_entity_id, dataset_entity_id] + report_entity_ids,
            metadata={"bindings_sha256": binding_digest},
        )
    )

    records: List[ProvenanceRecordDTO] = []
    previous_checksum: Optional[str] = None
    for sequence_id, entry in enumerate(entries, start=1):
        entry.sequence_id = sequence_id
        entry.previous_checksum = previous_checksum
        entry.checksum = compute_checksum(entry)
        records.append(
            ProvenanceRecordDTO(
                entry_json=canonical_json(entry.to_dict()), checksum=entry.checksum
            )
        )
        previous_checksum = entry.checksum

    content = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "bundle_id": bundle_id,
        "generated_at": when,
        "bindings": normalized_bindings,
        "records": [record.as_dict() for record in records],
    }
    return ProvenanceBundleDTO(
        bundle_id=bundle_id,
        generated_at=when,
        bindings_json=bindings_json,
        records=tuple(records),
        bundle_sha256=sha256_text(canonical_json(content)),
    )


def build_execution_receipt(
    *,
    created_at: str,
    runtime_version: str,
    runtime_commit: str,
    runtime_artifact_sha256: str,
    package_id: str,
    package_version: str,
    package_digest: str,
    asset_hashes: Mapping[str, str],
    chapter_contract_sha256: str,
    snapshot: DatasetSnapshotDTO,
    capability_report: ExecutionReportDTO,
    cq_report: ExecutionReportDTO,
    shacl_report: ExecutionReportDTO,
    oracle_report: ExecutionReportDTO,
    output_hashes: Optional[Mapping[str, str]] = None,
) -> PackageExecutionReceiptDTO:
    """Create a deterministic receipt and its bound provenance bundle."""

    sorted_assets = tuple(
        sorted((str(key), str(value)) for key, value in asset_hashes.items())
    )
    sorted_outputs = tuple(
        sorted((str(key), str(value)) for key, value in (output_hashes or {}).items())
    )
    reports = (capability_report, cq_report, shacl_report, oracle_report)
    bindings = {
        "runtime_version": str(runtime_version),
        "runtime_commit": str(runtime_commit),
        "runtime_artifact_sha256": str(runtime_artifact_sha256),
        "package_id": str(package_id),
        "package_version": str(package_version),
        "package_digest": str(package_digest),
        "asset_hashes": dict(sorted_assets),
        "chapter_contract_sha256": str(chapter_contract_sha256),
        "dataset_sha256": snapshot.dataset_sha256,
        "report_hashes": {report.kind: report.sha256 for report in reports},
        "output_hashes": dict(sorted_outputs),
    }
    bundle = build_provenance_bundle(bindings, generated_at=created_at)
    provisional = PackageExecutionReceiptDTO(
        created_at=created_at,
        runtime_version=str(runtime_version),
        runtime_commit=str(runtime_commit),
        runtime_artifact_sha256=str(runtime_artifact_sha256),
        package_id=str(package_id),
        package_version=str(package_version),
        package_digest=str(package_digest),
        asset_hashes=sorted_assets,
        chapter_contract_sha256=str(chapter_contract_sha256),
        dataset_sha256=snapshot.dataset_sha256,
        dataset_quad_count=snapshot.quad_count,
        dataset_revision=snapshot.revision,
        capability_report=capability_report,
        cq_report=cq_report,
        shacl_report=shacl_report,
        oracle_report=oracle_report,
        output_hashes=sorted_outputs,
        provenance_bundle=bundle,
        receipt_sha256="0" * 64,
    )
    digest = sha256_text(canonical_json(provisional._content_dict()))
    return PackageExecutionReceiptDTO(
        **{**provisional.__dict__, "receipt_sha256": digest}
    )


def receipt_bindings(receipt: PackageExecutionReceiptDTO) -> Dict[str, Any]:
    """Return the exact binding map a receipt's PROV bundle must retain."""

    return {
        "runtime_version": receipt.runtime_version,
        "runtime_commit": receipt.runtime_commit,
        "runtime_artifact_sha256": receipt.runtime_artifact_sha256,
        "package_id": receipt.package_id,
        "package_version": receipt.package_version,
        "package_digest": receipt.package_digest,
        "asset_hashes": dict(receipt.asset_hashes),
        "chapter_contract_sha256": receipt.chapter_contract_sha256,
        "dataset_sha256": receipt.dataset_sha256,
        "report_hashes": {report.kind: report.sha256 for report in receipt.reports},
        "output_hashes": dict(receipt.output_hashes),
    }


def is_sha256(value: Any) -> bool:
    """Return whether ``value`` is one lowercase hexadecimal SHA-256 digest."""

    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX_CHARS for character in value)
    )


def _normalize_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        # json.dumps(..., allow_nan=False) performs the finite-value check.
        json.dumps(value, allow_nan=False)
        return value
    if isinstance(value, Mapping):
        normalized: Dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if text_key in normalized:
                raise ValueError("JSON mapping contains colliding string keys")
            normalized[text_key] = _normalize_json_value(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize_json_value(item) for item in value]
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        return _normalize_json_value(as_dict())
    raise TypeError(
        "lifecycle evidence must be JSON-compatible pure data, not {}".format(
            type(value).__name__
        )
    )


def _term_nquad(term: Node) -> str:
    # RDFLib's n3() emits an absolute, prefix-free RDF term representation
    # when no namespace manager is supplied.  Canonical graph bnodes already
    # carry content-derived labels at this point.
    return term.n3()


def _provenance_entry(
    *,
    entity_id: str,
    entity_type: str,
    activity_id: str,
    agent_id: str,
    source_document: str,
    timestamp: str,
    bundle_id: str,
    metadata: Mapping[str, Any],
    parent_entity_id: Optional[str] = None,
    derived_from_id: Optional[str] = None,
    used_entities: Optional[Sequence[str]] = None,
) -> ProvenanceEntry:
    return ProvenanceEntry(
        entity_id=entity_id,
        entity_type=entity_type,
        activity_id=activity_id,
        agent_id=agent_id,
        agent_type="software_agent",
        is_automated=True,
        role="generator",
        source_document=source_document,
        timestamp=timestamp,
        first_seen=timestamp,
        last_updated=timestamp,
        confidence=1.0,
        parent_entity_id=parent_entity_id,
        derived_from_id=derived_from_id,
        used_entities=list(used_entities or ()),
        activity_started_at_time=timestamp,
        activity_ended_at_time=timestamp,
        bundle_id=bundle_id,
        metadata=dict(metadata),
    )


__all__ = [
    "DatasetDiffDTO",
    "DatasetSnapshotDTO",
    "ExecutionReportDTO",
    "PackageExecutionReceiptDTO",
    "ProvenanceBundleDTO",
    "ProvenanceRecordDTO",
    "ReleaseCheckDTO",
    "ReleaseVerdictDTO",
    "SNAPSHOT_ALGORITHM",
    "build_execution_receipt",
    "build_provenance_bundle",
    "canonical_json",
    "diff_snapshots",
    "execution_report",
    "is_sha256",
    "missing_execution_report",
    "receipt_bindings",
    "snapshot_dataset",
    "utc_now",
]
