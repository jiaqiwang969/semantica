"""Governed, content-addressed ontology evolution on ``SemanticRuntime``.

This module is the native Semantica home for the recurring ontology loop:

``init -> propose -> reasoned verdict -> commit -> CQ regress -> history``.

The workspace is intentionally a small append-only release store.  A version
is assembled in a private staging directory and published only after its RDF
Dataset snapshot, semantic diff, execution receipt, PROV bundle, and release
verdict have all been produced by :class:`~semantica.ontology.runtime.SemanticRuntime`.
Only then is the atomic ``current.json`` pointer replaced.  Existing versions
are never overwritten and a conflict or removal without a non-empty reason is
rejected before staging begins.

The JSON ontology model is deliberately bounded: named classes and object
properties with comments and optional JSON-compatible source metadata.  It is
not a replacement for arbitrary OWL editing.  Its purpose is to govern the
common practice-artifact delta used by engineering ontology programmes while
leaving all RDF, SPARQL, snapshot, diff, provenance, and receipt semantics at
the single Semantica runtime boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import quote, urlsplit

from .lifecycle import DatasetDiffDTO, DatasetSnapshotDTO, canonical_json
from .runtime import (
    PackageExecutionReceiptDTO,
    ReleaseVerdictDTO,
    SemanticRuntime,
    SemanticRuntimeError,
)


GOVERNANCE_SCHEMA_VERSION = "1.0"
# Preserve the published domain-ontology-loop namespace so an existing CQ bank
# keeps addressing the same entities after the implementation moves into
# Semantica.  Code ownership changes; ontology identity must not.
DEFAULT_NAMESPACE = "https://w3id.org/domain-ontology-loop#"
_VERSION_DIRECTORY = re.compile(r"^v([0-9]{4,})$")
_HEX = frozenset("0123456789abcdef")


class OntologyGovernanceError(RuntimeError):
    """Base error for governed ontology workspaces."""


class GovernanceInputError(OntologyGovernanceError):
    """Raised when an ontology, delta, verdict, or CQ is malformed."""


class GovernanceWorkspaceError(OntologyGovernanceError):
    """Raised when workspace state is absent, busy, or fails integrity checks."""


class GovernanceWorkspaceExistsError(GovernanceWorkspaceError):
    """Raised when ``init`` would overwrite an existing workspace."""


class GovernanceGateError(OntologyGovernanceError):
    """Raised when a change lacks the mandatory conflict/removal decisions."""

    def __init__(self, violations: Sequence[str]) -> None:
        self.violations = tuple(str(item) for item in violations)
        super().__init__("; ".join(self.violations))


@dataclass(frozen=True)
class RuntimeSourceIdentityDTO:
    """Optional installed-source identity bound into a lifecycle receipt.

    Empty values are retained rather than invented.  Semantica's release
    verifier will consequently return ``blocked`` until a real source commit
    and artifact SHA-256 are supplied by the build/release caller.
    """

    runtime_commit: str = ""
    runtime_artifact_sha256: str = ""
    runtime_version: Optional[str] = None


@dataclass(frozen=True)
class GovernanceConflictDTO:
    """One same-name/different-meaning conflict."""

    entity_kind: str
    name: str
    old_comment: str
    new_comment: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "entity_kind": self.entity_kind,
            "name": self.name,
            "old_comment": self.old_comment,
            "new_comment": self.new_comment,
        }


@dataclass(frozen=True)
class GovernanceRemovalDTO:
    """One requested class/property removal."""

    entity_kind: str
    name: str

    def as_dict(self) -> Dict[str, str]:
        return {"entity_kind": self.entity_kind, "name": self.name}


@dataclass(frozen=True)
class GovernanceProposalDTO:
    """Deterministic, non-mutating delta analysis."""

    added_classes: Tuple[str, ...]
    added_properties: Tuple[str, ...]
    conflicts: Tuple[GovernanceConflictDTO, ...]
    removals: Tuple[GovernanceRemovalDTO, ...]
    unknown_removals: Tuple[str, ...]

    @property
    def requires_verdicts(self) -> bool:
        return bool(self.conflicts or self.removals or self.unknown_removals)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "added_classes": list(self.added_classes),
            "added_properties": list(self.added_properties),
            "conflicts": [item.as_dict() for item in self.conflicts],
            "removals": [item.as_dict() for item in self.removals],
            "unknown_removals": list(self.unknown_removals),
            "requires_verdicts": self.requires_verdicts,
        }


@dataclass(frozen=True)
class CompetencyQuestionResultDTO:
    """Backend-neutral result for one CQ regression check."""

    cq_id: str
    question: str
    passed: bool
    query_type: str
    observed: Optional[Union[bool, int]]
    expected: Optional[Union[bool, int]]
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "cq_id": self.cq_id,
            "question": self.question,
            "passed": self.passed,
            "query_type": self.query_type,
            "observed": self.observed,
            "expected": self.expected,
            "error": self.error,
        }


@dataclass(frozen=True)
class RegressionReportDTO:
    """Complete CQ-bank regression result for one ontology version."""

    status: str
    results: Tuple[CompetencyQuestionResultDTO, ...]

    def __post_init__(self) -> None:
        if self.status not in {"passed", "failed"}:
            raise ValueError("regression status must be passed or failed")
        expected = "passed" if all(item.passed for item in self.results) else "failed"
        if self.status != expected:
            raise ValueError("regression status does not match CQ results")

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    @property
    def passed_count(self) -> int:
        return sum(1 for item in self.results if item.passed)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "passed_count": self.passed_count,
            "total_count": len(self.results),
            "results": [item.as_dict() for item in self.results],
        }


@dataclass(frozen=True)
class GovernanceVersionDTO:
    """Verified immutable version descriptor."""

    version: int
    attempt: str
    recorded_at: str
    record_sha256: str
    parent_record_sha256: Optional[str]
    ontology_sha256: str
    dataset_sha256: str
    receipt_sha256: str
    release_status: str
    regression_status: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "attempt": self.attempt,
            "recorded_at": self.recorded_at,
            "record_sha256": self.record_sha256,
            "parent_record_sha256": self.parent_record_sha256,
            "ontology_sha256": self.ontology_sha256,
            "dataset_sha256": self.dataset_sha256,
            "receipt_sha256": self.receipt_sha256,
            "release_status": self.release_status,
            "regression_status": self.regression_status,
        }


@dataclass(frozen=True)
class GovernanceCommitDTO:
    """Result of publishing one governed ontology version."""

    version: GovernanceVersionDTO
    proposal: GovernanceProposalDTO
    semantic_diff: DatasetDiffDTO
    regression: RegressionReportDTO
    receipt: PackageExecutionReceiptDTO
    release: ReleaseVerdictDTO


def initialize_workspace(
    workspace: Union[str, os.PathLike],
    *,
    name: str,
    baseline: Optional[Union[Mapping[str, Any], str, os.PathLike]] = None,
    namespace: str = DEFAULT_NAMESPACE,
    attempt: str = "init",
    source_identity: Optional[RuntimeSourceIdentityDTO] = None,
    recorded_at: Optional[str] = None,
) -> GovernanceCommitDTO:
    """Create a new governed workspace without ever replacing an old one."""

    target = Path(workspace).expanduser().resolve()
    clean_name = _required_text(name, "name")
    clean_namespace = _validate_namespace(namespace)
    clean_attempt = _required_text(attempt, "attempt")
    baseline_value = _read_mapping_input(baseline, default={})
    normalized = _ontology_from_baseline(
        clean_name, clean_namespace, baseline_value, version=1
    )
    empty = {
        "name": clean_name,
        "namespace": clean_namespace,
        "version": 0,
        "classes": {},
        "properties": {},
    }
    delta = _normalize_delta(baseline_value)
    proposal = _analyze_delta(empty, delta)
    package_id = "semantica.governed-ontology.{}".format(
        _sha256_bytes(
            canonical_json({"name": clean_name, "namespace": clean_namespace}).encode(
                "utf-8"
            )
        )[:20]
    )

    target.parent.mkdir(parents=True, exist_ok=True)
    init_lock = target.parent / ".{}.semantica-init.lock".format(target.name)
    with _exclusive_lock(init_lock):
        if target.exists() or target.is_symlink():
            raise GovernanceWorkspaceExistsError(
                "workspace already exists; refusing to overwrite: {}".format(target)
            )
        stage = Path(
            tempfile.mkdtemp(
                prefix=".{}.semantica-init-".format(target.name), dir=str(target.parent)
            )
        )
        try:
            (stage / "versions").mkdir()
            (stage / "cq-bank").mkdir()
            _write_new(
                stage / "workspace.json",
                _json_bytes(
                    {
                        "schema_version": GOVERNANCE_SCHEMA_VERSION,
                        "name": clean_name,
                        "namespace": clean_namespace,
                        "package_id": package_id,
                    }
                ),
            )
            before_runtime = SemanticRuntime(profile="ontology-runtime")
            before_snapshot = before_runtime.snapshot(created_at=recorded_at)
            commit = _stage_and_publish_version(
                stage,
                ontology=normalized,
                delta=delta,
                verdicts={},
                proposal=proposal,
                parent_version=None,
                parent_snapshot=before_snapshot,
                attempt=clean_attempt,
                package_id=package_id,
                source_identity=source_identity or RuntimeSourceIdentityDTO(),
                recorded_at=recorded_at,
            )
            if target.exists() or target.is_symlink():
                raise GovernanceWorkspaceExistsError(
                    "workspace appeared during init; refusing to overwrite"
                )
            os.rename(str(stage), str(target))
            _fsync_directory(target.parent)
            return commit
        except Exception:
            if stage.exists():
                shutil.rmtree(str(stage))
            raise


def propose_change(
    workspace: Union[str, os.PathLike],
    delta: Union[Mapping[str, Any], str, os.PathLike],
) -> GovernanceProposalDTO:
    """Analyze a delta against the current verified workspace without writes."""

    root = _workspace_path(workspace)
    ontology, _, _ = _read_current_ontology(root)
    return _analyze_delta(ontology, _normalize_delta(_read_mapping_input(delta)))


def commit_change(
    workspace: Union[str, os.PathLike],
    delta: Union[Mapping[str, Any], str, os.PathLike],
    *,
    verdicts: Optional[Union[Mapping[str, Any], str, os.PathLike]] = None,
    attempt: str = "unnamed",
    source_identity: Optional[RuntimeSourceIdentityDTO] = None,
    recorded_at: Optional[str] = None,
) -> GovernanceCommitDTO:
    """Publish one immutable version after all governance decisions are valid.

    CQ regression is executed and bound into the receipt.  To preserve the
    separate ``commit``/``regress`` workflow, a failed CQ does not erase or
    hide the requested version; it makes that version's release verdict
    ``blocked`` and is returned explicitly to the caller.
    """

    root = _workspace_path(workspace)
    clean_attempt = _required_text(attempt, "attempt")
    normalized_delta = _normalize_delta(_read_mapping_input(delta))
    normalized_verdicts = _normalize_verdicts(_read_mapping_input(verdicts, default={}))
    with _exclusive_lock(root / ".governance.lock"):
        ontology, current, parent_version = _read_current_ontology(root)
        proposal = _analyze_delta(ontology, normalized_delta)
        violations = _verdict_violations(proposal, normalized_verdicts)
        if violations:
            raise GovernanceGateError(violations)
        candidate = _apply_delta(
            ontology, normalized_delta, normalized_verdicts, proposal
        )
        candidate["version"] = int(ontology["version"]) + 1
        workspace_manifest = _read_json(root / "workspace.json")
        parent_snapshot = _snapshot_from_dict(
            _read_json(
                root
                / "versions"
                / _version_name(parent_version.version)
                / "snapshot.json"
            )
        )
        return _stage_and_publish_version(
            root,
            ontology=candidate,
            delta=normalized_delta,
            verdicts=normalized_verdicts,
            proposal=proposal,
            parent_version=parent_version,
            parent_snapshot=parent_snapshot,
            attempt=clean_attempt,
            package_id=_required_text(
                workspace_manifest.get("package_id"), "package_id"
            ),
            source_identity=source_identity or RuntimeSourceIdentityDTO(),
            recorded_at=recorded_at,
        )


def regress_workspace(
    workspace: Union[str, os.PathLike],
) -> RegressionReportDTO:
    """Run the complete accumulated CQ bank against the current version."""

    root = _workspace_path(workspace)
    ontology, _, _ = _read_current_ontology(root)
    runtime, _ = _runtime_and_turtle(ontology)
    return _run_cq_bank(runtime, _load_cq_bank(root))


def history_workspace(
    workspace: Union[str, os.PathLike],
) -> Tuple[GovernanceVersionDTO, ...]:
    """Return the verified, unbroken immutable version chain."""

    root = _workspace_path(workspace)
    current = _read_json(root / "current.json")
    current_version = _required_positive_int(current.get("version"), "current.version")
    version_root = root / "versions"
    discovered = []
    for path in version_root.iterdir():
        match = _VERSION_DIRECTORY.match(path.name)
        if path.is_dir() and match:
            discovered.append(int(match.group(1)))
    expected = list(range(1, current_version + 1))
    if sorted(discovered) != expected:
        raise GovernanceWorkspaceError(
            "version chain has missing, duplicate, or unpublished directories"
        )

    result: List[GovernanceVersionDTO] = []
    expected_parent: Optional[str] = None
    for version in expected:
        record, record_hash = _load_version_record(root, version)
        if record.get("parent_record_sha256") != expected_parent:
            raise GovernanceWorkspaceError(
                "version {} parent hash breaks the history chain".format(version)
            )
        dto = _version_dto(record, record_hash)
        result.append(dto)
        expected_parent = record_hash
    if current.get("version_record_sha256") != result[-1].record_sha256:
        raise GovernanceWorkspaceError(
            "current pointer does not bind the latest version"
        )
    if current.get("version_dir") != "versions/{}".format(
        _version_name(current_version)
    ):
        raise GovernanceWorkspaceError("current pointer has an invalid version_dir")
    return tuple(result)


def _stage_and_publish_version(
    root: Path,
    *,
    ontology: Mapping[str, Any],
    delta: Mapping[str, Any],
    verdicts: Mapping[str, Any],
    proposal: GovernanceProposalDTO,
    parent_version: Optional[GovernanceVersionDTO],
    parent_snapshot: DatasetSnapshotDTO,
    attempt: str,
    package_id: str,
    source_identity: RuntimeSourceIdentityDTO,
    recorded_at: Optional[str],
) -> GovernanceCommitDTO:
    version = _required_positive_int(ontology.get("version"), "ontology.version")
    version_root = root / "versions"
    version_root.mkdir(exist_ok=True)
    final_dir = version_root / _version_name(version)
    if final_dir.exists() or final_dir.is_symlink():
        raise GovernanceWorkspaceError(
            "version already exists; refusing to overwrite: {}".format(final_dir.name)
        )
    stage = version_root / ".{}.staging-{}".format(
        _version_name(version), uuid.uuid4().hex
    )
    stage.mkdir()
    when = recorded_at or _utc_now()
    try:
        _, turtle = _runtime_and_turtle(ontology)
        cq_payload = _load_cq_bank(root)
        contract = {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "contract_id": "{}.{}".format(package_id, _version_name(version)),
            "package_id": package_id,
            "package_version": _version_name(version),
            "governance_semantics": "semantica.governed-ontology.v1",
            "attempt": attempt,
            "parent_dataset_sha256": parent_snapshot.dataset_sha256,
            "requires_reasoned_conflict_verdict": True,
            "requires_reasoned_removal_verdict": True,
            "cq_regression_required_for_release": True,
        }
        asset_payloads = {
            "ontology.json": _json_bytes(ontology),
            "ontology.ttl": turtle.encode("utf-8"),
            "chapter-contract.json": _json_bytes(contract),
            "delta.json": _json_bytes(delta),
            "verdicts.json": _json_bytes(verdicts),
            "cq-bank.json": _json_bytes(cq_payload),
        }
        for filename, payload in asset_payloads.items():
            _write_new(stage / filename, payload)

        manifest_assets = [
            _manifest_asset(
                "ontology",
                "ontology",
                "ontology.ttl",
                asset_payloads,
                format="turtle",
                kind="rdf",
                load=True,
            ),
            _manifest_asset(
                "governance-state", "governance_state", "ontology.json", asset_payloads
            ),
            _manifest_asset(
                "chapter-contract",
                "chapter_contract",
                "chapter-contract.json",
                asset_payloads,
            ),
            _manifest_asset(
                "change-delta", "change_delta", "delta.json", asset_payloads
            ),
            _manifest_asset(
                "governance-verdicts",
                "governance_verdicts",
                "verdicts.json",
                asset_payloads,
            ),
            _manifest_asset(
                "cq-bank", "competency_questions", "cq-bank.json", asset_payloads
            ),
        ]
        manifest = {
            "schema_version": "1.0",
            "package_id": package_id,
            "version": _version_name(version),
            "namespace": str(ontology["namespace"]),
            "assets": manifest_assets,
        }
        manifest_bytes = _json_bytes(manifest)
        _write_new(stage / "package-manifest.json", manifest_bytes)

        runtime = SemanticRuntime(profile="ontology-runtime")
        runtime.load_package(stage / "package-manifest.json")
        snapshot = runtime.snapshot(created_at=when)
        semantic_diff = runtime.diff(parent_snapshot, snapshot, created_at=when)
        regression = _run_cq_bank(runtime, cq_payload)
        cq_status = "passed" if regression.passed else "failed"
        cq_report = runtime.execution_report(
            "cq", regression.as_dict(), status=cq_status
        )
        shacl_report = runtime.execution_report(
            "shacl",
            {
                "applicable": False,
                "reason": "bounded governance contract declares no SHACL shapes",
            },
            status="passed",
        )
        oracle_report = runtime.execution_report(
            "oracle",
            {
                "oracle": "accumulated competency-question bank",
                "regression": regression.as_dict(),
            },
            status=cq_status,
        )
        snapshot_bytes = (snapshot.to_json() + "\n").encode("utf-8")
        diff_bytes = (semantic_diff.to_json() + "\n").encode("utf-8")
        output_hashes = {
            filename: _sha256_bytes(payload)
            for filename, payload in {
                **asset_payloads,
                "package-manifest.json": manifest_bytes,
                "snapshot.json": snapshot_bytes,
                "diff.json": diff_bytes,
            }.items()
        }
        receipt = runtime.create_execution_receipt(
            package_id,
            _version_name(version),
            runtime_commit=source_identity.runtime_commit,
            runtime_artifact_sha256=source_identity.runtime_artifact_sha256,
            runtime_version=source_identity.runtime_version,
            required_capabilities=(
                "rdf.dataset.load",
                "rdf.dataset.snapshot",
                "rdf.dataset.diff",
                "sparql.select",
                "sparql.ask",
                "semantic.package.receipt",
                "provenance.bundle",
                "semantic.release.verify",
            ),
            cq_report=cq_report,
            shacl_report=shacl_report,
            oracle_report=oracle_report,
            output_hashes=output_hashes,
            created_at=when,
        )
        release = runtime.verify_release(receipt, checked_at=when)
        evidence_payloads = {
            "snapshot.json": snapshot_bytes,
            "diff.json": diff_bytes,
            "regression.json": _json_bytes(regression.as_dict()),
            "receipt.json": (receipt.to_json() + "\n").encode("utf-8"),
            "provenance.json": (receipt.provenance_bundle.to_json() + "\n").encode(
                "utf-8"
            ),
            "release.json": (release.to_json() + "\n").encode("utf-8"),
        }
        for filename, payload in evidence_payloads.items():
            _write_new(stage / filename, payload)

        parent_hash = parent_version.record_sha256 if parent_version else None
        all_payloads = {
            **asset_payloads,
            "package-manifest.json": manifest_bytes,
            **evidence_payloads,
        }
        record = {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "version": version,
            "attempt": attempt,
            "recorded_at": when,
            "parent_record_sha256": parent_hash,
            "ontology_sha256": _sha256_bytes(asset_payloads["ontology.json"]),
            "dataset_sha256": snapshot.dataset_sha256,
            "receipt_sha256": receipt.receipt_sha256,
            "release_status": release.status,
            "regression_status": regression.status,
            "proposal": proposal.as_dict(),
            "files": {
                name: _sha256_bytes(payload)
                for name, payload in sorted(all_payloads.items())
            },
        }
        record_bytes = _json_bytes(record)
        _write_new(stage / "version.json", record_bytes)
        record_hash = _sha256_bytes(record_bytes)
        _fsync_directory(stage)
        if final_dir.exists() or final_dir.is_symlink():
            raise GovernanceWorkspaceError("version target appeared during commit")
        os.rename(str(stage), str(final_dir))
        _fsync_directory(version_root)
        current = {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "version": version,
            "version_dir": "versions/{}".format(_version_name(version)),
            "version_record_sha256": record_hash,
        }
        _atomic_replace(root / "current.json", _json_bytes(current))
        dto = _version_dto(record, record_hash)
        return GovernanceCommitDTO(
            version=dto,
            proposal=proposal,
            semantic_diff=semantic_diff,
            regression=regression,
            receipt=receipt,
            release=release,
        )
    except Exception:
        if stage.exists():
            shutil.rmtree(str(stage))
        raise


def _runtime_and_turtle(ontology: Mapping[str, Any]) -> Tuple[SemanticRuntime, str]:
    statements = []
    namespace = _validate_namespace(ontology.get("namespace"))
    for kind, rdf_type in (
        ("classes", "http://www.w3.org/2002/07/owl#Class"),
        ("properties", "http://www.w3.org/2002/07/owl#ObjectProperty"),
    ):
        entities = ontology.get(kind)
        if not isinstance(entities, Mapping):
            raise GovernanceInputError("ontology.{} must be a mapping".format(kind))
        for name in sorted(entities):
            metadata = entities[name]
            if not isinstance(metadata, Mapping):
                raise GovernanceInputError("ontology entity metadata must be a mapping")
            iri = "{}{}".format(namespace, quote(str(name), safe="-._~"))
            statements.append(
                "<{}> a <{}> ; <http://www.w3.org/2000/01/rdf-schema#label> {} .".format(
                    iri, rdf_type, _turtle_string(str(name))
                )
            )
            comment = str(metadata.get("comment", ""))
            if comment:
                statements.append(
                    "<{}> <http://www.w3.org/2000/01/rdf-schema#comment> {} .".format(
                        iri, _turtle_string(comment)
                    )
                )
    source = "\n".join(statements) + ("\n" if statements else "")
    runtime = SemanticRuntime(profile="ontology-runtime")
    runtime.load(source, format="turtle", base_uri=namespace)
    # Do not ask the serializer to relativize against a fragment namespace.
    # RFC IRI resolution would turn ``#A`` into a sibling path when that
    # relative Turtle is parsed again.  Absolute output keeps package reloads
    # semantically identical for both ``#`` and ``/`` namespaces.
    return runtime, runtime.serialize(format="turtle")


def _run_cq_bank(
    runtime: SemanticRuntime, cq_payload: Sequence[Mapping[str, Any]]
) -> RegressionReportDTO:
    results: List[CompetencyQuestionResultDTO] = []
    for raw in cq_payload:
        cq_id = str(raw.get("id", "")).strip()
        question = str(raw.get("question", "")).strip()
        sparql = raw.get("sparql")
        ask = raw.get("ask", False)
        if (
            not cq_id
            or not question
            or not isinstance(sparql, str)
            or not sparql.strip()
        ):
            results.append(
                CompetencyQuestionResultDTO(
                    cq_id=cq_id or "<missing>",
                    question=question,
                    passed=False,
                    query_type="invalid",
                    observed=None,
                    expected=None,
                    error="CQ requires non-empty id, question, and sparql",
                )
            )
            continue
        try:
            if ask is True:
                observed: Union[bool, int] = runtime.ask(sparql).boolean
                expected_bool = raw.get("expected", True)
                if not isinstance(expected_bool, bool):
                    raise GovernanceInputError("ASK CQ expected must be boolean")
                passed = observed is expected_bool
                result = CompetencyQuestionResultDTO(
                    cq_id=cq_id,
                    question=question,
                    passed=passed,
                    query_type="ASK",
                    observed=observed,
                    expected=expected_bool,
                )
            elif ask is False:
                min_rows = raw.get("min_rows", 1)
                if (
                    not isinstance(min_rows, int)
                    or isinstance(min_rows, bool)
                    or min_rows < 0
                ):
                    raise GovernanceInputError(
                        "SELECT CQ min_rows must be non-negative integer"
                    )
                observed = len(runtime.select(sparql).rows)
                result = CompetencyQuestionResultDTO(
                    cq_id=cq_id,
                    question=question,
                    passed=observed >= min_rows,
                    query_type="SELECT",
                    observed=observed,
                    expected=min_rows,
                )
            else:
                raise GovernanceInputError("CQ ask field must be boolean")
        except (SemanticRuntimeError, GovernanceInputError) as exc:
            result = CompetencyQuestionResultDTO(
                cq_id=cq_id,
                question=question,
                passed=False,
                query_type="ASK" if ask is True else "SELECT",
                observed=None,
                expected=None,
                error=str(exc),
            )
        results.append(result)
    frozen = tuple(results)
    return RegressionReportDTO(
        status="passed" if all(item.passed for item in frozen) else "failed",
        results=frozen,
    )


def _load_cq_bank(root: Path) -> Tuple[Mapping[str, Any], ...]:
    bank = root / "cq-bank"
    if not bank.is_dir():
        raise GovernanceWorkspaceError("workspace cq-bank directory is missing")
    values: List[Mapping[str, Any]] = []
    ids = set()
    for path in sorted(bank.glob("*.json"), key=lambda item: item.name):
        value = _read_json(path)
        cq_id = str(value.get("id", "")).strip()
        if cq_id and cq_id in ids:
            raise GovernanceInputError("duplicate CQ id: {}".format(cq_id))
        if cq_id:
            ids.add(cq_id)
        values.append(value)
    return tuple(values)


def _analyze_delta(
    ontology: Mapping[str, Any], delta: Mapping[str, Any]
) -> GovernanceProposalDTO:
    added_classes: List[str] = []
    added_properties: List[str] = []
    conflicts: List[GovernanceConflictDTO] = []
    for plural, singular, added in (
        ("classes", "class", added_classes),
        ("properties", "property", added_properties),
    ):
        existing = ontology.get(plural, {})
        for item in delta.get(plural, ()):
            name = item["name"]
            old = existing.get(name)
            if old is None:
                added.append(name)
            else:
                old_comment = str(old.get("comment", ""))
                new_comment = str(item.get("comment", ""))
                if new_comment and old_comment and new_comment != old_comment:
                    conflicts.append(
                        GovernanceConflictDTO(
                            entity_kind=singular,
                            name=name,
                            old_comment=old_comment,
                            new_comment=new_comment,
                        )
                    )
    removals: List[GovernanceRemovalDTO] = []
    unknown: List[str] = []
    for name in delta.get("removes", ()):
        if name in ontology.get("classes", {}):
            removals.append(GovernanceRemovalDTO("class", name))
        elif name in ontology.get("properties", {}):
            removals.append(GovernanceRemovalDTO("property", name))
        else:
            unknown.append(name)
    return GovernanceProposalDTO(
        added_classes=tuple(sorted(added_classes)),
        added_properties=tuple(sorted(added_properties)),
        conflicts=tuple(
            sorted(conflicts, key=lambda item: (item.entity_kind, item.name))
        ),
        removals=tuple(
            sorted(removals, key=lambda item: (item.entity_kind, item.name))
        ),
        unknown_removals=tuple(sorted(unknown)),
    )


def _verdict_violations(
    proposal: GovernanceProposalDTO, verdicts: Mapping[str, Mapping[str, str]]
) -> Tuple[str, ...]:
    violations = []
    required_names = {item.name for item in proposal.conflicts} | {
        item.name for item in proposal.removals
    }
    for conflict in proposal.conflicts:
        verdict = verdicts.get(conflict.name)
        if verdict is None or verdict.get("action") not in {
            "replace",
            "keep_old",
            "merge",
        }:
            violations.append(
                "conflict {} requires replace/keep_old/merge verdict".format(
                    conflict.name
                )
            )
        elif not verdict.get("reason", "").strip():
            violations.append(
                "conflict {} verdict requires a reason".format(conflict.name)
            )
    for removal in proposal.removals:
        verdict = verdicts.get(removal.name)
        if verdict is None or not verdict.get("reason", "").strip():
            violations.append("removal {} requires a reason".format(removal.name))
        elif verdict.get("action") not in {None, "", "remove"}:
            violations.append(
                "removal {} action must be remove or omitted".format(removal.name)
            )
    for name in proposal.unknown_removals:
        violations.append("cannot remove unknown ontology entity: {}".format(name))
    for name in sorted(set(verdicts) - required_names):
        violations.append(
            "verdict does not match a reported conflict or removal: {}".format(name)
        )
    return tuple(violations)


def _apply_delta(
    ontology: Mapping[str, Any],
    delta: Mapping[str, Any],
    verdicts: Mapping[str, Mapping[str, str]],
    proposal: GovernanceProposalDTO,
) -> Dict[str, Any]:
    candidate = json.loads(canonical_json(ontology))
    conflict_keys = {(item.entity_kind, item.name) for item in proposal.conflicts}
    for plural, singular in (("classes", "class"), ("properties", "property")):
        for item in delta.get(plural, ()):
            name = item["name"]
            old = candidate[plural].get(name)
            if old is None:
                candidate[plural][name] = _entity_metadata(item)
                continue
            if (singular, name) not in conflict_keys:
                # Filling a previously empty description is monotonic
                # enrichment, not a same-name/different-meaning conflict.
                if not old.get("comment") and item.get("comment"):
                    old["comment"] = item["comment"]
                if "source" in item and "source" not in old:
                    old["source"] = json.loads(canonical_json(item["source"]))
                continue
            verdict = verdicts[name]
            action = verdict["action"]
            if action == "keep_old":
                continue
            replacement = _entity_metadata(item)
            if action == "merge":
                old_comment = str(old.get("comment", ""))
                new_comment = str(replacement.get("comment", ""))
                replacement["comment"] = (
                    old_comment
                    if not new_comment or new_comment == old_comment
                    else old_comment + "；" + new_comment
                )
            replacement["verdict"] = {
                "action": action,
                "reason": verdict["reason"],
            }
            candidate[plural][name] = replacement
    for removal in proposal.removals:
        plural = "classes" if removal.entity_kind == "class" else "properties"
        candidate[plural].pop(removal.name)
    overlap = sorted(set(candidate["classes"]) & set(candidate["properties"]))
    if overlap:
        raise GovernanceInputError(
            "change creates class/property name collisions: {}".format(
                ", ".join(overlap)
            )
        )
    return candidate


def _ontology_from_baseline(
    name: str, namespace: str, baseline: Mapping[str, Any], *, version: int
) -> Dict[str, Any]:
    delta = _normalize_delta(baseline)
    classes = {item["name"]: _entity_metadata(item) for item in delta["classes"]}
    properties = {item["name"]: _entity_metadata(item) for item in delta["properties"]}
    overlap = sorted(set(classes) & set(properties))
    if overlap:
        raise GovernanceInputError(
            "class/property names collide and make verdict keys ambiguous: {}".format(
                ", ".join(overlap)
            )
        )
    return {
        "name": name,
        "namespace": namespace,
        "version": version,
        "classes": classes,
        "properties": properties,
    }


def _normalize_delta(value: Mapping[str, Any]) -> Dict[str, Any]:
    allowed = {"classes", "properties", "removes", "source"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise GovernanceInputError(
            "delta has unsupported fields: {}".format(", ".join(unknown))
        )
    result: Dict[str, Any] = {"classes": [], "properties": [], "removes": []}
    names = set()
    for plural in ("classes", "properties"):
        raw_items = value.get(plural, [])
        if not isinstance(raw_items, list):
            raise GovernanceInputError("delta.{} must be a list".format(plural))
        normalized = []
        for raw in raw_items:
            if not isinstance(raw, Mapping):
                raise GovernanceInputError("delta entities must be mappings")
            item = _normalize_entity(raw)
            key = (plural, item["name"])
            if key in names:
                raise GovernanceInputError(
                    "delta contains duplicate {} {}".format(plural, item["name"])
                )
            names.add(key)
            normalized.append(item)
        result[plural] = normalized
    overlap = sorted(
        {item["name"] for item in result["classes"]}
        & {item["name"] for item in result["properties"]}
    )
    if overlap:
        raise GovernanceInputError(
            "delta class/property names collide: {}".format(", ".join(overlap))
        )
    removes = value.get("removes", [])
    if not isinstance(removes, list):
        raise GovernanceInputError("delta.removes must be a list")
    normalized_removes = []
    for raw in removes:
        name = _required_text(raw, "remove name")
        if name in normalized_removes:
            raise GovernanceInputError(
                "delta contains duplicate removal {}".format(name)
            )
        normalized_removes.append(name)
    result["removes"] = normalized_removes
    changed_names = {item["name"] for item in result["classes"] + result["properties"]}
    contradictory = sorted(changed_names & set(normalized_removes))
    if contradictory:
        raise GovernanceInputError(
            "delta cannot add/change and remove the same entities: {}".format(
                ", ".join(contradictory)
            )
        )
    if "source" in value:
        source = value["source"]
        if not isinstance(source, Mapping):
            raise GovernanceInputError("delta.source must be a mapping")
        # Round-trip through canonical JSON to reject non-JSON or ambiguous keys.
        result["source"] = json.loads(canonical_json(source))
    return result


def _normalize_entity(raw: Mapping[str, Any]) -> Dict[str, Any]:
    unknown = sorted(set(raw) - {"name", "comment", "source"})
    if unknown:
        raise GovernanceInputError(
            "ontology entity has unsupported fields: {}".format(", ".join(unknown))
        )
    name = _required_text(raw.get("name"), "entity name")
    comment = raw.get("comment", "")
    if not isinstance(comment, str):
        raise GovernanceInputError("entity comment must be text")
    result: Dict[str, Any] = {"name": name, "comment": comment}
    if "source" in raw:
        if not isinstance(raw["source"], Mapping):
            raise GovernanceInputError("entity source must be a mapping")
        result["source"] = json.loads(canonical_json(raw["source"]))
    return result


def _entity_metadata(item: Mapping[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {"comment": str(item.get("comment", ""))}
    if "source" in item:
        result["source"] = json.loads(canonical_json(item["source"]))
    return result


def _normalize_verdicts(value: Mapping[str, Any]) -> Dict[str, Dict[str, str]]:
    result = {}
    for raw_name, raw in value.items():
        name = _required_text(raw_name, "verdict entity name")
        if not isinstance(raw, Mapping):
            raise GovernanceInputError("verdict for {} must be a mapping".format(name))
        unknown = sorted(set(raw) - {"action", "reason"})
        if unknown:
            raise GovernanceInputError(
                "verdict for {} has unsupported fields: {}".format(
                    name, ", ".join(unknown)
                )
            )
        action = raw.get("action", "")
        reason = raw.get("reason", "")
        if not isinstance(action, str) or not isinstance(reason, str):
            raise GovernanceInputError("verdict action/reason must be text")
        result[name] = {"action": action.strip(), "reason": reason.strip()}
    return result


def _read_current_ontology(
    root: Path,
) -> Tuple[Dict[str, Any], Mapping[str, Any], GovernanceVersionDTO]:
    current = _read_json(root / "current.json")
    if current.get("schema_version") != GOVERNANCE_SCHEMA_VERSION:
        raise GovernanceWorkspaceError("unsupported current pointer schema")
    version = _required_positive_int(current.get("version"), "current.version")
    record, record_hash = _load_version_record(root, version)
    if current.get("version_record_sha256") != record_hash:
        raise GovernanceWorkspaceError("current pointer version hash mismatch")
    expected_dir = "versions/{}".format(_version_name(version))
    if current.get("version_dir") != expected_dir:
        raise GovernanceWorkspaceError("current pointer version_dir mismatch")
    ontology_path = root / expected_dir / "ontology.json"
    ontology = dict(_read_json(ontology_path))
    if ontology.get("version") != version:
        raise GovernanceWorkspaceError("ontology version differs from current pointer")
    _validate_namespace(ontology.get("namespace"))
    return ontology, current, _version_dto(record, record_hash)


def _load_version_record(root: Path, version: int) -> Tuple[Mapping[str, Any], str]:
    directory = root / "versions" / _version_name(version)
    record_path = directory / "version.json"
    record_bytes = _read_bytes(record_path)
    record = _read_json_bytes(record_bytes, record_path)
    if record.get("schema_version") != GOVERNANCE_SCHEMA_VERSION:
        raise GovernanceWorkspaceError("unsupported version record schema")
    if record.get("version") != version:
        raise GovernanceWorkspaceError("version record number mismatch")
    files = record.get("files")
    if not isinstance(files, Mapping) or not files:
        raise GovernanceWorkspaceError("version record file ledger is missing")
    for filename, expected in files.items():
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise GovernanceWorkspaceError("version record contains unsafe filename")
        if not _is_sha256(expected):
            raise GovernanceWorkspaceError("version record contains invalid file hash")
        actual = _sha256_bytes(_read_bytes(directory / filename))
        if actual != expected:
            raise GovernanceWorkspaceError(
                "version {} file hash mismatch: {}".format(version, filename)
            )
    return record, _sha256_bytes(record_bytes)


def _version_dto(record: Mapping[str, Any], record_hash: str) -> GovernanceVersionDTO:
    return GovernanceVersionDTO(
        version=_required_positive_int(record.get("version"), "record.version"),
        attempt=_required_text(record.get("attempt"), "record.attempt"),
        recorded_at=_required_text(record.get("recorded_at"), "record.recorded_at"),
        record_sha256=record_hash,
        parent_record_sha256=(
            str(record["parent_record_sha256"])
            if record.get("parent_record_sha256") is not None
            else None
        ),
        ontology_sha256=_required_digest(
            record.get("ontology_sha256"), "ontology_sha256"
        ),
        dataset_sha256=_required_digest(record.get("dataset_sha256"), "dataset_sha256"),
        receipt_sha256=_required_digest(record.get("receipt_sha256"), "receipt_sha256"),
        release_status=_required_text(record.get("release_status"), "release_status"),
        regression_status=_required_text(
            record.get("regression_status"), "regression_status"
        ),
    )


def _snapshot_from_dict(value: Mapping[str, Any]) -> DatasetSnapshotDTO:
    try:
        snapshot = DatasetSnapshotDTO(
            dataset_sha256=str(value["dataset_sha256"]),
            quad_count=int(value["quad_count"]),
            canonical_nquads=str(value["canonical_nquads"]),
            revision=int(value["revision"]),
            created_at=str(value["created_at"]),
            algorithm=str(value["algorithm"]),
            schema_version=str(value["schema_version"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise GovernanceWorkspaceError("saved dataset snapshot is invalid") from exc
    if not snapshot.verify_integrity():
        raise GovernanceWorkspaceError("saved dataset snapshot fails integrity")
    return snapshot


def _manifest_asset(
    asset_id: str,
    role: str,
    filename: str,
    payloads: Mapping[str, bytes],
    *,
    format: Optional[str] = None,
    kind: Optional[str] = None,
    load: bool = False,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "asset_id": asset_id,
        "role": role,
        "path": filename,
        "sha256": _sha256_bytes(payloads[filename]),
        "load_into_dataset": load,
    }
    if format is not None:
        result["format"] = format
    if kind is not None:
        result["kind"] = kind
    return result


def _read_mapping_input(
    value: Optional[Union[Mapping[str, Any], str, os.PathLike]],
    *,
    default: Optional[Mapping[str, Any]] = None,
) -> Mapping[str, Any]:
    if value is None:
        if default is None:
            raise GovernanceInputError("required JSON mapping input is missing")
        return default
    if isinstance(value, Mapping):
        return value
    return _read_json(Path(value).expanduser().resolve())


def _read_json(path: Path) -> Mapping[str, Any]:
    return _read_json_bytes(_read_bytes(path), path)


def _read_json_bytes(payload: bytes, path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise GovernanceInputError("invalid JSON file: {}".format(path)) from exc
    if not isinstance(value, Mapping):
        raise GovernanceInputError("JSON root must be a mapping: {}".format(path))
    return value


def _read_bytes(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise GovernanceWorkspaceError(
                "required regular file is missing: {}".format(path)
            )
        return path.read_bytes()
    except OntologyGovernanceError:
        raise
    except OSError as exc:
        raise GovernanceWorkspaceError("failed to read {}".format(path)) from exc


def _workspace_path(workspace: Union[str, os.PathLike]) -> Path:
    root = Path(workspace).expanduser().resolve()
    if root.is_symlink() or not root.is_dir():
        raise GovernanceWorkspaceError(
            "workspace is not a regular directory: {}".format(root)
        )
    manifest = _read_json(root / "workspace.json")
    if manifest.get("schema_version") != GOVERNANCE_SCHEMA_VERSION:
        raise GovernanceWorkspaceError("unsupported or incomplete governance workspace")
    return root


def _json_bytes(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise GovernanceWorkspaceError(
            "refusing to overwrite existing file: {}".format(path)
        ) from exc


def _atomic_replace(path: Path, payload: bytes) -> None:
    temporary = path.parent / ".{}.tmp-{}".format(path.name, uuid.uuid4().hex)
    try:
        _write_new(temporary, payload)
        os.replace(str(temporary), str(path))
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextmanager
def _exclusive_lock(path: Path) -> Iterable[None]:
    try:
        descriptor = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise GovernanceWorkspaceError(
            "governance workspace is busy or has a stale lock: {}".format(path)
        ) from exc
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        yield
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        # Some platforms/filesystems do not support directory fsync.  File
        # fsync and atomic rename still preserve the publication protocol.
        pass


def _version_name(version: int) -> str:
    return "v{:04d}".format(version)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _required_digest(value: Any, field: str) -> str:
    if not _is_sha256(value):
        raise GovernanceWorkspaceError("{} must be a SHA-256 digest".format(field))
    return str(value)


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceInputError("{} must be non-empty text".format(field))
    return value.strip()


def _required_positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise GovernanceWorkspaceError("{} must be a positive integer".format(field))
    return value


def _validate_namespace(value: Any) -> str:
    namespace = _required_text(value, "namespace")
    parsed = urlsplit(namespace)
    if parsed.scheme not in {"http", "https", "urn"}:
        raise GovernanceInputError("namespace must be an absolute HTTP(S) or URN IRI")
    return namespace


def _turtle_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _source_identity_from_args(args: argparse.Namespace) -> RuntimeSourceIdentityDTO:
    return RuntimeSourceIdentityDTO(
        runtime_commit=str(getattr(args, "runtime_commit", "") or ""),
        runtime_artifact_sha256=str(getattr(args, "runtime_artifact_sha256", "") or ""),
        runtime_version=getattr(args, "runtime_version", None),
    )


def _add_source_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime-commit")
    parser.add_argument("--runtime-artifact-sha256")
    parser.add_argument("--runtime-version")


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the standalone governance CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("init")
    command.add_argument("--workspace", required=True)
    command.add_argument("--name", required=True)
    command.add_argument("--baseline")
    command.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    command.add_argument("--attempt", default="init")
    _add_source_identity_arguments(command)

    command = commands.add_parser("propose")
    command.add_argument("--workspace", required=True)
    command.add_argument("--delta", required=True)

    command = commands.add_parser("commit")
    command.add_argument("--workspace", required=True)
    command.add_argument("--delta", required=True)
    command.add_argument("--verdicts")
    command.add_argument("--attempt", default="unnamed")
    _add_source_identity_arguments(command)

    command = commands.add_parser("regress")
    command.add_argument("--workspace", required=True)

    command = commands.add_parser("history")
    command.add_argument("--workspace", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the standalone ``python -m semantica.ontology.governance`` CLI."""

    args = build_argument_parser().parse_args(argv)
    try:
        if args.command == "init":
            result = initialize_workspace(
                args.workspace,
                name=args.name,
                baseline=args.baseline,
                namespace=args.namespace,
                attempt=args.attempt,
                source_identity=_source_identity_from_args(args),
            )
            print(canonical_json(result.version.as_dict()))
            return 0
        if args.command == "propose":
            result = propose_change(args.workspace, args.delta)
            print(canonical_json(result.as_dict()))
            return 2 if result.requires_verdicts else 0
        if args.command == "commit":
            result = commit_change(
                args.workspace,
                args.delta,
                verdicts=args.verdicts,
                attempt=args.attempt,
                source_identity=_source_identity_from_args(args),
            )
            print(canonical_json(result.version.as_dict()))
            return 0
        if args.command == "regress":
            result = regress_workspace(args.workspace)
            print(canonical_json(result.as_dict()))
            return 0 if result.passed else 1
        for item in history_workspace(args.workspace):
            print(canonical_json(item.as_dict()))
        return 0
    except GovernanceGateError as exc:
        print(canonical_json({"status": "blocked", "violations": exc.violations}))
        return 1
    except OntologyGovernanceError as exc:
        print(str(exc), file=sys.stderr)
        return 1


__all__ = [
    "CompetencyQuestionResultDTO",
    "DEFAULT_NAMESPACE",
    "GOVERNANCE_SCHEMA_VERSION",
    "GovernanceCommitDTO",
    "GovernanceConflictDTO",
    "GovernanceGateError",
    "GovernanceInputError",
    "GovernanceProposalDTO",
    "GovernanceRemovalDTO",
    "GovernanceVersionDTO",
    "GovernanceWorkspaceError",
    "GovernanceWorkspaceExistsError",
    "OntologyGovernanceError",
    "RegressionReportDTO",
    "RuntimeSourceIdentityDTO",
    "build_argument_parser",
    "commit_change",
    "history_workspace",
    "initialize_workspace",
    "main",
    "propose_change",
    "regress_workspace",
]


if __name__ == "__main__":
    raise SystemExit(main())
