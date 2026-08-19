"""Fail-closed execution of built-in semantic chapter packages.

``SemanticPackageRunner`` is the execution boundary for the declarative
chapter-package contracts bundled with Semantica.  It understands both the
Vol.1 YAML registries and the Vol.2 JSON registries, but it only executes
operations that have an exact, public :class:`~semantica.ontology.runtime.SemanticRuntime`
contract.  Unsupported prose workflows, SWRL, and description-logic profiles
remain explicit ``blocked`` evidence.

No RDFLib, PySHACL, or reasoning-engine object crosses this module's public
API.  Every returned value is a frozen DTO containing canonical JSON-compatible
data, content hashes, lifecycle reports, and (when the package could be
registered) a provenance-bound execution receipt.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import yaml

from semantica.ontology.lifecycle import canonical_json, sha256_text, utc_now
from semantica.ontology.runtime import (
    AskResultDTO,
    ExecutionReportDTO,
    ForwardChainResultDTO,
    PackageExecutionReceiptDTO,
    PackageLoadResultDTO,
    ReleaseCheckDTO,
    ReleaseVerdictDTO,
    SelectResultDTO,
    SemanticPackageAssetDTO,
    SemanticRuntime,
    ValidationReportDTO,
)

from . import (
    ChapterPackageNotFoundError,
    get_chapter_package,
    get_domain_package,
    list_chapter_packages,
    list_domain_packages,
)

RUNNER_CONTRACT = "semantica.chapter_packages.SemanticPackageRunner/v1"
RUNNER_SCHEMA_VERSION = "1.0"

_STATUSES = frozenset({"passed", "failed", "blocked"})
_RDF_FORMATS = frozenset(
    {
        "turtle",
        "ttl",
        "nt",
        "ntriples",
        "n-triples",
        "xml",
        "rdfxml",
        "rdf/xml",
        "json-ld",
        "jsonld",
        "json_ld",
        "trig",
        "nq",
        "nquads",
        "n-quads",
        "trix",
    }
)

_CAP_PACKAGE_LOAD = "semantic.package.load"
_CAP_RDF_LOAD = "rdf.dataset.load"
_CAP_SELECT = "sparql.select"
_CAP_ASK = "sparql.ask"
_CAP_SHACL = "shacl.validate"
_CAP_REASON = "rule.forward_chain"
_CAP_SNAPSHOT = "rdf.dataset.snapshot"
_CAP_RECEIPT = "semantic.package.receipt"
_CAP_PROVENANCE = "provenance.bundle"
_CAP_RELEASE = "semantic.release.verify"


@dataclass(frozen=True)
class PackageOperationReportDTO:
    """One normalized package operation and its content-bound output."""

    operation_id: str
    operation: str
    status: str
    payload_json: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.operation_id.strip() or not self.operation.strip():
            raise ValueError("operation_id and operation must be non-empty")
        if self.status not in _STATUSES:
            raise ValueError("operation status must be passed, failed, or blocked")
        if canonical_json(json.loads(self.payload_json)) != self.payload_json:
            raise ValueError("operation payload_json must be canonical JSON")
        if self.sha256 != sha256_text(
            canonical_json(
                {
                    "operation_id": self.operation_id,
                    "operation": self.operation,
                    "status": self.status,
                    "payload": self.payload,
                }
            )
        ):
            raise ValueError("operation sha256 does not match its content")

    @property
    def payload(self) -> Any:
        return json.loads(self.payload_json)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation": self.operation,
            "status": self.status,
            "payload": self.payload,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class OracleCheckDTO:
    """One exact comparison against a declared scenario oracle."""

    check_id: str
    status: str
    expected_json: str
    actual_json: str
    message: str

    def __post_init__(self) -> None:
        if not self.check_id.strip():
            raise ValueError("oracle check_id must be non-empty")
        if self.status not in _STATUSES:
            raise ValueError("oracle status must be passed, failed, or blocked")
        if canonical_json(json.loads(self.expected_json)) != self.expected_json:
            raise ValueError("oracle expected_json must be canonical JSON")
        if canonical_json(json.loads(self.actual_json)) != self.actual_json:
            raise ValueError("oracle actual_json must be canonical JSON")

    @property
    def expected(self) -> Any:
        return json.loads(self.expected_json)

    @property
    def actual(self) -> Any:
        return json.loads(self.actual_json)

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": self.status,
            "expected": self.expected,
            "actual": self.actual,
            "message": self.message,
        }


@dataclass(frozen=True)
class SemanticPackageRunResultDTO:
    """Complete pure-data evidence for one scenario execution."""

    package_id: str
    package_version: str
    package_digest: str
    scenario_id: str
    status: str
    created_at: str
    operations: Tuple[PackageOperationReportDTO, ...]
    oracle_checks: Tuple[OracleCheckDTO, ...]
    capability_report: ExecutionReportDTO
    cq_report: ExecutionReportDTO
    shacl_report: ExecutionReportDTO
    oracle_report: ExecutionReportDTO
    receipt: Optional[PackageExecutionReceiptDTO]
    release_verdict: ReleaseVerdictDTO
    reasons: Tuple[str, ...]
    runner_contract: str = RUNNER_CONTRACT
    schema_version: str = RUNNER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ValueError("run status must be passed, failed, or blocked")
        if self.runner_contract != RUNNER_CONTRACT:
            raise ValueError("unsupported runner contract")
        if self.schema_version != RUNNER_SCHEMA_VERSION:
            raise ValueError("unsupported runner result schema")
        if self.receipt is not None:
            if self.receipt.package_id != self.package_id:
                raise ValueError("receipt package_id differs from run result")
            if self.receipt.package_version != self.package_version:
                raise ValueError("receipt package_version differs from run result")
            if self.receipt.package_digest != self.package_digest:
                raise ValueError("receipt package_digest differs from run result")

    @property
    def release_complete(self) -> bool:
        return self.release_verdict.complete

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "runner_contract": self.runner_contract,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "package_digest": self.package_digest,
            "scenario_id": self.scenario_id,
            "status": self.status,
            "created_at": self.created_at,
            "operations": [item.as_dict() for item in self.operations],
            "oracle_checks": [item.as_dict() for item in self.oracle_checks],
            "capability_report": self.capability_report.as_dict(),
            "cq_report": self.cq_report.as_dict(),
            "shacl_report": self.shacl_report.as_dict(),
            "oracle_report": self.oracle_report.as_dict(),
            "receipt": self.receipt.as_dict() if self.receipt is not None else None,
            "release_verdict": self.release_verdict.as_dict(),
            "reasons": list(self.reasons),
        }

    def to_json(self) -> str:
        return canonical_json(self.as_dict())


class _BlockedOperation(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = str(code)
        self.message = str(message)


@dataclass
class _StepOutcome:
    operation: str
    value: Any
    report: PackageOperationReportDTO


@dataclass
class _ExecutionState:
    runtime: SemanticRuntime
    loaded: PackageLoadResultDTO
    manifest: Mapping[str, Any]
    manifest_source: Union[Mapping[str, Any], Path]
    base_path: Optional[Path]
    operations: List[PackageOperationReportDTO]
    outcomes: Dict[str, List[_StepOutcome]]
    required_capabilities: set


class SemanticPackageRunner:
    """Execute one built-in package scenario through ``SemanticRuntime`` only.

    ``runtime`` is treated as a profile/backend template.  Each run receives a
    fresh runtime so chapter scenarios cannot contaminate one another.  The
    exact runtime used for a returned receipt is retained by this runner for a
    later :meth:`verify` call.
    """

    def __init__(self, runtime: Optional[SemanticRuntime] = None) -> None:
        template = runtime or SemanticRuntime(
            profile="ontology-runtime", backend="rdflib"
        )
        if not isinstance(template, SemanticRuntime):
            raise TypeError("runtime must be a SemanticRuntime")
        self._profile_name = template.profile.name
        self._backend_name = template.profile.backend
        self._receipt_contexts: Dict[str, Tuple[SemanticRuntime, str, str]] = {}

    def run(
        self,
        package_id: str,
        scenario_id: Optional[str] = None,
        *,
        runtime_commit: Optional[str] = None,
        runtime_artifact_sha256: Optional[str] = None,
        runtime_version: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> SemanticPackageRunResultDTO:
        """Run an exact built-in package id; arbitrary paths are never resolved."""

        manifest_path = self._resolve_builtin_package(package_id)
        return self.run_manifest(
            manifest_path,
            scenario_id,
            runtime_commit=runtime_commit,
            runtime_artifact_sha256=runtime_artifact_sha256,
            runtime_version=runtime_version,
            created_at=created_at,
        )

    def run_scenario(
        self,
        volume: str,
        chapter: str,
        scenario_id: Optional[str] = None,
        *,
        runtime_commit: Optional[str] = None,
        runtime_artifact_sha256: Optional[str] = None,
        runtime_version: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> SemanticPackageRunResultDTO:
        """Run one registry-backed volume/chapter scenario."""

        descriptor = get_chapter_package(str(volume), str(chapter))
        return self.run_manifest(
            descriptor.manifest_path,
            scenario_id,
            runtime_commit=runtime_commit,
            runtime_artifact_sha256=runtime_artifact_sha256,
            runtime_version=runtime_version,
            created_at=created_at,
        )

    def run_registry(
        self,
        registry: Any,
        package_id: str,
        scenario_id: Optional[str] = None,
        *,
        version: Optional[str] = None,
        runtime_commit: Optional[str] = None,
        runtime_artifact_sha256: Optional[str] = None,
        runtime_version: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> SemanticPackageRunResultDTO:
        """Run one promoted industry package through registry-backed discovery.

        The registry is re-resolved on every invocation.  It reconstructs its
        immutable promotion ledger and rebuilds an in-memory manifest from the
        committed manifest, strict execution projection, and verified CAS
        objects; this method never scans or accepts a package path.
        """

        from semantica.ontology.refinery import IndustryOntologyRegistry

        if not isinstance(registry, IndustryOntologyRegistry):
            raise TypeError("registry must be an IndustryOntologyRegistry")
        reserved = {
            item.package_id
            for item in (*list_chapter_packages(), *list_domain_packages())
        }
        if str(package_id) in reserved:
            raise ValueError(
                "industry registry package_id collides with a built-in package"
            )
        descriptor = registry.resolve_package(package_id, version=version)
        manifest = registry.execution_manifest(
            descriptor.package_id, version=descriptor.version
        )
        result = self.run_manifest(
            manifest,
            scenario_id,
            runtime_commit=runtime_commit,
            runtime_artifact_sha256=runtime_artifact_sha256,
            runtime_version=runtime_version,
            created_at=created_at,
        )
        if (
            result.package_id != descriptor.package_id
            or result.package_version != descriptor.version
        ):
            raise ValueError(
                "registry subject identity differs from the executed projection"
            )
        expected_assets = {
            str(item.get("asset_id")): str(item.get("sha256"))
            for item in manifest.get("assets", [])
            if isinstance(item, Mapping)
        }
        if (
            result.receipt is None
            or dict(result.receipt.asset_hashes) != expected_assets
        ):
            raise ValueError(
                "registry subject assets differ from the executed projection"
            )
        return result

    def run_manifest(
        self,
        manifest: Union[Mapping[str, Any], str, Path],
        scenario_id: Optional[str] = None,
        *,
        base_path: Optional[Union[str, Path]] = None,
        runtime_commit: Optional[str] = None,
        runtime_artifact_sha256: Optional[str] = None,
        runtime_version: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> SemanticPackageRunResultDTO:
        """Run a manifest mapping/path using the v1 declarative contract.

        This lower-level entry point is intended for tests and package authors.
        User-facing discovery should call :meth:`run`, which resolves only the
        fixed built-in allowlist.
        """

        when = created_at or utc_now()
        runtime = self._new_runtime()
        manifest_value: Mapping[str, Any]
        manifest_source: Union[Mapping[str, Any], Path]
        root: Optional[Path]
        try:
            manifest_value, manifest_source, root = _read_manifest(
                manifest, base_path=base_path
            )
            loaded = runtime.load_package(manifest_source, base_path=root)
        except Exception:
            return self._unregistered_blocked_result(
                runtime,
                scenario_id=str(scenario_id or "unresolved"),
                created_at=when,
                reason="package manifest or declared asset could not be registered",
            )

        state = _ExecutionState(
            runtime=runtime,
            loaded=loaded,
            manifest=manifest_value,
            manifest_source=manifest_source,
            base_path=root,
            operations=[],
            outcomes={},
            required_capabilities={
                _CAP_PACKAGE_LOAD,
                _CAP_SNAPSHOT,
                _CAP_RECEIPT,
                _CAP_PROVENANCE,
                _CAP_RELEASE,
            },
        )

        selected_id = str(scenario_id or "")
        oracle_checks: List[OracleCheckDTO] = []
        cq_ids: Tuple[str, ...] = ()
        primary_labels: Tuple[str, ...] = ()
        validation_labels: Tuple[str, ...] = ()
        contract_status = "passed"
        contract_reason = ""
        try:
            scenario, cq, selected_id, dialect = self._resolve_scenario(
                state, selected_id or None
            )
            cq_ids = _cq_ids(cq)
            if dialect == "vol2":
                primary_labels, validation_labels, oracle_checks = self._run_vol2(
                    state, scenario, cq
                )
            else:
                primary_labels, validation_labels, oracle_checks = self._run_vol1(
                    state, scenario, cq
                )
        except _BlockedOperation as exc:
            contract_status = "blocked"
            contract_reason = exc.message
            if not selected_id:
                selected_id = "unresolved"
            oracle_checks.append(
                _oracle_check(
                    "oracle.contract",
                    "blocked",
                    expected={"runner_contract": RUNNER_CONTRACT},
                    actual={"error_code": exc.code},
                    message=exc.message,
                )
            )
        except Exception:
            contract_status = "blocked"
            contract_reason = (
                "scenario execution was rejected at the stable runtime boundary"
            )
            if not selected_id:
                selected_id = "unresolved"
            oracle_checks.append(
                _oracle_check(
                    "oracle.execution",
                    "blocked",
                    expected={"executable": True},
                    actual={"error_code": "stable_runtime_rejected_execution"},
                    message=contract_reason,
                )
            )

        operation_status = _aggregate_status(item.status for item in state.operations)
        cq_status = _aggregate_status((contract_status, operation_status))
        cq_report = runtime.execution_report(
            "cq",
            {
                "scenario_id": selected_id,
                "competency_question_ids": list(cq_ids),
                "status": cq_status,
                "operation_hashes": {
                    item.operation_id: item.sha256
                    for item in state.operations
                    if not primary_labels
                    or any(
                        item.operation_id.startswith(label + ".")
                        for label in primary_labels
                    )
                },
                "reason": contract_reason or None,
            },
            status=cq_status,
        )

        validation_operations = tuple(
            item
            for item in state.operations
            if item.operation == "validate"
            and (
                not validation_labels
                or any(
                    item.operation_id.startswith(label + ".")
                    for label in validation_labels
                )
            )
        )
        shacl_status = _aggregate_status(item.status for item in validation_operations)
        if not validation_operations:
            shacl_status = "passed" if cq_status != "blocked" else "blocked"
        shacl_report = runtime.execution_report(
            "shacl",
            {
                "scenario_id": selected_id,
                "applicable": bool(validation_operations),
                "operations": [item.as_dict() for item in validation_operations],
            },
            status=shacl_status,
        )

        if not oracle_checks:
            oracle_checks.append(
                _oracle_check(
                    "oracle.required",
                    "blocked",
                    expected={"declared_exact_oracle": True},
                    actual={"declared_exact_oracle": False},
                    message="scenario has no machine-checkable exact oracle",
                )
            )
        oracle_status = _aggregate_status(item.status for item in oracle_checks)
        oracle_report = runtime.execution_report(
            "oracle",
            {
                "scenario_id": selected_id,
                "checks": [item.as_dict() for item in oracle_checks],
            },
            status=oracle_status,
        )

        output_hashes = {item.operation_id: item.sha256 for item in state.operations}
        receipt = runtime.create_execution_receipt(
            loaded.identity.package_id,
            loaded.identity.version,
            runtime_commit=runtime_commit,
            runtime_artifact_sha256=runtime_artifact_sha256,
            runtime_version=runtime_version,
            required_capabilities=tuple(sorted(state.required_capabilities)),
            cq_report=cq_report,
            shacl_report=shacl_report,
            oracle_report=oracle_report,
            output_hashes=output_hashes,
            created_at=when,
        )
        base_verdict = runtime.verify_release(receipt, checked_at=when)
        declared_release = str(manifest_value.get("release_status", ""))
        scenario_run_status = _aggregate_status(
            (cq_status, shacl_status, oracle_status)
        )
        verdict = _extend_release_verdict(
            base_verdict,
            (
                ReleaseCheckDTO(
                    check_id="package.declared_release_status",
                    passed=declared_release == "complete",
                    message="manifest release_status must be complete; got {!r}".format(
                        declared_release or "missing"
                    ),
                ),
                ReleaseCheckDTO(
                    check_id="runner.scenario_execution",
                    passed=scenario_run_status == "passed",
                    message="scenario execution and exact oracle checks must pass",
                ),
            ),
        )
        reasons = tuple(
            sorted(
                set(
                    [item.check_id for item in verdict.checks if not item.passed]
                    + [
                        item.check_id
                        for item in oracle_checks
                        if item.status != "passed"
                    ]
                )
            )
        )
        result = SemanticPackageRunResultDTO(
            package_id=loaded.identity.package_id,
            package_version=loaded.identity.version,
            package_digest=loaded.identity.digest,
            scenario_id=selected_id,
            status=scenario_run_status,
            created_at=when,
            operations=tuple(state.operations),
            oracle_checks=tuple(oracle_checks),
            capability_report=receipt.capability_report,
            cq_report=receipt.cq_report,
            shacl_report=receipt.shacl_report,
            oracle_report=receipt.oracle_report,
            receipt=receipt,
            release_verdict=verdict,
            reasons=reasons,
        )
        self._receipt_contexts[receipt.receipt_sha256] = (
            runtime,
            declared_release,
            scenario_run_status,
        )
        return result

    def verify(
        self,
        value: Union[SemanticPackageRunResultDTO, PackageExecutionReceiptDTO],
        *,
        checked_at: Optional[str] = None,
    ) -> ReleaseVerdictDTO:
        """Re-verify a receipt against the exact retained execution context."""

        receipt = (
            value.receipt if isinstance(value, SemanticPackageRunResultDTO) else value
        )
        if receipt is None or not isinstance(receipt, PackageExecutionReceiptDTO):
            return _blocked_verdict(
                "0" * 64,
                checked_at or utc_now(),
                "runner.execution_context",
                "run result has no registered execution receipt",
            )
        context = self._receipt_contexts.get(receipt.receipt_sha256)
        if context is None:
            return _blocked_verdict(
                receipt.receipt_sha256,
                checked_at or utc_now(),
                "runner.execution_context",
                "receipt was not produced by this runner instance",
            )
        runtime, declared_release, scenario_status = context
        base = runtime.verify_release(receipt, checked_at=checked_at)
        return _extend_release_verdict(
            base,
            (
                ReleaseCheckDTO(
                    check_id="package.declared_release_status",
                    passed=declared_release == "complete",
                    message="manifest release_status must be complete; got {!r}".format(
                        declared_release or "missing"
                    ),
                ),
                ReleaseCheckDTO(
                    check_id="runner.scenario_execution",
                    passed=scenario_status == "passed",
                    message="scenario execution and exact oracle checks must pass",
                ),
            ),
        )

    # ------------------------------------------------------------------ plans

    def _run_vol2(
        self,
        state: _ExecutionState,
        scenario: Mapping[str, Any],
        cq: Mapping[str, Any],
    ) -> Tuple[Tuple[str, ...], Tuple[str, ...], List[OracleCheckDTO]]:
        execution = cq.get("execution")
        if not isinstance(execution, Mapping):
            raise _BlockedOperation("missing_execution", "CQ execution is missing")
        steps = execution.get("steps")
        primary = self._execute_steps(state, "primary", steps)

        raw_oracles = cq.get("oracles")
        if not isinstance(raw_oracles, Mapping):
            raise _BlockedOperation("missing_oracle", "CQ exact oracles are missing")
        checks: List[OracleCheckDTO] = []
        exact = raw_oracles.get("cq_exact")
        select_outcome = _last_outcome(primary, "select")
        ask_outcome = _last_outcome(primary, "ask")
        if select_outcome is not None:
            checks.extend(_compare_binding_multiset(exact, select_outcome.value))
        elif ask_outcome is not None:
            checks.append(
                _compare_ask_oracle("oracle.cq_exact", exact, ask_outcome.value)
            )
        else:
            checks.append(
                _oracle_check(
                    "oracle.cq_exact",
                    "blocked",
                    expected=exact if exact is not None else {"oracle": "required"},
                    actual={"query_result": "unavailable"},
                    message="CQ execution produced no SELECT or ASK result",
                )
            )

        validation_labels: List[str] = []
        for label in ("positive_path", "single_fault_negative"):
            declaration = raw_oracles.get(label)
            if not isinstance(declaration, Mapping):
                checks.append(
                    _oracle_check(
                        "oracle.{}".format(label),
                        "blocked",
                        expected={"oracle": "required"},
                        actual={"oracle": "missing"},
                        message="{} oracle is missing".format(label),
                    )
                )
                continue
            branch = self._new_branch_state(state)
            branch_steps = declaration.get("execution")
            if branch_steps is None:
                branch_steps = _vol2_compact_validation_steps(declaration)
            outcomes = self._execute_steps(branch, label, branch_steps)
            state.operations.extend(branch.operations)
            state.required_capabilities.update(branch.required_capabilities)
            validation_labels.append(label)
            validation = _last_outcome(outcomes, "validate")
            checks.extend(_compare_validation_oracle(label, declaration, validation))
        return ("primary",), tuple(validation_labels), checks

    def _run_vol1(
        self,
        state: _ExecutionState,
        scenario: Mapping[str, Any],
        cq: Mapping[str, Any],
    ) -> Tuple[Tuple[str, ...], Tuple[str, ...], List[OracleCheckDTO]]:
        execution = scenario.get("execution")
        oracle = scenario.get("oracle")
        if not isinstance(execution, Mapping):
            raise _BlockedOperation(
                "missing_execution", "scenario execution is missing"
            )
        if not isinstance(oracle, Mapping) or str(oracle.get("status", "")) not in {
            "ready",
            "native",
        }:
            raise _BlockedOperation(
                "missing_oracle", "scenario has no machine-checkable ready oracle"
            )
        operation = str(execution.get("operation", ""))
        inputs = scenario.get("inputs")
        if not isinstance(inputs, list):
            raise _BlockedOperation("missing_inputs", "scenario inputs are missing")

        if operation == "select_exact_multiset":
            query_id = _required_text(execution, "query_asset_id")
            if len(inputs) != 2:
                raise _BlockedOperation(
                    "invalid_inputs",
                    "select_exact_multiset requires two dataset assets",
                )
            positive_steps = (
                {"operation": "load_asset", "asset_id": str(inputs[0])},
                {"operation": "select", "asset_id": query_id},
            )
            positive = self._execute_steps(state, "positive", positive_steps)
            negative_state = self._new_branch_state(state)
            negative = self._execute_steps(
                negative_state,
                "single_fault_negative",
                (
                    {"operation": "load_asset", "asset_id": str(inputs[1])},
                    {"operation": "select", "asset_id": query_id},
                ),
            )
            state.operations.extend(negative_state.operations)
            state.required_capabilities.update(negative_state.required_capabilities)
            checks = []
            checks.extend(
                _compare_vol1_select_oracle(
                    "positive",
                    oracle.get("positive"),
                    _last_outcome(positive, "select"),
                )
            )
            checks.extend(
                _compare_vol1_select_oracle(
                    "single_fault_negative",
                    oracle.get("single_fault_negative"),
                    _last_outcome(negative, "select"),
                )
            )
            return (
                ("positive", "single_fault_negative"),
                (),
                checks,
            )

        if operation == "validate":
            shape_id = _required_text(execution, "shape_asset_id")
            if len(inputs) != 2:
                raise _BlockedOperation(
                    "invalid_inputs", "validate scenario requires two dataset assets"
                )
            positive = self._execute_steps(
                state,
                "positive",
                (
                    {"operation": "load_asset", "asset_id": str(inputs[0])},
                    {"operation": "validate", "asset_id": shape_id, "advanced": True},
                ),
            )
            negative_state = self._new_branch_state(state)
            negative = self._execute_steps(
                negative_state,
                "single_fault_negative",
                (
                    {"operation": "load_asset", "asset_id": str(inputs[1])},
                    {"operation": "validate", "asset_id": shape_id, "advanced": True},
                ),
            )
            state.operations.extend(negative_state.operations)
            state.required_capabilities.update(negative_state.required_capabilities)
            checks = []
            checks.extend(
                _compare_validation_oracle(
                    "positive",
                    oracle.get("positive"),
                    _last_outcome(positive, "validate"),
                )
            )
            checks.extend(
                _compare_validation_oracle(
                    "single_fault_negative",
                    oracle.get("single_fault_negative"),
                    _last_outcome(negative, "validate"),
                )
            )
            return (
                ("positive", "single_fault_negative"),
                ("positive", "single_fault_negative"),
                checks,
            )

        if operation == "forward_chain":
            facts_id, rules_id = _forward_asset_ids(state.loaded, inputs)
            outcomes = self._execute_steps(
                state,
                "primary",
                (
                    {
                        "operation": "reason",
                        "facts_asset_id": facts_id,
                        "rules_asset_id": rules_id,
                    },
                ),
            )
            check = _compare_reason_oracle(
                "oracle.expected_conclusions",
                oracle.get("expected_conclusions"),
                _last_outcome(outcomes, "reason"),
            )
            return ("primary",), (), [check]

        if operation == "composite":
            facts_id, rules_id = _forward_asset_ids(state.loaded, inputs)
            rdf_id = _asset_id_by_format(state.loaded, inputs, _RDF_FORMATS)
            query_ids = tuple(
                str(item)
                for item in inputs
                if _asset(state.loaded, str(item)).role == "sparql"
            )
            if len(query_ids) != 2:
                raise _BlockedOperation(
                    "invalid_inputs", "composite scenario requires two ASK query assets"
                )
            outcomes = self._execute_steps(
                state,
                "primary",
                (
                    {
                        "operation": "reason",
                        "facts_asset_id": facts_id,
                        "rules_asset_id": rules_id,
                    },
                    {"operation": "load_asset", "asset_id": rdf_id},
                    {"operation": "ask", "asset_id": query_ids[0]},
                    {"operation": "ask", "asset_id": query_ids[1]},
                ),
            )
            expected = oracle.get("expected")
            if not isinstance(expected, Mapping):
                raise _BlockedOperation("missing_oracle", "composite oracle is missing")
            reason = _last_outcome(outcomes, "reason")
            asks = [item for item in outcomes if item.operation == "ask"]
            checks = [
                _compare_reason_oracle(
                    "oracle.inferred", expected.get("inferred"), reason
                )
            ]
            ask_expectations = (
                ("oracle.ask_owa_evidence", expected.get("ask_owa_evidence")),
                ("oracle.ask_cwa_naf", expected.get("ask_cwa_naf")),
            )
            for index, (check_id, expected_boolean) in enumerate(ask_expectations):
                outcome = asks[index] if index < len(asks) else None
                checks.append(_compare_boolean(check_id, expected_boolean, outcome))
            return ("primary",), (), checks

        if operation == "select_then_cross_package_validate":
            query_id = _required_text(execution, "query_asset_id")
            dependency = _required_text(execution, "shape_dependency")
            if len(inputs) != 1:
                raise _BlockedOperation(
                    "invalid_inputs",
                    "cross-package scenario requires one dataset asset",
                )
            outcomes = self._execute_steps(
                state,
                "primary",
                (
                    {"operation": "load_asset", "asset_id": str(inputs[0])},
                    {"operation": "select", "asset_id": query_id},
                ),
            )
            validation = self._execute_cross_package_validation(
                state, dependency, "cross_package_validation"
            )
            checks = []
            checks.extend(
                _compare_vol1_select_oracle(
                    "select", oracle.get("select"), _last_outcome(outcomes, "select")
                )
            )
            checks.extend(
                _compare_validation_oracle(
                    "validation", oracle.get("validation"), validation
                )
            )
            return ("primary",), ("cross_package_validation",), checks

        raise _BlockedOperation(
            "unsupported_operation",
            "operation {!r} has no SemanticRuntime/v1 contract".format(operation),
        )

    # ------------------------------------------------------------- operations

    def _execute_steps(
        self,
        state: _ExecutionState,
        label: str,
        raw_steps: Any,
    ) -> List[_StepOutcome]:
        if not isinstance(raw_steps, (list, tuple)) or not raw_steps:
            raise _BlockedOperation(
                "missing_steps", "{} execution has no declared steps".format(label)
            )
        outcomes: List[_StepOutcome] = []
        for index, raw in enumerate(raw_steps, start=1):
            operation_id = "{}.{:03d}".format(label, index)
            if not isinstance(raw, Mapping):
                report = _operation_report(
                    operation_id,
                    "invalid",
                    "blocked",
                    {
                        "error_code": "invalid_step",
                        "message": "declared execution step is not a mapping",
                    },
                )
                state.operations.append(report)
                break
            operation = str(raw.get("operation", ""))
            try:
                value, payload = self._execute_operation(state, raw)
                report = _operation_report(operation_id, operation, "passed", payload)
            except _BlockedOperation as exc:
                report = _operation_report(
                    operation_id,
                    operation or "missing",
                    "blocked",
                    {"error_code": exc.code, "message": exc.message},
                )
                state.operations.append(report)
                outcomes.append(_StepOutcome(operation, None, report))
                break
            except Exception:
                report = _operation_report(
                    operation_id,
                    operation or "missing",
                    "blocked",
                    {
                        "error_code": "stable_runtime_rejected_operation",
                        "message": "declared semantic operation could not be executed",
                    },
                )
                state.operations.append(report)
                outcomes.append(_StepOutcome(operation, None, report))
                break
            state.operations.append(report)
            outcome = _StepOutcome(operation, value, report)
            outcomes.append(outcome)
            state.outcomes.setdefault(label, []).append(outcome)
        return outcomes

    def _execute_operation(
        self, state: _ExecutionState, step: Mapping[str, Any]
    ) -> Tuple[Any, Mapping[str, Any]]:
        operation = str(step.get("operation", ""))
        if operation == "load_package":
            package_id = _required_text(step, "package_id")
            version = _required_text(step, "version")
            if (
                package_id != state.loaded.identity.package_id
                or version != state.loaded.identity.version
            ):
                raise _BlockedOperation(
                    "package_identity_mismatch",
                    "declared load_package identity differs from the active package",
                )
            state.required_capabilities.add(_CAP_PACKAGE_LOAD)
            return state.loaded, {
                "package_id": package_id,
                "version": version,
                "digest": state.loaded.identity.digest,
            }

        if operation in {"load", "load_asset"}:
            asset_id = _required_text(step, "asset_id")
            asset = _asset(state.loaded, asset_id)
            format_name = str(step.get("format") or asset.format or "")
            if format_name.lower() not in _RDF_FORMATS:
                raise _BlockedOperation(
                    "unsupported_asset_format",
                    "asset {!r} is not declared in a supported RDF format".format(
                        asset_id
                    ),
                )
            mutation = state.runtime.load(
                asset.content,
                format=format_name,
                graph_name=str(step["graph_name"]) if step.get("graph_name") else None,
            )
            state.required_capabilities.add(_CAP_RDF_LOAD)
            return mutation, {
                "asset_id": asset.asset_id,
                "asset_sha256": asset.sha256,
                "format": format_name,
                "added": mutation.added,
                "quad_count": mutation.quad_count,
                "revision": mutation.revision,
            }

        if operation in {"select", "ask"}:
            asset_id = _required_text(step, "asset_id")
            asset = _asset(state.loaded, asset_id)
            if asset.role != "sparql":
                raise _BlockedOperation(
                    "asset_role_mismatch",
                    "asset {!r} is not registered as SPARQL".format(asset_id),
                )
            if operation == "select":
                result = state.runtime.select(asset.text())
                state.required_capabilities.add(_CAP_SELECT)
                return result, _select_payload(asset, result)
            result = state.runtime.ask(asset.text())
            state.required_capabilities.add(_CAP_ASK)
            return result, {
                "asset_id": asset.asset_id,
                "asset_sha256": asset.sha256,
                "boolean": result.boolean,
                "revision": result.revision,
            }

        if operation == "validate":
            asset_id = _required_text(step, "asset_id")
            asset = _asset(state.loaded, asset_id)
            if asset.role not in {"shapes", "shape", "shacl"}:
                raise _BlockedOperation(
                    "asset_role_mismatch",
                    "asset {!r} is not registered as SHACL shapes".format(asset_id),
                )
            result = state.runtime.validate(
                asset.content,
                shapes_format=str(step.get("format") or asset.format or "turtle"),
                inference=str(step.get("inference", "none")),
                advanced=bool(step.get("advanced", False)),
                abort_on_first=bool(step.get("abort_on_first", False)),
            )
            state.required_capabilities.add(_CAP_SHACL)
            return result, _validation_payload(asset, result)

        if operation == "reason":
            facts_id = _required_text(step, "facts_asset_id")
            rules_id = _required_text(step, "rules_asset_id")
            facts = _asset(state.loaded, facts_id)
            rules = _asset(state.loaded, rules_id)
            result = state.runtime.reason(
                facts,
                rules,
                max_iterations=int(step.get("max_iterations", 50)),
            )
            state.required_capabilities.add(_CAP_REASON)
            return result, {
                "facts_asset_id": facts.asset_id,
                "facts_sha256": facts.sha256,
                "rules_asset_id": rules.asset_id,
                "rules_sha256": rules.sha256,
                "semantics": result.semantics,
                "complete": result.complete,
                "conclusions": list(result.conclusions),
                "all_facts": list(result.all_facts),
                "inferences": [
                    {
                        "conclusion": item.conclusion,
                        "rule_id": item.rule_id,
                        "premises": list(item.premises),
                        "confidence": item.confidence,
                        "explanation": item.explanation,
                    }
                    for item in result.inferences
                ],
            }

        raise _BlockedOperation(
            "unsupported_operation",
            "operation {!r} has no SemanticRuntime/v1 contract".format(operation),
        )

    def _execute_cross_package_validation(
        self, state: _ExecutionState, dependency: str, label: str
    ) -> Optional[_StepOutcome]:
        if ":" not in dependency:
            raise _BlockedOperation(
                "invalid_dependency", "shape dependency must bind package_id:asset_id"
            )
        package_id, asset_id = dependency.rsplit(":", 1)
        descriptor = next(
            (item for item in list_chapter_packages() if item.package_id == package_id),
            None,
        )
        if descriptor is None:
            raise _BlockedOperation(
                "missing_dependency", "shape dependency package is not registered"
            )
        dependency_loaded = state.runtime.load_package(descriptor.manifest_path)
        shapes = _asset(dependency_loaded, asset_id)
        operation_id = "{}.001".format(label)
        try:
            report_value = state.runtime.validate(
                shapes.content,
                shapes_format=shapes.format or "turtle",
                inference="none",
                advanced=True,
            )
            report = _operation_report(
                operation_id,
                "validate",
                "passed",
                {
                    **_validation_payload(shapes, report_value),
                    "dependency_package_id": dependency_loaded.identity.package_id,
                    "dependency_package_version": dependency_loaded.identity.version,
                    "dependency_package_digest": dependency_loaded.identity.digest,
                },
            )
            outcome = _StepOutcome("validate", report_value, report)
        except Exception:
            report = _operation_report(
                operation_id,
                "validate",
                "blocked",
                {
                    "error_code": "stable_runtime_rejected_operation",
                    "message": "cross-package validation could not be executed",
                },
            )
            outcome = _StepOutcome("validate", None, report)
        state.operations.append(report)
        state.required_capabilities.add(_CAP_SHACL)
        return outcome

    # --------------------------------------------------------------- metadata

    def _resolve_scenario(
        self,
        state: _ExecutionState,
        scenario_id: Optional[str],
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any], str, str]:
        manifest_scenarios = state.manifest.get("scenarios")
        if isinstance(manifest_scenarios, list) and manifest_scenarios:
            first = manifest_scenarios[0]
            if isinstance(first, Mapping) and "scenario_id" in first:
                scenario = _select_mapping_by_id(
                    manifest_scenarios, "scenario_id", scenario_id
                )
                registry_id = str(scenario.get("cq_registry_asset", ""))
                if not registry_id:
                    raise _BlockedOperation(
                        "missing_cq_registry", "scenario has no CQ registry asset"
                    )
                registry = _structured_asset(state.loaded, registry_id)
                cqs = registry.get("competency_questions")
                if not isinstance(cqs, list):
                    raise _BlockedOperation(
                        "missing_cq", "CQ registry has no competency_questions"
                    )
                selected = str(scenario.get("scenario_id", ""))
                cq = next(
                    (
                        item
                        for item in cqs
                        if isinstance(item, Mapping)
                        and str(item.get("scenario_id", "")) == selected
                    ),
                    None,
                )
                if cq is None:
                    raise _BlockedOperation(
                        "missing_cq", "scenario is not bound to a CQ execution"
                    )
                _validate_runner_contract(registry.get("runner_contract"))
                return scenario, cq, selected, "vol2"

        execution = state.manifest.get("execution")
        if not isinstance(execution, Mapping):
            raise _BlockedOperation(
                "missing_scenario_registry", "manifest has no scenario registry"
            )
        registry_id = str(execution.get("scenario_registry_asset_id", ""))
        cq_registry_id = str(execution.get("cq_registry_asset_id", ""))
        if not registry_id or not cq_registry_id:
            raise _BlockedOperation(
                "missing_scenario_registry", "manifest scenario/CQ assets are missing"
            )
        registry = _structured_asset(state.loaded, registry_id)
        _validate_runner_contract(registry.get("runner_contract"))
        scenarios = registry.get("scenarios")
        if not isinstance(scenarios, list):
            raise _BlockedOperation(
                "missing_scenario", "scenario registry has no scenarios"
            )
        scenario = _select_mapping_by_id(scenarios, "id", scenario_id)
        selected = str(scenario.get("id", ""))
        cq_registry = _structured_asset(state.loaded, cq_registry_id)
        raw_cqs = cq_registry.get("competency_questions")
        cqs = raw_cqs if isinstance(raw_cqs, list) else []
        matches = [
            item
            for item in cqs
            if isinstance(item, Mapping)
            and selected in tuple(str(value) for value in item.get("scenario_ids", ()))
        ]
        cq: Mapping[str, Any] = {"ids": [str(item.get("id", "")) for item in matches]}
        return scenario, cq, selected, "vol1"

    def _new_branch_state(self, parent: _ExecutionState) -> _ExecutionState:
        runtime = self._new_runtime()
        loaded = runtime.load_package(
            parent.manifest_source, base_path=parent.base_path
        )
        return _ExecutionState(
            runtime=runtime,
            loaded=loaded,
            manifest=parent.manifest,
            manifest_source=parent.manifest_source,
            base_path=parent.base_path,
            operations=[],
            outcomes={},
            required_capabilities={
                _CAP_PACKAGE_LOAD,
                _CAP_SNAPSHOT,
                _CAP_RECEIPT,
                _CAP_PROVENANCE,
                _CAP_RELEASE,
            },
        )

    def _new_runtime(self) -> SemanticRuntime:
        return SemanticRuntime(
            profile=self._profile_name,
            backend=self._backend_name,
        )

    def _resolve_builtin_package(self, package_id: str) -> Path:
        normalized = str(package_id)
        for descriptor in list_chapter_packages():
            if descriptor.package_id == normalized:
                return descriptor.manifest_path
        try:
            return get_domain_package(normalized).manifest_path
        except ChapterPackageNotFoundError:
            pass
        raise ChapterPackageNotFoundError(
            "built-in semantic package is not registered: {}".format(normalized)
        )

    def _unregistered_blocked_result(
        self,
        runtime: SemanticRuntime,
        *,
        scenario_id: str,
        created_at: str,
        reason: str,
    ) -> SemanticPackageRunResultDTO:
        capability = runtime.execution_report(
            "capability",
            {
                "profile": runtime.profile.as_dict(),
                "required": [],
                "unknown": [],
                "missing": [],
            },
            status="passed",
        )
        cq = runtime.execution_report("cq", {"reason": reason}, status="blocked")
        shacl = runtime.execution_report("shacl", {"reason": reason}, status="blocked")
        oracle = runtime.execution_report(
            "oracle", {"reason": reason}, status="blocked"
        )
        check = _oracle_check(
            "oracle.package_registration",
            "blocked",
            expected={"registered": True},
            actual={"registered": False},
            message=reason,
        )
        verdict = _blocked_verdict(
            "0" * 64,
            created_at,
            "package.registration",
            reason,
        )
        return SemanticPackageRunResultDTO(
            package_id="unregistered",
            package_version="unregistered",
            package_digest="",
            scenario_id=scenario_id,
            status="blocked",
            created_at=created_at,
            operations=(),
            oracle_checks=(check,),
            capability_report=capability,
            cq_report=cq,
            shacl_report=shacl,
            oracle_report=oracle,
            receipt=None,
            release_verdict=verdict,
            reasons=("package.registration",),
        )


# ---------------------------------------------------------------------------
# Pure-data helpers


def _read_manifest(
    manifest: Union[Mapping[str, Any], str, Path],
    *,
    base_path: Optional[Union[str, Path]],
) -> Tuple[Mapping[str, Any], Union[Mapping[str, Any], Path], Optional[Path]]:
    if isinstance(manifest, Mapping):
        root = Path(base_path).resolve() if base_path is not None else None
        return manifest, manifest, root
    path = Path(manifest).resolve()
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("semantic package manifest must be a mapping")
    return value, path, None


def _structured_asset(loaded: PackageLoadResultDTO, asset_id: str) -> Mapping[str, Any]:
    asset = _asset(loaded, asset_id)
    try:
        if str(asset.format or "").lower() == "json":
            value = json.loads(asset.text())
        else:
            value = yaml.safe_load(asset.text())
    except Exception as exc:
        raise _BlockedOperation(
            "invalid_registry",
            "registry asset {!r} is not valid structured data".format(asset_id),
        ) from exc
    if not isinstance(value, Mapping):
        raise _BlockedOperation(
            "invalid_registry", "registry asset {!r} must be a mapping".format(asset_id)
        )
    return value


def _asset(loaded: PackageLoadResultDTO, asset_id: str) -> SemanticPackageAssetDTO:
    for item in loaded.assets:
        if item.asset_id == asset_id:
            return item
    raise _BlockedOperation(
        "missing_asset", "declared package asset is missing: {}".format(asset_id)
    )


def _asset_id_by_format(
    loaded: PackageLoadResultDTO,
    candidates: Sequence[Any],
    formats: Iterable[str],
) -> str:
    accepted = set(str(item).lower() for item in formats)
    matches = []
    for candidate in candidates:
        item = _asset(loaded, str(candidate))
        if str(item.format or "").lower() in accepted:
            matches.append(item.asset_id)
    if len(matches) != 1:
        raise _BlockedOperation(
            "ambiguous_asset", "scenario must bind exactly one matching asset"
        )
    return matches[0]


def _forward_asset_ids(
    loaded: PackageLoadResultDTO, inputs: Sequence[Any]
) -> Tuple[str, str]:
    facts = []
    rules = []
    for item in inputs:
        asset = _asset(loaded, str(item))
        if str(asset.format or "").lower() == "semantica-fact":
            facts.append(asset.asset_id)
        if str(asset.format or "").lower() == "semantica-rule":
            rules.append(asset.asset_id)
    if len(facts) != 1 or len(rules) != 1:
        raise _BlockedOperation(
            "unsupported_reasoning_profile",
            "reasoning requires exactly one semantica-fact and one semantica-rule asset; SWRL/DL are not implied",
        )
    return facts[0], rules[0]


def _required_text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _BlockedOperation(
            "missing_field", "declared operation is missing {}".format(key)
        )
    return value


def _validate_runner_contract(value: Any) -> None:
    if isinstance(value, str):
        if value != RUNNER_CONTRACT:
            raise _BlockedOperation(
                "unsupported_runner_contract", "scenario runner contract is unsupported"
            )
        return
    if isinstance(value, Mapping):
        if (
            value.get("requested_api") != "SemanticPackageRunner.run_scenario"
            or value.get("fail_closed") is not True
        ):
            raise _BlockedOperation(
                "unsupported_runner_contract", "scenario runner contract is unsupported"
            )
        return
    raise _BlockedOperation(
        "missing_runner_contract", "scenario runner contract is missing"
    )


def _select_mapping_by_id(
    values: Sequence[Any], key: str, requested: Optional[str]
) -> Mapping[str, Any]:
    candidates = [item for item in values if isinstance(item, Mapping)]
    if requested is None:
        if len(candidates) != 1:
            raise _BlockedOperation(
                "ambiguous_scenario",
                "scenario_id is required when a package has multiple scenarios",
            )
        return candidates[0]
    for item in candidates:
        if str(item.get(key, "")) == requested:
            return item
    raise _BlockedOperation(
        "missing_scenario", "requested scenario is not registered: {}".format(requested)
    )


def _cq_ids(cq: Mapping[str, Any]) -> Tuple[str, ...]:
    if isinstance(cq.get("id"), str):
        return (str(cq["id"]),)
    ids = cq.get("ids")
    if isinstance(ids, list):
        return tuple(str(value) for value in ids if str(value))
    return ()


def _operation_report(
    operation_id: str,
    operation: str,
    status: str,
    payload: Any,
) -> PackageOperationReportDTO:
    payload_json = canonical_json(payload)
    digest = sha256_text(
        canonical_json(
            {
                "operation_id": operation_id,
                "operation": operation,
                "status": status,
                "payload": json.loads(payload_json),
            }
        )
    )
    return PackageOperationReportDTO(
        operation_id=operation_id,
        operation=operation,
        status=status,
        payload_json=payload_json,
        sha256=digest,
    )


def _oracle_check(
    check_id: str,
    status: str,
    *,
    expected: Any,
    actual: Any,
    message: str,
) -> OracleCheckDTO:
    return OracleCheckDTO(
        check_id=check_id,
        status=status,
        expected_json=canonical_json(expected),
        actual_json=canonical_json(actual),
        message=message,
    )


def _aggregate_status(values: Iterable[str]) -> str:
    normalized = tuple(values)
    if any(value == "blocked" for value in normalized):
        return "blocked"
    if any(value == "failed" for value in normalized):
        return "failed"
    return "passed"


def _last_outcome(
    outcomes: Sequence[_StepOutcome], operation: str
) -> Optional[_StepOutcome]:
    for item in reversed(outcomes):
        if item.operation == operation:
            return item
    return None


def _select_payload(
    asset: SemanticPackageAssetDTO, result: SelectResultDTO
) -> Mapping[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "asset_sha256": asset.sha256,
        "variables": list(result.variables),
        "row_count": len(result.rows),
        "rows": [
            {name: row[name].as_dict() for name in result.variables if name in row}
            for row in result.rows
        ],
        "revision": result.revision,
    }


def _validation_payload(
    asset: SemanticPackageAssetDTO, result: ValidationReportDTO
) -> Mapping[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "asset_sha256": asset.sha256,
        "conforms": result.conforms,
        "violation_count": result.violation_count,
        "violations": [
            {
                "focus": item.focus,
                "path": item.path,
                "source_constraint": item.source_constraint,
                "severity": item.severity,
                "message": item.message,
            }
            for item in result.violations
        ],
        "inference": result.inference,
        "advanced": result.advanced,
        "revision": result.revision,
    }


def _compare_binding_multiset(
    declaration: Any, result: SelectResultDTO
) -> List[OracleCheckDTO]:
    if not isinstance(declaration, Mapping):
        return [
            _oracle_check(
                "oracle.cq_exact",
                "blocked",
                expected={"oracle": "binding_multiset required"},
                actual={"oracle": "missing"},
                message="CQ binding multiset oracle is missing",
            )
        ]
    if declaration.get("kind") != "binding_multiset":
        return [
            _oracle_check(
                "oracle.cq_exact",
                "blocked",
                expected={"kind": "binding_multiset"},
                actual={"kind": declaration.get("kind")},
                message="CQ oracle kind is unsupported",
            )
        ]
    variables = declaration.get("variables")
    rows = declaration.get("rows")
    if not isinstance(variables, list) or not isinstance(rows, list):
        return [
            _oracle_check(
                "oracle.cq_exact",
                "blocked",
                expected={"variables": "list", "rows": "list"},
                actual={
                    "variables": type(variables).__name__,
                    "rows": type(rows).__name__,
                },
                message="CQ oracle variables/rows are malformed",
            )
        ]
    actual_variables = list(result.variables)
    actual_rows = [
        {name: row[name].as_dict() for name in result.variables if name in row}
        for row in result.rows
    ]
    expected_counter = Counter(canonical_json(item) for item in rows)
    actual_counter = Counter(canonical_json(item) for item in actual_rows)
    expected = {"variables": variables, "rows": rows}
    actual = {"variables": actual_variables, "rows": actual_rows}
    passed = variables == actual_variables and expected_counter == actual_counter
    return [
        _oracle_check(
            "oracle.cq_exact",
            "passed" if passed else "failed",
            expected=expected,
            actual=actual,
            message=(
                "exact SELECT variables and binding multiset match"
                if passed
                else "SELECT variables or binding multiset differs from the exact oracle"
            ),
        )
    ]


def _compare_ask_oracle(
    check_id: str, declaration: Any, result: AskResultDTO
) -> OracleCheckDTO:
    expected = declaration.get("boolean") if isinstance(declaration, Mapping) else None
    if not isinstance(expected, bool):
        return _oracle_check(
            check_id,
            "blocked",
            expected={"boolean": "required"},
            actual={"boolean": result.boolean},
            message="ASK oracle boolean is missing",
        )
    return _oracle_check(
        check_id,
        "passed" if result.boolean is expected else "failed",
        expected={"boolean": expected},
        actual={"boolean": result.boolean},
        message=(
            "ASK boolean matches"
            if result.boolean is expected
            else "ASK boolean differs"
        ),
    )


def _compare_vol1_select_oracle(
    label: str,
    declaration: Any,
    outcome: Optional[_StepOutcome],
) -> List[OracleCheckDTO]:
    check_id = "oracle.{}".format(label)
    if not isinstance(declaration, Mapping):
        return [
            _oracle_check(
                check_id,
                "blocked",
                expected={"oracle": "required"},
                actual={"oracle": "missing"},
                message="SELECT oracle is missing",
            )
        ]
    if outcome is None or not isinstance(outcome.value, SelectResultDTO):
        return [
            _oracle_check(
                check_id,
                "blocked",
                expected=declaration,
                actual={"result": "unavailable"},
                message="SELECT result is unavailable",
            )
        ]
    result = outcome.value
    expected_count = declaration.get("row_count")
    bindings = declaration.get("bindings", {})
    actual_bindings: Dict[str, List[str]] = {}
    if isinstance(bindings, Mapping):
        for variable in bindings:
            actual_bindings[str(variable)] = sorted(
                row[str(variable)].value for row in result.rows if str(variable) in row
            )
    expected_bindings = (
        {
            str(variable): sorted(str(value) for value in values)
            for variable, values in bindings.items()
        }
        if isinstance(bindings, Mapping)
        else {}
    )
    actual = {
        "row_count": len(result.rows),
        "bindings": actual_bindings,
        "variables": list(result.variables),
    }
    expected = {
        "row_count": expected_count,
        "bindings": expected_bindings,
    }
    valid = isinstance(expected_count, int) and isinstance(bindings, Mapping)
    if not valid:
        return [
            _oracle_check(
                check_id,
                "blocked",
                expected=declaration,
                actual=actual,
                message="SELECT oracle is malformed",
            )
        ]
    passed = len(result.rows) == expected_count and actual_bindings == expected_bindings
    return [
        _oracle_check(
            check_id,
            "passed" if passed else "failed",
            expected=expected,
            actual=actual,
            message=(
                "exact SELECT row count and bindings match"
                if passed
                else "SELECT row count or bindings differ from the oracle"
            ),
        )
    ]


def _compare_validation_oracle(
    label: str,
    declaration: Any,
    outcome: Optional[_StepOutcome],
) -> List[OracleCheckDTO]:
    check_id = "oracle.{}".format(label)
    if not isinstance(declaration, Mapping):
        return [
            _oracle_check(
                check_id,
                "blocked",
                expected={"oracle": "required"},
                actual={"oracle": "missing"},
                message="validation oracle is missing",
            )
        ]
    if outcome is None or not isinstance(outcome.value, ValidationReportDTO):
        return [
            _oracle_check(
                check_id,
                "blocked",
                expected=declaration,
                actual={"result": "unavailable"},
                message="SHACL validation result is unavailable",
            )
        ]
    result = outcome.value
    expected_conforms = declaration.get("conforms")
    expected_count = declaration.get("violation_count", declaration.get("fault_count"))
    message_contains = declaration.get(
        "message_contains", declaration.get("required_message_contains")
    )
    actual_messages = [item.message for item in result.violations]
    actual = {
        "conforms": result.conforms,
        "violation_count": result.violation_count,
        "messages": actual_messages,
    }
    expected: Dict[str, Any] = {"conforms": expected_conforms}
    valid = isinstance(expected_conforms, bool)
    passed = valid and result.conforms is expected_conforms
    if expected_count is not None:
        expected["violation_count"] = expected_count
        valid = valid and isinstance(expected_count, int)
        passed = passed and result.violation_count == expected_count
    if message_contains is not None:
        expected["message_contains"] = message_contains
        valid = valid and isinstance(message_contains, str)
        passed = passed and any(
            str(message_contains) in message for message in actual_messages
        )
    status = "blocked" if not valid else ("passed" if passed else "failed")
    return [
        _oracle_check(
            check_id,
            status,
            expected=expected,
            actual=actual,
            message=(
                "SHACL result matches the declared oracle"
                if status == "passed"
                else (
                    "SHACL oracle is malformed"
                    if status == "blocked"
                    else "SHACL result differs from the declared oracle"
                )
            ),
        )
    ]


def _compare_reason_oracle(
    check_id: str,
    declaration: Any,
    outcome: Optional[_StepOutcome],
) -> OracleCheckDTO:
    if not isinstance(declaration, list):
        return _oracle_check(
            check_id,
            "blocked",
            expected={"conclusions": "required list"},
            actual={"result": "unavailable"},
            message="forward-chain oracle is missing or malformed",
        )
    if outcome is None or not isinstance(outcome.value, ForwardChainResultDTO):
        return _oracle_check(
            check_id,
            "blocked",
            expected={"conclusions": sorted(str(item) for item in declaration)},
            actual={"result": "unavailable"},
            message="forward-chain result is unavailable",
        )
    expected = sorted(str(item) for item in declaration)
    actual = sorted(outcome.value.conclusions)
    return _oracle_check(
        check_id,
        "passed" if expected == actual else "failed",
        expected={"conclusions": expected},
        actual={"conclusions": actual},
        message=(
            "forward-chain conclusions match exactly"
            if expected == actual
            else "forward-chain conclusions differ from the exact oracle"
        ),
    )


def _compare_boolean(
    check_id: str,
    declaration: Any,
    outcome: Optional[_StepOutcome],
) -> OracleCheckDTO:
    if not isinstance(declaration, bool):
        return _oracle_check(
            check_id,
            "blocked",
            expected={"boolean": "required"},
            actual={"result": "unavailable"},
            message="boolean oracle is missing",
        )
    if outcome is None or not isinstance(outcome.value, AskResultDTO):
        return _oracle_check(
            check_id,
            "blocked",
            expected={"boolean": declaration},
            actual={"result": "unavailable"},
            message="ASK result is unavailable",
        )
    actual = outcome.value.boolean
    return _oracle_check(
        check_id,
        "passed" if actual is declaration else "failed",
        expected={"boolean": declaration},
        actual={"boolean": actual},
        message=(
            "ASK boolean matches" if actual is declaration else "ASK boolean differs"
        ),
    )


def _vol2_compact_validation_steps(
    declaration: Mapping[str, Any],
) -> Tuple[Mapping[str, Any], ...]:
    shapes = declaration.get("shapes_asset")
    if not isinstance(shapes, str) or not shapes:
        raise _BlockedOperation(
            "missing_shape", "compact validation oracle has no shapes_asset"
        )
    dataset = declaration.get("dataset_asset")
    steps: List[Mapping[str, Any]] = []
    if isinstance(dataset, str) and dataset:
        steps.append({"operation": "load_asset", "asset_id": dataset})
    elif declaration.get("dataset") != "loaded-package":
        raise _BlockedOperation(
            "missing_dataset", "compact validation oracle has no dataset binding"
        )
    steps.append({"operation": "validate", "asset_id": shapes})
    return tuple(steps)


def _extend_release_verdict(
    base: ReleaseVerdictDTO, extra: Sequence[ReleaseCheckDTO]
) -> ReleaseVerdictDTO:
    by_id: Dict[str, ReleaseCheckDTO] = {item.check_id: item for item in base.checks}
    for item in extra:
        by_id[item.check_id] = item
    checks = tuple(by_id[key] for key in sorted(by_id))
    return ReleaseVerdictDTO(
        status="complete" if all(item.passed for item in checks) else "blocked",
        receipt_sha256=base.receipt_sha256,
        checked_at=base.checked_at,
        checks=checks,
    )


def _blocked_verdict(
    receipt_sha256: str,
    checked_at: str,
    check_id: str,
    message: str,
) -> ReleaseVerdictDTO:
    return ReleaseVerdictDTO(
        status="blocked",
        receipt_sha256=receipt_sha256,
        checked_at=checked_at,
        checks=(ReleaseCheckDTO(check_id=check_id, passed=False, message=message),),
    )


__all__ = [
    "OracleCheckDTO",
    "PackageOperationReportDTO",
    "RUNNER_CONTRACT",
    "SemanticPackageRunResultDTO",
    "SemanticPackageRunner",
]
