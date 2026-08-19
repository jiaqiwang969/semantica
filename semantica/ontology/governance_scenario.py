"""Built-in acceptance scenario for governed ontology evolution.

The scenario owns the synthetic ontology deltas and CQ bank that formerly
lived in ontology-engineering's demo.  External callers receive only frozen
DTO evidence and never need to embed RDF, SPARQL, or governance fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
from typing import Any, Dict, Optional, Tuple

from .governance import (
    DEFAULT_NAMESPACE,
    GovernanceGateError,
    GovernanceWorkspaceExistsError,
    RuntimeSourceIdentityDTO,
    commit_change,
    history_workspace,
    initialize_workspace,
    regress_workspace,
)
from .lifecycle import canonical_json


GOVERNANCE_ACCEPTANCE_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class GovernanceAcceptanceCheckDTO:
    """One deterministic acceptance assertion."""

    check_id: str
    passed: bool
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class GovernanceAcceptanceResultDTO:
    """Pure-data result of the built-in learn-without-forgetting scenario."""

    status: str
    checks: Tuple[GovernanceAcceptanceCheckDTO, ...]
    version_count: int
    final_regression_status: str
    schema_version: str = GOVERNANCE_ACCEPTANCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in {"passed", "failed"}:
            raise ValueError("acceptance status must be passed or failed")
        expected = "passed" if all(item.passed for item in self.checks) else "failed"
        if self.status != expected:
            raise ValueError("acceptance status differs from its checks")

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "version_count": self.version_count,
            "final_regression_status": self.final_regression_status,
            "checks": [item.as_dict() for item in self.checks],
        }


def _write_cq(path: Path, value: Dict[str, Any]) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8")


def run_governance_acceptance_scenario(
    source_identity: Optional[RuntimeSourceIdentityDTO] = None,
) -> GovernanceAcceptanceResultDTO:
    """Run conflict, lineage, regression, and deliberate-forgetting checks."""

    identity = source_identity or RuntimeSourceIdentityDTO()
    checks = []
    baseline = {
        "classes": [
            {"name": "IntentMode", "comment": "Design-intent mode"},
            {"name": "PartMode", "comment": "Part-only tools"},
            {"name": "AssemblyMode", "comment": "Assembly-only commands"},
            {"name": "HybridMode", "comment": "Part and assembly commands"},
            {"name": "WorkflowTransition", "comment": "Supported mode change"},
        ],
        "properties": [{"name": "hasIntentMode", "comment": ""}],
    }
    lesson_two = {
        "classes": [
            {"name": "CourseOrientationLesson", "comment": "Roadmap lesson"},
            {"name": "RoadmapStage", "comment": "Evidence-bound stage"},
            {"name": "CurrentCapabilityContact", "comment": "Read-only probe"},
        ]
    }
    conflict = {
        "classes": [
            {
                "name": "IntentMode",
                "comment": "Design-intent mode also constrains collaboration",
            },
            {"name": "TSplineBody", "comment": "T-Spline body"},
        ]
    }
    removal = {"removes": ["PartMode"]}

    with tempfile.TemporaryDirectory(prefix="semantica-governance-") as temporary:
        workspace = Path(temporary) / "curriculum"
        initialize_workspace(
            workspace,
            name="FusionCurriculum",
            baseline=baseline,
            attempt="lesson-1",
            source_identity=identity,
            recorded_at="2026-01-01T00:00:00Z",
        )
        try:
            initialize_workspace(workspace, name="Replacement")
        except GovernanceWorkspaceExistsError:
            refused_overwrite = True
        else:
            refused_overwrite = False
        checks.append(
            GovernanceAcceptanceCheckDTO(
                "lineage.refuse_overwrite",
                refused_overwrite,
                "initialization must not replace an existing lineage",
            )
        )

        _write_cq(
            workspace / "cq-bank" / "cq-modes.json",
            {
                "id": "CQ-MODES",
                "question": "Are all three intent modes retained?",
                "sparql": (
                    "PREFIX dom: <{}> PREFIX owl: <http://www.w3.org/2002/07/owl#> "
                    "SELECT ?c WHERE {{ VALUES ?c {{ dom:PartMode dom:AssemblyMode "
                    "dom:HybridMode }} ?c a owl:Class }}"
                ).format(DEFAULT_NAMESPACE),
                "min_rows": 3,
            },
        )
        commit_change(
            workspace,
            lesson_two,
            attempt="lesson-2",
            source_identity=identity,
            recorded_at="2026-01-02T00:00:00Z",
        )
        _write_cq(
            workspace / "cq-bank" / "cq-roadmap.json",
            {
                "id": "CQ-ROADMAP",
                "question": "Is the roadmap lesson retained?",
                "ask": True,
                "sparql": (
                    "PREFIX dom: <{}> PREFIX owl: <http://www.w3.org/2002/07/owl#> "
                    "ASK {{ dom:CourseOrientationLesson a owl:Class }}"
                ).format(DEFAULT_NAMESPACE),
            },
        )

        try:
            commit_change(workspace, conflict, attempt="lesson-3-without-verdict")
        except GovernanceGateError:
            refused_unreasoned_conflict = True
        else:
            refused_unreasoned_conflict = False
        checks.append(
            GovernanceAcceptanceCheckDTO(
                "conflict.requires_reasoned_verdict",
                refused_unreasoned_conflict,
                "same-name semantic changes require an explicit reasoned verdict",
            )
        )
        commit_change(
            workspace,
            conflict,
            verdicts={
                "IntentMode": {
                    "action": "merge",
                    "reason": "the collaboration constraint enriches the retained meaning",
                }
            },
            attempt="lesson-3",
            source_identity=identity,
            recorded_at="2026-01-03T00:00:00Z",
        )
        before_removal = regress_workspace(workspace)
        checks.append(
            GovernanceAcceptanceCheckDTO(
                "regression.retains_prior_competency_questions",
                before_removal.passed and len(before_removal.results) == 2,
                "both accumulated competency questions pass after three lessons",
            )
        )

        final_commit = commit_change(
            workspace,
            removal,
            verdicts={
                "PartMode": {
                    "action": "remove",
                    "reason": "deliberate negative example for regression detection",
                }
            },
            attempt="deliberate-forgetting",
            source_identity=identity,
            recorded_at="2026-01-04T00:00:00Z",
        )
        after_removal = regress_workspace(workspace)
        checks.append(
            GovernanceAcceptanceCheckDTO(
                "regression.detects_forgetting",
                (not after_removal.passed)
                and final_commit.release.complete is False,
                "a reasoned removal is committed but CQ regression blocks release",
            )
        )
        history = history_workspace(workspace)
        checks.append(
            GovernanceAcceptanceCheckDTO(
                "lineage.four_immutable_versions",
                len(history) == 4 and history[-1].version == 4,
                "the complete append-only history remains verifiable",
            )
        )

    frozen = tuple(checks)
    return GovernanceAcceptanceResultDTO(
        status="passed" if all(item.passed for item in frozen) else "failed",
        checks=frozen,
        version_count=4,
        final_regression_status=after_removal.status,
    )


__all__ = [
    "GOVERNANCE_ACCEPTANCE_SCHEMA_VERSION",
    "GovernanceAcceptanceCheckDTO",
    "GovernanceAcceptanceResultDTO",
    "run_governance_acceptance_scenario",
]
