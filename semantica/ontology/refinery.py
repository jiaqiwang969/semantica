"""Semantica-native industry ontology refinement and promotion.

The refinery is the governed control plane for turning one engineering
engagement into reusable industry semantics.  It deliberately separates two
truth levels:

* an engagement may observe practice and retain a content-addressed candidate;
* only an explicitly authorised, regression-passed and release-complete
  candidate may become a promoted industry package.

All semantic assets are stored in a Semantica-managed content-addressed store.
Package identifiers are opaque registry keys: they are validated, hashed, and
looked up in ``registry.json``; they are never interpreted as filesystem paths.
Immutable event chains record the exact lifecycle

``candidate -> proposed -> committed -> regression_passed ->
release_complete -> promoted``.

``published`` is intentionally absent.  Publication remains an external
decision by the relevant rights holder or release authority.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import unquote, urlsplit

from .lifecycle import (
    canonical_json,
    is_sha256,
    sha256_text,
    utc_now,
)

REFINERY_SCHEMA_VERSION = "1.0"
REFINERY_CONTRACT = "semantica.ontology.refinery/v1"
INDUSTRY_REGISTRY_TARGET = "industry-registry"
SEMANTIC_PACKAGE_RUNNER_CONTRACT = "semantica.chapter_packages.SemanticPackageRunner/v1"

PACKAGE_ASSET_CATEGORIES = (
    "ontology",
    "competency_questions",
    "shapes",
    "queries",
    "rules",
    "cases",
    "contract",
    "provenance",
)
BOOK_IMPACTS = ("none", "vol1-method", "vol2-iso-exemplar", "both")
PACKAGE_DELTA_CATEGORIES = PACKAGE_ASSET_CATEGORIES + ("book_impact",)
CASE_KINDS = ("positive", "negative", "ambiguity", "prior_release")
REGRESSION_REQUIRED_CHECK_IDS = (
    "cq.prior",
    "cq.current",
    "case.positive",
    "case.negative",
    "case.ambiguity",
    "case.prior_release",
)
RELEASE_REQUIRED_CHECK_IDS = (
    "package.coverage",
    "capability.coverage",
    "receipt.binding",
    "provenance.binding",
    "source.rights",
    "io.binding",
)
REFINERY_STATES = (
    "candidate",
    "proposed",
    "committed",
    "regression_passed",
    "release_complete",
    "promoted",
)
_NEXT_STATE = {
    "candidate": "proposed",
    "proposed": "committed",
    "committed": "regression_passed",
    "regression_passed": "release_complete",
    "release_complete": "promoted",
}
_PHASE_NAMES = ("execution", "regression", "receipt", "release")
_PHASE_STATUSES = frozenset({"passed", "failed", "blocked"})
_LEARNING_STATUSES = frozenset({"no_delta", "candidate"})
_ASSET_OPERATIONS = frozenset({"add", "replace", "remove"})
_AUTHORIZATION_ACTIONS = frozenset({"commit", "promote"})
TRANSITION_CONTEXT_ACTIONS = (
    "candidate",
    "proposed",
    "committed",
    "execute_candidate",
    "derive_regression_gate",
    "regression_passed",
    "derive_release_gate",
    "release_complete",
    "promoted",
)
_TASK_ACTIONS = frozenset({"engagement", *TRANSITION_CONTEXT_ACTIONS})
_CONTEXT_ALLOWED_STATE = {
    "candidate": "candidate",
    "proposed": "proposed",
    "committed": "committed",
    "execute_candidate": "committed",
    "derive_regression_gate": "regression_passed",
    "regression_passed": "regression_passed",
    "derive_release_gate": "release_complete",
    "release_complete": "release_complete",
    "promoted": "promoted",
}
_EVENT_CONTEXT_ACTION = {
    "candidate": "candidate",
    "proposed": "proposed",
    "committed": "committed",
    "regression_passed": "regression_passed",
    "release_complete": "release_complete",
    "promoted": "promoted",
}
_TRANSITION_CONTEXT_ORDER = {
    action: index for index, action in enumerate(TRANSITION_CONTEXT_ACTIONS)
}
_LOGICAL_URI_SCHEMES = frozenset({"urn", "semantica", "evidence", "ni"})
_SAFE_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,199}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")

EMPTY_PACKAGE_SHA256 = sha256_text(
    canonical_json(
        {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "package_id": None,
            "version": "0",
            "assets": [],
        }
    )
)


# ---------------------------------------------------------------------------
# Errors


class OntologyRefineryError(RuntimeError):
    """Base error for the industry ontology refinery."""


class RefineryInputError(OntologyRefineryError):
    """Raised when a public refinery DTO or argument is malformed."""


class RefineryWorkspaceError(OntologyRefineryError):
    """Raised when the managed workspace is absent, busy, or corrupt."""


class RefineryWorkspaceExistsError(RefineryWorkspaceError):
    """Raised when workspace creation would replace existing data."""


class RefineryStateError(OntologyRefineryError):
    """Raised when a lifecycle transition is out of order."""


class RefineryGateError(OntologyRefineryError):
    """Raised when an advancement gate is incomplete or unauthorised."""

    def __init__(self, violations: Sequence[str]) -> None:
        self.violations = tuple(str(item) for item in violations)
        super().__init__("; ".join(self.violations))


class IndustryPackageNotFoundError(OntologyRefineryError):
    """Raised when an opaque package ID is not present in the registry."""


class IndustryPackageVersionExistsError(OntologyRefineryError):
    """Raised when promotion would overwrite an immutable package version."""


# ---------------------------------------------------------------------------
# Stable contracts


@dataclass(frozen=True)
class SourceEvidenceDTO:
    """Logical source identity plus the hash of the exact observed bytes.

    ``uri`` is retained as evidence only.  The refinery never opens or resolves
    it, so a source identity cannot become an arbitrary filesystem read.
    """

    source_id: str
    uri: str
    sha256: str
    media_type: str
    captured_at: str

    def __post_init__(self) -> None:
        _required_text(self.source_id, "source_id")
        _validate_logical_uri(self.uri, "source uri")
        _required_sha256(self.sha256, "source sha256")
        _required_text(self.media_type, "source media_type")
        _validate_timestamp(self.captured_at, "source captured_at")

    def as_dict(self) -> Dict[str, str]:
        return {
            "source_id": self.source_id,
            "uri": self.uri,
            "sha256": self.sha256,
            "media_type": self.media_type,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SourceEvidenceDTO":
        _reject_unknown(
            value,
            {"source_id", "uri", "sha256", "media_type", "captured_at"},
            "source evidence",
        )
        return cls(
            source_id=_strict_text(value.get("source_id"), "source_id"),
            uri=_strict_text(value.get("uri"), "source uri"),
            sha256=_strict_text(value.get("sha256"), "source sha256"),
            media_type=_strict_text(value.get("media_type"), "source media_type"),
            captured_at=_strict_text(value.get("captured_at"), "source captured_at"),
        )


@dataclass(frozen=True)
class RuntimeSourceIdentityDTO:
    """Exact Semantica source and built-artifact identity."""

    runtime_commit: str
    runtime_artifact_sha256: str
    runtime_version: str

    def __post_init__(self) -> None:
        _exact_string(self.runtime_commit, "runtime_commit")
        _exact_string(self.runtime_artifact_sha256, "runtime_artifact_sha256")
        _exact_string(self.runtime_version, "runtime_version")

    @property
    def complete(self) -> bool:
        return bool(
            _GIT_COMMIT.fullmatch(self.runtime_commit)
            and is_sha256(self.runtime_artifact_sha256)
            and self.runtime_version.strip()
        )

    def as_dict(self) -> Dict[str, str]:
        return {
            "runtime_commit": self.runtime_commit,
            "runtime_artifact_sha256": self.runtime_artifact_sha256,
            "runtime_version": self.runtime_version,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RuntimeSourceIdentityDTO":
        _reject_unknown(
            value,
            {"runtime_commit", "runtime_artifact_sha256", "runtime_version"},
            "runtime source identity",
        )
        return cls(
            runtime_commit=_exact_string(value.get("runtime_commit"), "runtime_commit"),
            runtime_artifact_sha256=_exact_string(
                value.get("runtime_artifact_sha256"),
                "runtime_artifact_sha256",
            ),
            runtime_version=_exact_string(
                value.get("runtime_version"), "runtime_version"
            ),
        )


@dataclass(frozen=True)
class SemanticTaskEnvelope:
    """Stable task hand-off from any engineering skill into Semantica."""

    task_id: str
    task_kind: str
    project_id: str
    domain: str
    intent: str
    requested_decision: str
    actor_id: str
    requested_actions: Tuple[str, ...]
    required_capabilities: Tuple[str, ...]
    evidence: Tuple[SourceEvidenceDTO, ...]
    created_at: str
    schema_version: str = REFINERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for field, value in (
            ("task_id", self.task_id),
            ("task_kind", self.task_kind),
            ("project_id", self.project_id),
            ("domain", self.domain),
            ("intent", self.intent),
            ("requested_decision", self.requested_decision),
            ("actor_id", self.actor_id),
        ):
            _required_text(value, field)
        _validate_unique_text_tuple(self.requested_actions, "requested_actions")
        unknown_actions = sorted(set(self.requested_actions) - _TASK_ACTIONS)
        if unknown_actions:
            raise RefineryInputError(
                "requested_actions contains unknown actions: {}".format(
                    ", ".join(unknown_actions)
                )
            )
        _validate_unique_text_tuple(self.required_capabilities, "required_capabilities")
        if not self.evidence:
            raise RefineryInputError(
                "task envelope requires at least one source identity/hash"
            )
        _validate_unique_by(
            self.evidence, lambda item: item.source_id, "task evidence source_id"
        )
        _validate_timestamp(self.created_at, "task created_at")
        _require_schema(self.schema_version)

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_kind": self.task_kind,
            "project_id": self.project_id,
            "domain": self.domain,
            "intent": self.intent,
            "requested_decision": self.requested_decision,
            "actor_id": self.actor_id,
            "requested_actions": list(self.requested_actions),
            "required_capabilities": list(self.required_capabilities),
            "evidence": [item.as_dict() for item in self.evidence],
            "created_at": self.created_at,
        }

    @property
    def envelope_sha256(self) -> str:
        return sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "envelope_sha256": self.envelope_sha256}

    def to_json(self) -> str:
        return canonical_json(self.as_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SemanticTaskEnvelope":
        _reject_unknown(
            value,
            {
                "schema_version",
                "task_id",
                "task_kind",
                "project_id",
                "domain",
                "intent",
                "requested_decision",
                "actor_id",
                "requested_actions",
                "required_capabilities",
                "evidence",
                "created_at",
                "envelope_sha256",
            },
            "semantic task envelope",
        )
        result = cls(
            task_id=_strict_text(value.get("task_id"), "task_id"),
            task_kind=_strict_text(value.get("task_kind"), "task_kind"),
            project_id=_strict_text(value.get("project_id"), "project_id"),
            domain=_strict_text(value.get("domain"), "domain"),
            intent=_strict_text(value.get("intent"), "intent"),
            requested_decision=_strict_text(
                value.get("requested_decision"), "requested_decision"
            ),
            actor_id=_strict_text(value.get("actor_id"), "actor_id"),
            requested_actions=_text_tuple(
                value.get("requested_actions"), "requested_actions"
            ),
            required_capabilities=_text_tuple(
                value.get("required_capabilities"), "required_capabilities"
            ),
            evidence=tuple(
                SourceEvidenceDTO.from_dict(item)
                for item in _mapping_list(value.get("evidence"), "evidence")
            ),
            created_at=_strict_text(value.get("created_at"), "created_at"),
            schema_version=_strict_text(
                value.get("schema_version", REFINERY_SCHEMA_VERSION),
                "schema_version",
            ),
        )
        _check_declared_digest(value, "envelope_sha256", result.envelope_sha256)
        return result


@dataclass(frozen=True)
class ProjectOntologyBinding:
    """Binding between one project and one logical industry package baseline."""

    binding_id: str
    project_id: str
    domain: str
    package_id: str
    workspace_id: str
    baseline_version: str
    baseline_package_sha256: str
    evidence_root: str
    fact_authorities: Tuple[str, ...]
    decision_authorities: Tuple[str, ...]
    allowed_actions: Tuple[str, ...]
    semantic_api_contract: str
    promotion_target: str
    created_at: str
    schema_version: str = REFINERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for field, value in (
            ("binding_id", self.binding_id),
            ("project_id", self.project_id),
            ("domain", self.domain),
            ("workspace_id", self.workspace_id),
            ("baseline_version", self.baseline_version),
            ("promotion_target", self.promotion_target),
        ):
            _required_text(value, field)
        if self.promotion_target != INDUSTRY_REGISTRY_TARGET:
            raise RefineryInputError(
                "promotion_target must exactly match {}".format(
                    INDUSTRY_REGISTRY_TARGET
                )
            )
        _validate_package_id(self.package_id)
        _required_sha256(self.baseline_package_sha256, "baseline_package_sha256")
        if self.baseline_version == "0" and (
            self.baseline_package_sha256 != EMPTY_PACKAGE_SHA256
        ):
            raise RefineryInputError(
                "baseline version 0 must bind EMPTY_PACKAGE_SHA256"
            )
        if self.baseline_version != "0" and (
            self.baseline_package_sha256 == EMPTY_PACKAGE_SHA256
        ):
            raise RefineryInputError(
                "a non-zero baseline cannot bind EMPTY_PACKAGE_SHA256"
            )
        _validate_logical_uri(self.evidence_root, "evidence_root")
        _validate_unique_text_tuple(self.fact_authorities, "fact_authorities")
        _validate_unique_text_tuple(self.decision_authorities, "decision_authorities")
        _validate_unique_text_tuple(self.allowed_actions, "allowed_actions")
        if self.allowed_actions != REFINERY_STATES[: len(self.allowed_actions)]:
            raise RefineryInputError(
                "binding allowed_actions must be a non-empty ordered lifecycle prefix"
            )
        if self.semantic_api_contract != REFINERY_CONTRACT:
            raise RefineryInputError(
                "semantic_api_contract must exactly match {}".format(REFINERY_CONTRACT)
            )
        _validate_timestamp(self.created_at, "binding created_at")
        _require_schema(self.schema_version)

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "binding_id": self.binding_id,
            "project_id": self.project_id,
            "domain": self.domain,
            "package_id": self.package_id,
            "workspace_id": self.workspace_id,
            "baseline_version": self.baseline_version,
            "baseline_package_sha256": self.baseline_package_sha256,
            "evidence_root": self.evidence_root,
            "fact_authorities": list(self.fact_authorities),
            "decision_authorities": list(self.decision_authorities),
            "allowed_actions": list(self.allowed_actions),
            "semantic_api_contract": self.semantic_api_contract,
            "promotion_target": self.promotion_target,
            "created_at": self.created_at,
        }

    @property
    def binding_sha256(self) -> str:
        return sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "binding_sha256": self.binding_sha256}

    def to_json(self) -> str:
        return canonical_json(self.as_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProjectOntologyBinding":
        _reject_unknown(
            value,
            {
                "schema_version",
                "binding_id",
                "project_id",
                "domain",
                "package_id",
                "workspace_id",
                "baseline_version",
                "baseline_package_sha256",
                "evidence_root",
                "fact_authorities",
                "decision_authorities",
                "allowed_actions",
                "semantic_api_contract",
                "promotion_target",
                "created_at",
                "binding_sha256",
            },
            "project ontology binding",
        )
        result = cls(
            binding_id=_strict_text(value.get("binding_id"), "binding_id"),
            project_id=_strict_text(value.get("project_id"), "project_id"),
            domain=_strict_text(value.get("domain"), "domain"),
            package_id=_strict_text(value.get("package_id"), "package_id"),
            workspace_id=_strict_text(value.get("workspace_id"), "workspace_id"),
            baseline_version=_strict_text(
                value.get("baseline_version"), "baseline_version"
            ),
            baseline_package_sha256=_strict_text(
                value.get("baseline_package_sha256"),
                "baseline_package_sha256",
            ),
            evidence_root=_strict_text(value.get("evidence_root"), "evidence_root"),
            fact_authorities=_text_tuple(
                value.get("fact_authorities"), "fact_authorities"
            ),
            decision_authorities=_text_tuple(
                value.get("decision_authorities"), "decision_authorities"
            ),
            allowed_actions=_text_tuple(
                value.get("allowed_actions"), "allowed_actions"
            ),
            semantic_api_contract=_strict_text(
                value.get("semantic_api_contract"), "semantic_api_contract"
            ),
            promotion_target=_strict_text(
                value.get("promotion_target"), "promotion_target"
            ),
            created_at=_strict_text(value.get("created_at"), "created_at"),
            schema_version=_strict_text(
                value.get("schema_version", REFINERY_SCHEMA_VERSION),
                "schema_version",
            ),
        )
        _check_declared_digest(value, "binding_sha256", result.binding_sha256)
        return result


@dataclass(frozen=True)
class TransitionContextDTO:
    """Current invocation intent and binding for exactly one refinery write."""

    action: str
    delta_sha256: str
    envelope: SemanticTaskEnvelope
    binding: ProjectOntologyBinding
    context_sha256: str
    schema_version: str = REFINERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.action not in TRANSITION_CONTEXT_ACTIONS:
            raise RefineryInputError("transition context action is unsupported")
        _required_sha256(self.delta_sha256, "transition delta_sha256")
        if self.envelope.requested_actions != (self.action,):
            raise RefineryInputError(
                "transition task must request exactly its current context action"
            )
        if (
            self.envelope.project_id != self.binding.project_id
            or self.envelope.domain != self.binding.domain
        ):
            raise RefineryInputError(
                "transition task project/domain differs from current binding"
            )
        for source in self.envelope.evidence:
            if not _uri_within_root(source.uri, self.binding.evidence_root):
                raise RefineryInputError(
                    "transition task evidence is outside current binding evidence_root"
                )
        required_state = _CONTEXT_ALLOWED_STATE[self.action]
        if required_state not in self.binding.allowed_actions:
            raise RefineryInputError(
                "transition action is outside the binding lifecycle prefix"
            )
        _require_schema(self.schema_version)
        _required_sha256(self.context_sha256, "transition context_sha256")
        if not self.verify_integrity():
            raise RefineryInputError("transition context hash mismatch")

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action": self.action,
            "delta_sha256": self.delta_sha256,
            "envelope": self.envelope.as_dict(),
            "binding": self.binding.as_dict(),
        }

    def verify_integrity(self) -> bool:
        return self.context_sha256 == sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "context_sha256": self.context_sha256}

    @classmethod
    def create(
        cls,
        *,
        action: str,
        delta_sha256: str,
        envelope: SemanticTaskEnvelope,
        binding: ProjectOntologyBinding,
    ) -> "TransitionContextDTO":
        content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "action": action,
            "delta_sha256": delta_sha256,
            "envelope": envelope.as_dict(),
            "binding": binding.as_dict(),
        }
        return cls(
            action=action,
            delta_sha256=delta_sha256,
            envelope=envelope,
            binding=binding,
            context_sha256=sha256_text(canonical_json(content)),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransitionContextDTO":
        fields = {
            "schema_version",
            "action",
            "delta_sha256",
            "envelope",
            "binding",
            "context_sha256",
        }
        _reject_unknown(value, fields, "transition context")
        if set(value) != fields:
            raise RefineryInputError("transition context schema is incomplete")
        return cls(
            action=_strict_text(value.get("action"), "transition action"),
            delta_sha256=_strict_text(
                value.get("delta_sha256"), "transition delta_sha256"
            ),
            envelope=SemanticTaskEnvelope.from_dict(
                _mapping(value.get("envelope"), "transition envelope")
            ),
            binding=ProjectOntologyBinding.from_dict(
                _mapping(value.get("binding"), "transition binding")
            ),
            context_sha256=_strict_text(
                value.get("context_sha256"), "transition context_sha256"
            ),
            schema_version=_strict_text(
                value.get("schema_version"), "transition schema_version"
            ),
        )


@dataclass(frozen=True)
class EngagementPhaseDTO:
    """One mandatory phase result in every semantic engagement."""

    name: str
    status: str
    required_capabilities: Tuple[str, ...]
    observed_capabilities: Tuple[str, ...]
    evidence_sha256: Optional[str]
    details_json: str

    def __post_init__(self) -> None:
        if self.name not in _PHASE_NAMES:
            raise RefineryInputError("unknown engagement phase: {}".format(self.name))
        if self.status not in _PHASE_STATUSES:
            raise RefineryInputError("invalid engagement phase status")
        _validate_unique_text_tuple(
            self.required_capabilities, "phase required_capabilities"
        )
        _validate_unique_text_tuple(
            self.observed_capabilities,
            "phase observed_capabilities",
            allow_empty=True,
        )
        _validate_canonical_json(self.details_json, "phase details_json")
        missing = sorted(
            set(self.required_capabilities) - set(self.observed_capabilities)
        )
        if self.evidence_sha256 is not None:
            _required_sha256(self.evidence_sha256, "phase evidence_sha256")
        if self.status == "passed" and (missing or self.evidence_sha256 is None):
            raise RefineryInputError(
                "a passed phase requires all capabilities and hashed evidence"
            )

    @property
    def missing_capabilities(self) -> Tuple[str, ...]:
        return tuple(
            sorted(set(self.required_capabilities) - set(self.observed_capabilities))
        )

    @property
    def details(self) -> Any:
        return json.loads(self.details_json)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "required_capabilities": list(self.required_capabilities),
            "observed_capabilities": list(self.observed_capabilities),
            "missing_capabilities": list(self.missing_capabilities),
            "evidence_sha256": self.evidence_sha256,
            "details": self.details,
        }

    @classmethod
    def evaluate(
        cls,
        name: str,
        *,
        required_capabilities: Sequence[str],
        observed_capabilities: Sequence[str],
        evidence_sha256: Optional[str],
        details: Any,
        execution_status: str = "passed",
    ) -> "EngagementPhaseDTO":
        required = tuple(required_capabilities)
        observed = tuple(observed_capabilities)
        missing = set(required) - set(observed)
        status = execution_status
        if missing or not is_sha256(evidence_sha256):
            status = "blocked"
        return cls(
            name=name,
            status=status,
            required_capabilities=required,
            observed_capabilities=observed,
            evidence_sha256=evidence_sha256 if is_sha256(evidence_sha256) else None,
            details_json=canonical_json(details),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EngagementPhaseDTO":
        _reject_unknown(
            value,
            {
                "name",
                "status",
                "required_capabilities",
                "observed_capabilities",
                "missing_capabilities",
                "evidence_sha256",
                "details",
            },
            "engagement phase",
        )
        details = value.get("details", {})
        return cls(
            name=_strict_text(value.get("name"), "phase name"),
            status=_strict_text(value.get("status"), "phase status"),
            required_capabilities=_text_tuple(
                value.get("required_capabilities"), "required_capabilities"
            ),
            observed_capabilities=_text_tuple(
                value.get("observed_capabilities"),
                "observed_capabilities",
                allow_empty=True,
            ),
            evidence_sha256=(
                _strict_text(value["evidence_sha256"], "phase evidence_sha256")
                if value.get("evidence_sha256") is not None
                else None
            ),
            details_json=canonical_json(details),
        )


@dataclass(frozen=True)
class ExecutionReceiptReferenceDTO:
    """Opaque reference to an exact native Semantica execution receipt."""

    receipt_sha256: str
    package_id: str
    package_version: str
    package_digest: str

    def __post_init__(self) -> None:
        _required_sha256(self.receipt_sha256, "execution receipt_sha256")
        _required_text(self.package_id, "execution package_id")
        _required_text(self.package_version, "execution package_version")
        _required_sha256(self.package_digest, "execution package_digest")

    def as_dict(self) -> Dict[str, str]:
        return {
            "receipt_sha256": self.receipt_sha256,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "package_digest": self.package_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionReceiptReferenceDTO":
        _reject_unknown(
            value,
            {"receipt_sha256", "package_id", "package_version", "package_digest"},
            "execution receipt reference",
        )
        return cls(
            receipt_sha256=_strict_text(
                value.get("receipt_sha256"), "execution receipt_sha256"
            ),
            package_id=_strict_text(value.get("package_id"), "execution package_id"),
            package_version=_strict_text(
                value.get("package_version"), "execution package_version"
            ),
            package_digest=_strict_text(
                value.get("package_digest"), "execution package_digest"
            ),
        )


@dataclass(frozen=True)
class LearningResultDTO:
    """Explicit no-learning or candidate-learning result."""

    status: str
    rationale: str
    delta_sha256: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in _LEARNING_STATUSES:
            raise RefineryInputError("learning status must be no_delta or candidate")
        _required_text(self.rationale, "learning rationale")
        if self.status == "candidate":
            _required_sha256(self.delta_sha256, "learning delta_sha256")
        elif self.delta_sha256 is not None:
            raise RefineryInputError("no_delta learning must not bind a delta")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "rationale": self.rationale,
            "delta_sha256": self.delta_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LearningResultDTO":
        _reject_unknown(
            value,
            {"status", "rationale", "delta_sha256"},
            "learning result",
        )
        return cls(
            status=_strict_text(value.get("status"), "learning status"),
            rationale=_strict_text(value.get("rationale"), "learning rationale"),
            delta_sha256=(
                _strict_text(value["delta_sha256"], "learning delta_sha256")
                if value.get("delta_sha256") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class SemanticEngagementReceipt:
    """Mandatory five-part output of one Semantica engagement.

    The five outputs are ``execution``, ``regression``, ``receipt``,
    ``release``, and ``learning``.  The receipt is ``blocked`` whenever a phase
    lacks evidence, a requested capability is missing, or the runtime source
    identity is incomplete.
    """

    engagement_id: str
    envelope_sha256: str
    binding_sha256: str
    required_capabilities: Tuple[str, ...]
    runtime_source: RuntimeSourceIdentityDTO
    execution: EngagementPhaseDTO
    regression: EngagementPhaseDTO
    receipt: EngagementPhaseDTO
    release: EngagementPhaseDTO
    learning: LearningResultDTO
    execution_receipts: Tuple[ExecutionReceiptReferenceDTO, ...]
    status: str
    blocked_reasons: Tuple[str, ...]
    created_at: str
    receipt_sha256: str
    schema_version: str = REFINERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _required_text(self.engagement_id, "engagement_id")
        _required_sha256(self.envelope_sha256, "envelope_sha256")
        _required_sha256(self.binding_sha256, "binding_sha256")
        _validate_unique_text_tuple(
            self.required_capabilities, "engagement required_capabilities"
        )
        phases = (self.execution, self.regression, self.receipt, self.release)
        if tuple(item.name for item in phases) != _PHASE_NAMES:
            raise RefineryInputError(
                "engagement phases must be execution/regression/receipt/release"
            )
        if self.status not in {"complete", "blocked"}:
            raise RefineryInputError("engagement status must be complete or blocked")
        if self.status == "complete" and self.blocked_reasons:
            raise RefineryInputError("complete engagement cannot have blocked reasons")
        if self.status == "blocked" and not self.blocked_reasons:
            raise RefineryInputError("blocked engagement requires reasons")
        _validate_unique_by(
            self.execution_receipts,
            lambda item: item.receipt_sha256,
            "execution receipt hash",
            allow_empty=True,
        )
        _validate_timestamp(self.created_at, "engagement created_at")
        _required_sha256(self.receipt_sha256, "engagement receipt_sha256")
        _require_schema(self.schema_version)
        if self.status != self._expected_status()[0]:
            raise RefineryInputError(
                "engagement status does not match source/capability evidence"
            )
        if tuple(self.blocked_reasons) != self._expected_status()[1]:
            raise RefineryInputError(
                "engagement blocked_reasons do not match its evidence"
            )
        if not self.verify_integrity():
            raise RefineryInputError("engagement receipt hash mismatch")

    def _expected_status(self) -> Tuple[str, Tuple[str, ...]]:
        reasons: List[str] = []
        if not self.runtime_source.complete:
            reasons.append("runtime_source_identity")
        for phase in (self.execution, self.regression, self.receipt, self.release):
            if phase.status != "passed":
                reasons.append("phase.{}.{}".format(phase.name, phase.status))
            for capability in phase.missing_capabilities:
                reasons.append("capability.{}.{}".format(phase.name, capability))
            if phase.evidence_sha256 is None:
                reasons.append("evidence.{}".format(phase.name))
        if not self.execution_receipts:
            reasons.append("execution_receipt")
        for capability in sorted(
            set(self.required_capabilities) - set(self.execution.observed_capabilities)
        ):
            reasons.append("capability.engagement.{}".format(capability))
        normalized = tuple(sorted(set(reasons)))
        return ("blocked", normalized) if normalized else ("complete", ())

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "contract": REFINERY_CONTRACT,
            "engagement_id": self.engagement_id,
            "envelope_sha256": self.envelope_sha256,
            "binding_sha256": self.binding_sha256,
            "required_capabilities": list(self.required_capabilities),
            "runtime_source": self.runtime_source.as_dict(),
            "execution": self.execution.as_dict(),
            "regression": self.regression.as_dict(),
            "receipt": self.receipt.as_dict(),
            "release": self.release.as_dict(),
            "learning": self.learning.as_dict(),
            "execution_receipts": [item.as_dict() for item in self.execution_receipts],
            "status": self.status,
            "blocked_reasons": list(self.blocked_reasons),
            "created_at": self.created_at,
        }

    def verify_integrity(self) -> bool:
        return self.receipt_sha256 == sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "receipt_sha256": self.receipt_sha256}

    def to_json(self) -> str:
        return canonical_json(self.as_dict())

    @classmethod
    def create(
        cls,
        *,
        engagement_id: str,
        envelope: SemanticTaskEnvelope,
        binding: ProjectOntologyBinding,
        runtime_source: RuntimeSourceIdentityDTO,
        execution: EngagementPhaseDTO,
        regression: EngagementPhaseDTO,
        receipt: EngagementPhaseDTO,
        release: EngagementPhaseDTO,
        learning: LearningResultDTO,
        execution_receipts: Sequence[ExecutionReceiptReferenceDTO],
        created_at: Optional[str] = None,
    ) -> "SemanticEngagementReceipt":
        if (
            envelope.project_id != binding.project_id
            or envelope.domain != binding.domain
        ):
            raise RefineryInputError(
                "task envelope project/domain differs from ontology binding"
            )
        when = created_at or utc_now()
        # Determine the fail-closed status without constructing an inconsistent
        # frozen dataclass first.
        phase_tuple = (execution, regression, receipt, release)
        reasons: List[str] = []
        if not runtime_source.complete:
            reasons.append("runtime_source_identity")
        for phase in phase_tuple:
            if phase.status != "passed":
                reasons.append("phase.{}.{}".format(phase.name, phase.status))
            for capability in phase.missing_capabilities:
                reasons.append("capability.{}.{}".format(phase.name, capability))
            if phase.evidence_sha256 is None:
                reasons.append("evidence.{}".format(phase.name))
        if not execution_receipts:
            reasons.append("execution_receipt")
        for capability in sorted(
            set(envelope.required_capabilities) - set(execution.observed_capabilities)
        ):
            reasons.append("capability.engagement.{}".format(capability))
        blocked = tuple(sorted(set(reasons)))
        status = "blocked" if blocked else "complete"
        content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "contract": REFINERY_CONTRACT,
            "engagement_id": engagement_id,
            "envelope_sha256": envelope.envelope_sha256,
            "binding_sha256": binding.binding_sha256,
            "required_capabilities": list(envelope.required_capabilities),
            "runtime_source": runtime_source.as_dict(),
            "execution": execution.as_dict(),
            "regression": regression.as_dict(),
            "receipt": receipt.as_dict(),
            "release": release.as_dict(),
            "learning": learning.as_dict(),
            "execution_receipts": [item.as_dict() for item in execution_receipts],
            "status": status,
            "blocked_reasons": list(blocked),
            "created_at": when,
        }
        return cls(
            engagement_id=engagement_id,
            envelope_sha256=envelope.envelope_sha256,
            binding_sha256=binding.binding_sha256,
            required_capabilities=envelope.required_capabilities,
            runtime_source=runtime_source,
            execution=execution,
            regression=regression,
            receipt=receipt,
            release=release,
            learning=learning,
            execution_receipts=tuple(execution_receipts),
            status=status,
            blocked_reasons=blocked,
            created_at=when,
            receipt_sha256=sha256_text(canonical_json(content)),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SemanticEngagementReceipt":
        _reject_unknown(
            value,
            {
                "schema_version",
                "contract",
                "engagement_id",
                "envelope_sha256",
                "binding_sha256",
                "required_capabilities",
                "runtime_source",
                "execution",
                "regression",
                "receipt",
                "release",
                "learning",
                "execution_receipts",
                "status",
                "blocked_reasons",
                "created_at",
                "receipt_sha256",
            },
            "semantic engagement receipt",
        )
        if value.get("contract") != REFINERY_CONTRACT:
            raise RefineryInputError(
                "engagement contract must exactly match {}".format(REFINERY_CONTRACT)
            )
        return cls(
            engagement_id=_strict_text(value.get("engagement_id"), "engagement_id"),
            envelope_sha256=_strict_text(
                value.get("envelope_sha256"), "envelope_sha256"
            ),
            binding_sha256=_strict_text(value.get("binding_sha256"), "binding_sha256"),
            required_capabilities=_text_tuple(
                value.get("required_capabilities"), "required_capabilities"
            ),
            runtime_source=RuntimeSourceIdentityDTO.from_dict(
                _mapping(value.get("runtime_source"), "runtime_source")
            ),
            execution=EngagementPhaseDTO.from_dict(
                _mapping(value.get("execution"), "execution")
            ),
            regression=EngagementPhaseDTO.from_dict(
                _mapping(value.get("regression"), "regression")
            ),
            receipt=EngagementPhaseDTO.from_dict(
                _mapping(value.get("receipt"), "receipt")
            ),
            release=EngagementPhaseDTO.from_dict(
                _mapping(value.get("release"), "release")
            ),
            learning=LearningResultDTO.from_dict(
                _mapping(value.get("learning"), "learning")
            ),
            execution_receipts=tuple(
                ExecutionReceiptReferenceDTO.from_dict(item)
                for item in _mapping_list(
                    value.get("execution_receipts"), "execution_receipts"
                )
            ),
            status=_strict_text(value.get("status"), "engagement status"),
            blocked_reasons=_text_tuple(
                value.get("blocked_reasons"), "blocked_reasons", allow_empty=True
            ),
            created_at=_strict_text(value.get("created_at"), "created_at"),
            receipt_sha256=_strict_text(value.get("receipt_sha256"), "receipt_sha256"),
            schema_version=_strict_text(
                value.get("schema_version", REFINERY_SCHEMA_VERSION),
                "schema_version",
            ),
        )


@dataclass(frozen=True)
class PackageAssetDeltaDTO:
    """One content-addressed semantic asset mutation."""

    category: str
    asset_id: str
    operation: str
    media_type: str
    sha256: str
    content_base64: Optional[str]
    replaces_sha256: Optional[str] = None
    role: Optional[str] = None
    case_kind: Optional[str] = None

    def __post_init__(self) -> None:
        if self.category not in PACKAGE_ASSET_CATEGORIES:
            raise RefineryInputError("unsupported package asset category")
        _validate_opaque_id(self.asset_id, "asset_id")
        if self.operation not in _ASSET_OPERATIONS:
            raise RefineryInputError("asset operation must be add, replace, or remove")
        _required_text(self.media_type, "asset media_type")
        _required_sha256(self.sha256, "asset sha256")
        if self.role is not None:
            _required_text(self.role, "asset role")
        if self.category == "cases":
            if self.case_kind not in CASE_KINDS:
                raise RefineryInputError(
                    "case asset requires positive/negative/ambiguity/prior_release"
                )
        elif self.case_kind is not None:
            raise RefineryInputError("only case assets may declare case_kind")
        if self.operation == "remove":
            if self.content_base64 is not None:
                raise RefineryInputError("remove asset must not carry content")
            _required_sha256(self.replaces_sha256, "remove replaces_sha256")
            if self.sha256 != self.replaces_sha256:
                raise RefineryInputError(
                    "remove sha256 must identify the exact replaced content"
                )
        else:
            if self.content_base64 is None:
                raise RefineryInputError("add/replace asset requires content_base64")
            try:
                payload = base64.b64decode(self.content_base64, validate=True)
            except Exception as exc:
                raise RefineryInputError("asset content_base64 is invalid") from exc
            if _sha256_bytes(payload) != self.sha256:
                raise RefineryInputError("asset sha256 does not match content")
            if self.operation == "replace":
                _required_sha256(self.replaces_sha256, "replace replaces_sha256")
            elif self.replaces_sha256 is not None:
                raise RefineryInputError("add asset must not declare replaces_sha256")

    @property
    def content_bytes(self) -> Optional[bytes]:
        if self.content_base64 is None:
            return None
        return base64.b64decode(self.content_base64)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "asset_id": self.asset_id,
            "operation": self.operation,
            "media_type": self.media_type,
            "sha256": self.sha256,
            "content_base64": self.content_base64,
            "replaces_sha256": self.replaces_sha256,
            "role": self.role,
            "case_kind": self.case_kind,
        }

    @classmethod
    def add_text(
        cls,
        *,
        category: str,
        asset_id: str,
        content: str,
        media_type: str = "text/plain",
        role: Optional[str] = None,
        case_kind: Optional[str] = None,
    ) -> "PackageAssetDeltaDTO":
        payload = content.encode("utf-8")
        return cls(
            category=category,
            asset_id=asset_id,
            operation="add",
            media_type=media_type,
            sha256=_sha256_bytes(payload),
            content_base64=base64.b64encode(payload).decode("ascii"),
            role=role,
            case_kind=case_kind,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PackageAssetDeltaDTO":
        _reject_unknown(
            value,
            {
                "category",
                "asset_id",
                "operation",
                "media_type",
                "sha256",
                "content_base64",
                "replaces_sha256",
                "role",
                "case_kind",
            },
            "package asset delta",
        )
        return cls(
            category=_strict_text(value.get("category"), "asset category"),
            asset_id=_strict_text(value.get("asset_id"), "asset_id"),
            operation=_strict_text(value.get("operation"), "asset operation"),
            media_type=_strict_text(value.get("media_type"), "asset media_type"),
            sha256=_strict_text(value.get("sha256"), "asset sha256"),
            content_base64=(
                _exact_string(value["content_base64"], "asset content_base64")
                if value.get("content_base64") is not None
                else None
            ),
            replaces_sha256=(
                _strict_text(value["replaces_sha256"], "asset replaces_sha256")
                if value.get("replaces_sha256") is not None
                else None
            ),
            role=(
                _strict_text(value["role"], "asset role")
                if value.get("role") is not None
                else None
            ),
            case_kind=(
                _strict_text(value["case_kind"], "asset case_kind")
                if value.get("case_kind") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class PackageDelta:
    """Complete package delta across every executable semantic asset family."""

    package_id: str
    base_version: str
    base_package_sha256: str
    target_version: str
    rationale: str
    created_by: str
    created_at: str
    required_capabilities: Tuple[str, ...]
    source_evidence: Tuple[SourceEvidenceDTO, ...]
    book_impact: str
    ontology: Tuple[PackageAssetDeltaDTO, ...] = ()
    competency_questions: Tuple[PackageAssetDeltaDTO, ...] = ()
    shapes: Tuple[PackageAssetDeltaDTO, ...] = ()
    queries: Tuple[PackageAssetDeltaDTO, ...] = ()
    rules: Tuple[PackageAssetDeltaDTO, ...] = ()
    cases: Tuple[PackageAssetDeltaDTO, ...] = ()
    contract: Tuple[PackageAssetDeltaDTO, ...] = ()
    provenance: Tuple[PackageAssetDeltaDTO, ...] = ()
    schema_version: str = REFINERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_package_id(self.package_id)
        _required_text(self.base_version, "base_version")
        _required_sha256(self.base_package_sha256, "base_package_sha256")
        _required_text(self.target_version, "target_version")
        if self.target_version == self.base_version:
            raise RefineryInputError("target_version must differ from base_version")
        if (
            self.base_version == "0"
            and self.base_package_sha256 != EMPTY_PACKAGE_SHA256
        ):
            raise RefineryInputError("base version 0 must bind EMPTY_PACKAGE_SHA256")
        _required_text(self.rationale, "delta rationale")
        _required_text(self.created_by, "delta created_by")
        _validate_timestamp(self.created_at, "delta created_at")
        _validate_unique_text_tuple(
            self.required_capabilities, "delta required_capabilities"
        )
        if not self.source_evidence:
            raise RefineryInputError(
                "package delta requires at least one source identity/hash"
            )
        _validate_unique_by(
            self.source_evidence,
            lambda item: item.source_id,
            "delta source_evidence source_id",
        )
        if self.book_impact not in BOOK_IMPACTS:
            raise RefineryInputError(
                "book_impact must be none, vol1-method, vol2-iso-exemplar, or both"
            )
        all_assets = self.assets
        if not all_assets:
            raise RefineryInputError(
                "package delta must contain at least one asset change"
            )
        expected = (
            ("ontology", self.ontology),
            ("competency_questions", self.competency_questions),
            ("shapes", self.shapes),
            ("queries", self.queries),
            ("rules", self.rules),
            ("cases", self.cases),
            ("contract", self.contract),
            ("provenance", self.provenance),
        )
        for category, items in expected:
            for item in items:
                if item.category != category:
                    raise RefineryInputError(
                        "{} list contains {} asset".format(category, item.category)
                    )
        _validate_unique_by(
            all_assets,
            lambda item: (item.category, item.asset_id),
            "package delta category/asset_id",
        )
        _validate_unique_by(
            all_assets,
            lambda item: item.asset_id,
            "package delta asset_id",
        )
        _require_schema(self.schema_version)

    @property
    def assets(self) -> Tuple[PackageAssetDeltaDTO, ...]:
        return (
            self.ontology
            + self.competency_questions
            + self.shapes
            + self.queries
            + self.rules
            + self.cases
            + self.contract
            + self.provenance
        )

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "package_id": self.package_id,
            "base_version": self.base_version,
            "base_package_sha256": self.base_package_sha256,
            "target_version": self.target_version,
            "rationale": self.rationale,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "required_capabilities": list(self.required_capabilities),
            "source_evidence": [item.as_dict() for item in self.source_evidence],
            "book_impact": self.book_impact,
            "ontology": [item.as_dict() for item in self.ontology],
            "competency_questions": [
                item.as_dict() for item in self.competency_questions
            ],
            "shapes": [item.as_dict() for item in self.shapes],
            "queries": [item.as_dict() for item in self.queries],
            "rules": [item.as_dict() for item in self.rules],
            "cases": [item.as_dict() for item in self.cases],
            "contract": [item.as_dict() for item in self.contract],
            "provenance": [item.as_dict() for item in self.provenance],
        }

    @property
    def delta_sha256(self) -> str:
        return sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "delta_sha256": self.delta_sha256}

    def to_json(self) -> str:
        return canonical_json(self.as_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PackageDelta":
        _reject_unknown(
            value,
            {
                "schema_version",
                "package_id",
                "base_version",
                "base_package_sha256",
                "target_version",
                "rationale",
                "created_by",
                "created_at",
                "required_capabilities",
                "source_evidence",
                "book_impact",
                "ontology",
                "competency_questions",
                "shapes",
                "queries",
                "rules",
                "cases",
                "contract",
                "provenance",
                "delta_sha256",
            },
            "package delta",
        )
        missing_categories = [
            category for category in PACKAGE_ASSET_CATEGORIES if category not in value
        ]
        if missing_categories:
            raise RefineryInputError(
                "package delta must explicitly declare all asset arrays; missing: {}".format(
                    ", ".join(missing_categories)
                )
            )

        def assets(category: str) -> Tuple[PackageAssetDeltaDTO, ...]:
            return tuple(
                PackageAssetDeltaDTO.from_dict(item)
                for item in _mapping_list(value.get(category, []), category)
            )

        result = cls(
            package_id=_strict_text(value.get("package_id"), "package_id"),
            base_version=_strict_text(value.get("base_version"), "base_version"),
            base_package_sha256=_strict_text(
                value.get("base_package_sha256"), "base_package_sha256"
            ),
            target_version=_strict_text(value.get("target_version"), "target_version"),
            rationale=_strict_text(value.get("rationale"), "delta rationale"),
            created_by=_strict_text(value.get("created_by"), "delta created_by"),
            created_at=_strict_text(value.get("created_at"), "delta created_at"),
            required_capabilities=_text_tuple(
                value.get("required_capabilities"), "required_capabilities"
            ),
            source_evidence=tuple(
                SourceEvidenceDTO.from_dict(item)
                for item in _mapping_list(
                    value.get("source_evidence"), "source_evidence"
                )
            ),
            book_impact=_strict_text(value.get("book_impact"), "book_impact"),
            ontology=assets("ontology"),
            competency_questions=assets("competency_questions"),
            shapes=assets("shapes"),
            queries=assets("queries"),
            rules=assets("rules"),
            cases=assets("cases"),
            contract=assets("contract"),
            provenance=assets("provenance"),
            schema_version=_strict_text(
                value.get("schema_version", REFINERY_SCHEMA_VERSION),
                "schema_version",
            ),
        )
        _check_declared_digest(value, "delta_sha256", result.delta_sha256)
        return result


@dataclass(frozen=True)
class AssetDecisionDTO:
    """One explicit decision over an exact destructive asset mutation."""

    category: str
    asset_id: str
    operation: str
    replaces_sha256: str
    verdict: str
    reason: str

    def __post_init__(self) -> None:
        if self.category not in PACKAGE_ASSET_CATEGORIES:
            raise RefineryInputError("asset decision category is invalid")
        _validate_opaque_id(self.asset_id, "asset decision asset_id")
        if self.operation not in {"replace", "remove"}:
            raise RefineryInputError(
                "asset decision operation must be replace or remove"
            )
        _required_sha256(self.replaces_sha256, "asset decision replaces_sha256")
        if self.verdict != "approve":
            raise RefineryInputError("asset decision verdict must be approve")
        _required_text(self.reason, "asset decision reason")

    @property
    def key(self) -> Tuple[str, str, str, str]:
        return (
            self.category,
            self.asset_id,
            self.operation,
            self.replaces_sha256,
        )

    def as_dict(self) -> Dict[str, str]:
        return {
            "category": self.category,
            "asset_id": self.asset_id,
            "operation": self.operation,
            "replaces_sha256": self.replaces_sha256,
            "verdict": self.verdict,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AssetDecisionDTO":
        _reject_unknown(
            value,
            {
                "category",
                "asset_id",
                "operation",
                "replaces_sha256",
                "verdict",
                "reason",
            },
            "asset decision",
        )
        return cls(
            category=_strict_text(value.get("category"), "asset decision category"),
            asset_id=_strict_text(value.get("asset_id"), "asset decision asset_id"),
            operation=_strict_text(value.get("operation"), "asset decision operation"),
            replaces_sha256=_strict_text(
                value.get("replaces_sha256"),
                "asset decision replaces_sha256",
            ),
            verdict=_strict_text(value.get("verdict"), "asset decision verdict"),
            reason=_strict_text(value.get("reason"), "asset decision reason"),
        )


@dataclass(frozen=True)
class RefineryAuthorizationDTO:
    """Explicit, content-bound decision-authority action."""

    authorization_id: str
    action: str
    actor_id: str
    authority: str
    package_id: str
    delta_sha256: str
    promotion_target: str
    reason: str
    source: SourceEvidenceDTO
    issued_at: str
    decisions: Tuple[AssetDecisionDTO, ...] = ()

    def __post_init__(self) -> None:
        _required_text(self.authorization_id, "authorization_id")
        if self.action not in _AUTHORIZATION_ACTIONS:
            raise RefineryInputError("authorization action must be commit or promote")
        _required_text(self.actor_id, "authorization actor_id")
        _required_text(self.authority, "authorization authority")
        _validate_package_id(self.package_id)
        _required_sha256(self.delta_sha256, "authorization delta_sha256")
        _required_text(self.promotion_target, "authorization promotion_target")
        if self.promotion_target != INDUSTRY_REGISTRY_TARGET:
            raise RefineryInputError(
                "authorization promotion_target must exactly match {}".format(
                    INDUSTRY_REGISTRY_TARGET
                )
            )
        _required_text(self.reason, "authorization reason")
        _validate_timestamp(self.issued_at, "authorization issued_at")
        _validate_unique_by(
            self.decisions,
            lambda item: item.key,
            "authorization asset decision",
            allow_empty=True,
        )

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "action": self.action,
            "actor_id": self.actor_id,
            "authority": self.authority,
            "package_id": self.package_id,
            "delta_sha256": self.delta_sha256,
            "promotion_target": self.promotion_target,
            "reason": self.reason,
            "source": self.source.as_dict(),
            "issued_at": self.issued_at,
            "decisions": [item.as_dict() for item in self.decisions],
        }

    @property
    def authorization_sha256(self) -> str:
        return sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {
            **self._content_dict(),
            "authorization_sha256": self.authorization_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RefineryAuthorizationDTO":
        _reject_unknown(
            value,
            {
                "authorization_id",
                "action",
                "actor_id",
                "authority",
                "package_id",
                "delta_sha256",
                "promotion_target",
                "reason",
                "source",
                "issued_at",
                "decisions",
                "authorization_sha256",
            },
            "refinery authorization",
        )
        result = cls(
            authorization_id=_strict_text(
                value.get("authorization_id"), "authorization_id"
            ),
            action=_strict_text(value.get("action"), "authorization action"),
            actor_id=_strict_text(value.get("actor_id"), "authorization actor_id"),
            authority=_strict_text(value.get("authority"), "authorization authority"),
            package_id=_strict_text(
                value.get("package_id"), "authorization package_id"
            ),
            delta_sha256=_strict_text(
                value.get("delta_sha256"), "authorization delta_sha256"
            ),
            promotion_target=_strict_text(
                value.get("promotion_target"), "authorization promotion_target"
            ),
            reason=_strict_text(value.get("reason"), "authorization reason"),
            source=SourceEvidenceDTO.from_dict(
                _mapping(value.get("source"), "authorization source")
            ),
            issued_at=_strict_text(value.get("issued_at"), "authorization issued_at"),
            decisions=tuple(
                AssetDecisionDTO.from_dict(item)
                for item in _mapping_list(
                    value.get("decisions"), "authorization decisions"
                )
            ),
        )
        _check_declared_digest(
            value, "authorization_sha256", result.authorization_sha256
        )
        return result


@dataclass(frozen=True)
class GateCheckDTO:
    """One regression or release check."""

    check_id: str
    passed: bool
    message: str
    output_sha256: str

    def __post_init__(self) -> None:
        _required_text(self.check_id, "gate check_id")
        if not isinstance(self.passed, bool):
            raise RefineryInputError("gate passed must be boolean")
        _required_text(self.message, "gate message")
        _required_sha256(self.output_sha256, "gate output_sha256")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "passed": self.passed,
            "message": self.message,
            "output_sha256": self.output_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GateCheckDTO":
        _reject_unknown(
            value,
            {"check_id", "passed", "message", "output_sha256"},
            "gate check",
        )
        return cls(
            check_id=_strict_text(value.get("check_id"), "gate check_id"),
            passed=value.get("passed"),
            message=_strict_text(value.get("message"), "gate message"),
            output_sha256=_strict_text(
                value.get("output_sha256"), "gate output_sha256"
            ),
        )


@dataclass(frozen=True)
class RefineryGateEvidenceDTO:
    """Content-bound regression or release evidence."""

    gate: str
    package_sha256: str
    execution_suite_sha256: str
    execution_suite_object_sha256: str
    transition_context_sha256: str
    transition_context_object_sha256: str
    provenance_closure_sha256: str
    provenance_closure_object_sha256: str
    runtime_source: RuntimeSourceIdentityDTO
    required_capabilities: Tuple[str, ...]
    observed_capabilities: Tuple[str, ...]
    checks: Tuple[GateCheckDTO, ...]
    status: str
    recorded_at: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if self.gate not in {"regression", "release"}:
            raise RefineryInputError("gate must be regression or release")
        _required_sha256(self.package_sha256, "gate package_sha256")
        _required_sha256(self.execution_suite_sha256, "gate execution_suite_sha256")
        _required_sha256(
            self.execution_suite_object_sha256,
            "gate execution_suite_object_sha256",
        )
        _required_sha256(
            self.transition_context_sha256, "gate transition_context_sha256"
        )
        _required_sha256(
            self.transition_context_object_sha256,
            "gate transition_context_object_sha256",
        )
        _required_sha256(
            self.provenance_closure_sha256,
            "gate provenance_closure_sha256",
        )
        _required_sha256(
            self.provenance_closure_object_sha256,
            "gate provenance_closure_object_sha256",
        )
        _validate_unique_text_tuple(
            self.required_capabilities, "gate required_capabilities"
        )
        _validate_unique_text_tuple(
            self.observed_capabilities,
            "gate observed_capabilities",
            allow_empty=True,
        )
        if not self.checks:
            raise RefineryInputError("gate evidence requires checks")
        _validate_unique_by(self.checks, lambda item: item.check_id, "gate check_id")
        expected_check_ids = (
            REGRESSION_REQUIRED_CHECK_IDS
            if self.gate == "regression"
            else RELEASE_REQUIRED_CHECK_IDS
        )
        if tuple(item.check_id for item in self.checks) != expected_check_ids:
            raise RefineryInputError(
                "gate evidence must contain the fixed checks in contract order"
            )
        expected = "complete" if self.complete else "blocked"
        if self.status != expected:
            raise RefineryInputError("gate status does not match its evidence")
        _validate_timestamp(self.recorded_at, "gate recorded_at")
        _required_sha256(self.evidence_sha256, "gate evidence_sha256")
        if not self.verify_integrity():
            raise RefineryInputError("gate evidence hash mismatch")

    @property
    def missing_capabilities(self) -> Tuple[str, ...]:
        return tuple(
            sorted(set(self.required_capabilities) - set(self.observed_capabilities))
        )

    @property
    def complete(self) -> bool:
        return bool(
            self.runtime_source.complete
            and not self.missing_capabilities
            and self.checks
            and all(item.passed for item in self.checks)
        )

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "gate": self.gate,
            "package_sha256": self.package_sha256,
            "execution_suite_sha256": self.execution_suite_sha256,
            "execution_suite_object_sha256": self.execution_suite_object_sha256,
            "transition_context_sha256": self.transition_context_sha256,
            "transition_context_object_sha256": (self.transition_context_object_sha256),
            "provenance_closure_sha256": self.provenance_closure_sha256,
            "provenance_closure_object_sha256": (self.provenance_closure_object_sha256),
            "runtime_source": self.runtime_source.as_dict(),
            "required_capabilities": list(self.required_capabilities),
            "observed_capabilities": list(self.observed_capabilities),
            "checks": [item.as_dict() for item in self.checks],
            "status": self.status,
            "recorded_at": self.recorded_at,
        }

    def verify_integrity(self) -> bool:
        return self.evidence_sha256 == sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {
            **self._content_dict(),
            "missing_capabilities": list(self.missing_capabilities),
            "evidence_sha256": self.evidence_sha256,
        }

    @classmethod
    def create(
        cls,
        *,
        gate: str,
        package_sha256: str,
        execution_suite_sha256: str,
        execution_suite_object_sha256: str,
        transition_context_sha256: str,
        transition_context_object_sha256: str,
        provenance_closure_sha256: str,
        provenance_closure_object_sha256: str,
        runtime_source: RuntimeSourceIdentityDTO,
        required_capabilities: Sequence[str],
        observed_capabilities: Sequence[str],
        checks: Sequence[GateCheckDTO],
        recorded_at: Optional[str] = None,
    ) -> "RefineryGateEvidenceDTO":
        required = tuple(required_capabilities)
        observed = tuple(observed_capabilities)
        when = recorded_at or utc_now()
        complete = bool(
            runtime_source.complete
            and not (set(required) - set(observed))
            and checks
            and all(item.passed for item in checks)
        )
        status = "complete" if complete else "blocked"
        content = {
            "gate": gate,
            "package_sha256": package_sha256,
            "execution_suite_sha256": execution_suite_sha256,
            "execution_suite_object_sha256": execution_suite_object_sha256,
            "transition_context_sha256": transition_context_sha256,
            "transition_context_object_sha256": transition_context_object_sha256,
            "provenance_closure_sha256": provenance_closure_sha256,
            "provenance_closure_object_sha256": (provenance_closure_object_sha256),
            "runtime_source": runtime_source.as_dict(),
            "required_capabilities": list(required),
            "observed_capabilities": list(observed),
            "checks": [item.as_dict() for item in checks],
            "status": status,
            "recorded_at": when,
        }
        return cls(
            gate=gate,
            package_sha256=package_sha256,
            execution_suite_sha256=execution_suite_sha256,
            execution_suite_object_sha256=execution_suite_object_sha256,
            transition_context_sha256=transition_context_sha256,
            transition_context_object_sha256=transition_context_object_sha256,
            provenance_closure_sha256=provenance_closure_sha256,
            provenance_closure_object_sha256=(provenance_closure_object_sha256),
            runtime_source=runtime_source,
            required_capabilities=required,
            observed_capabilities=observed,
            checks=tuple(checks),
            status=status,
            recorded_at=when,
            evidence_sha256=sha256_text(canonical_json(content)),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RefineryGateEvidenceDTO":
        _reject_unknown(
            value,
            {
                "gate",
                "package_sha256",
                "execution_suite_sha256",
                "execution_suite_object_sha256",
                "transition_context_sha256",
                "transition_context_object_sha256",
                "provenance_closure_sha256",
                "provenance_closure_object_sha256",
                "runtime_source",
                "required_capabilities",
                "observed_capabilities",
                "missing_capabilities",
                "checks",
                "status",
                "recorded_at",
                "evidence_sha256",
            },
            "refinery gate evidence",
        )
        return cls(
            gate=_strict_text(value.get("gate"), "gate"),
            package_sha256=_strict_text(
                value.get("package_sha256"), "gate package_sha256"
            ),
            execution_suite_sha256=_strict_text(
                value.get("execution_suite_sha256"),
                "gate execution_suite_sha256",
            ),
            execution_suite_object_sha256=_strict_text(
                value.get("execution_suite_object_sha256"),
                "gate execution_suite_object_sha256",
            ),
            transition_context_sha256=_strict_text(
                value.get("transition_context_sha256"),
                "gate transition_context_sha256",
            ),
            transition_context_object_sha256=_strict_text(
                value.get("transition_context_object_sha256"),
                "gate transition_context_object_sha256",
            ),
            provenance_closure_sha256=_strict_text(
                value.get("provenance_closure_sha256"),
                "gate provenance_closure_sha256",
            ),
            provenance_closure_object_sha256=_strict_text(
                value.get("provenance_closure_object_sha256"),
                "gate provenance_closure_object_sha256",
            ),
            runtime_source=RuntimeSourceIdentityDTO.from_dict(
                _mapping(value.get("runtime_source"), "runtime_source")
            ),
            required_capabilities=_text_tuple(
                value.get("required_capabilities"), "required_capabilities"
            ),
            observed_capabilities=_text_tuple(
                value.get("observed_capabilities"),
                "observed_capabilities",
                allow_empty=True,
            ),
            checks=tuple(
                GateCheckDTO.from_dict(item)
                for item in _mapping_list(value.get("checks"), "checks")
            ),
            status=_strict_text(value.get("status"), "gate status"),
            recorded_at=_strict_text(value.get("recorded_at"), "gate recorded_at"),
            evidence_sha256=_strict_text(
                value.get("evidence_sha256"), "gate evidence_sha256"
            ),
        )


@dataclass(frozen=True)
class SubjectScenarioRunDTO:
    """CAS bindings for one scenario actually executed by Semantica."""

    scenario_id: str
    run_result_object_sha256: str
    receipt_sha256: str
    receipt_object_sha256: str
    executor_package_id: str
    executor_package_version: str
    executor_package_digest: str
    cq_ids: Tuple[str, ...]
    case_assets: Tuple[Tuple[str, str, str], ...]
    status: str
    release_status: str

    def __post_init__(self) -> None:
        _required_text(self.scenario_id, "suite scenario_id")
        for field, value in (
            ("run_result_object_sha256", self.run_result_object_sha256),
            ("receipt_sha256", self.receipt_sha256),
            ("receipt_object_sha256", self.receipt_object_sha256),
            ("executor_package_digest", self.executor_package_digest),
        ):
            _required_sha256(value, field)
        _validate_package_id(self.executor_package_id)
        _required_text(self.executor_package_version, "executor package version")
        _validate_unique_text_tuple(self.cq_ids, "suite run cq_ids", allow_empty=True)
        if tuple(sorted(self.case_assets)) != self.case_assets:
            raise RefineryInputError("suite run case_assets must be sorted")
        seen_cases = set()
        for case_kind, asset_id, digest in self.case_assets:
            if case_kind not in CASE_KINDS:
                raise RefineryInputError("suite run case_kind is invalid")
            _validate_opaque_id(asset_id, "suite run case asset_id")
            _required_sha256(digest, "suite run case asset sha256")
            identity = (case_kind, asset_id)
            if identity in seen_cases:
                raise RefineryInputError("suite run case asset is duplicated")
            seen_cases.add(identity)
        if self.status not in _PHASE_STATUSES:
            raise RefineryInputError("suite run status is invalid")
        if self.release_status not in {"complete", "blocked"}:
            raise RefineryInputError("suite run release_status is invalid")

    def as_dict(self) -> Dict[str, str]:
        return {
            "scenario_id": self.scenario_id,
            "run_result_object_sha256": self.run_result_object_sha256,
            "receipt_sha256": self.receipt_sha256,
            "receipt_object_sha256": self.receipt_object_sha256,
            "executor_package_id": self.executor_package_id,
            "executor_package_version": self.executor_package_version,
            "executor_package_digest": self.executor_package_digest,
            "cq_ids": list(self.cq_ids),
            "case_assets": [
                {
                    "case_kind": case_kind,
                    "asset_id": asset_id,
                    "sha256": digest,
                }
                for case_kind, asset_id, digest in self.case_assets
            ],
            "status": self.status,
            "release_status": self.release_status,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SubjectScenarioRunDTO":
        allowed = {
            "scenario_id",
            "run_result_object_sha256",
            "receipt_sha256",
            "receipt_object_sha256",
            "executor_package_id",
            "executor_package_version",
            "executor_package_digest",
            "cq_ids",
            "case_assets",
            "status",
            "release_status",
        }
        _reject_unknown(value, allowed, "subject scenario run")
        return cls(
            scenario_id=_strict_text(value.get("scenario_id"), "scenario_id"),
            run_result_object_sha256=_strict_text(
                value.get("run_result_object_sha256"),
                "run_result_object_sha256",
            ),
            receipt_sha256=_strict_text(value.get("receipt_sha256"), "receipt_sha256"),
            receipt_object_sha256=_strict_text(
                value.get("receipt_object_sha256"), "receipt_object_sha256"
            ),
            executor_package_id=_strict_text(
                value.get("executor_package_id"), "executor_package_id"
            ),
            executor_package_version=_strict_text(
                value.get("executor_package_version"),
                "executor_package_version",
            ),
            executor_package_digest=_strict_text(
                value.get("executor_package_digest"), "executor_package_digest"
            ),
            cq_ids=_text_tuple(
                value.get("cq_ids"), "suite run cq_ids", allow_empty=True
            ),
            case_assets=_case_asset_tuple(value.get("case_assets")),
            status=_strict_text(value.get("status"), "suite run status"),
            release_status=_strict_text(
                value.get("release_status"), "suite run release_status"
            ),
        )


@dataclass(frozen=True)
class ProvenanceScenarioBindingDTO:
    """Exact native I/O and receipt bindings for one executed scenario."""

    scenario_id: str
    input_asset_hashes: Tuple[Tuple[str, str], ...]
    case_assets: Tuple[Tuple[str, str, str], ...]
    output_hashes: Tuple[Tuple[str, str], ...]
    run_result_object_sha256: str
    receipt_sha256: str
    receipt_object_sha256: str
    native_provenance_bundle_sha256: str

    def __post_init__(self) -> None:
        _required_text(self.scenario_id, "provenance scenario_id")
        for field, pairs in (
            ("input_asset_hashes", self.input_asset_hashes),
            ("output_hashes", self.output_hashes),
        ):
            if tuple(sorted(pairs)) != pairs or len({key for key, _ in pairs}) != len(
                pairs
            ):
                raise RefineryInputError("{} must be sorted and unique".format(field))
            for key, digest in pairs:
                _required_text(key, "{} key".format(field))
                _required_sha256(digest, "{} sha256".format(field))
        if tuple(sorted(self.case_assets)) != self.case_assets:
            raise RefineryInputError("provenance case_assets must be sorted")
        for case_kind, asset_id, digest in self.case_assets:
            if case_kind not in CASE_KINDS:
                raise RefineryInputError("provenance case kind is invalid")
            _validate_opaque_id(asset_id, "provenance case asset_id")
            _required_sha256(digest, "provenance case sha256")
        for field, value in (
            ("run_result_object_sha256", self.run_result_object_sha256),
            ("receipt_sha256", self.receipt_sha256),
            ("receipt_object_sha256", self.receipt_object_sha256),
            (
                "native_provenance_bundle_sha256",
                self.native_provenance_bundle_sha256,
            ),
        ):
            _required_sha256(value, field)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "input_asset_hashes": dict(self.input_asset_hashes),
            "case_assets": [
                {"case_kind": kind, "asset_id": asset_id, "sha256": digest}
                for kind, asset_id, digest in self.case_assets
            ],
            "output_hashes": dict(self.output_hashes),
            "run_result_object_sha256": self.run_result_object_sha256,
            "receipt_sha256": self.receipt_sha256,
            "receipt_object_sha256": self.receipt_object_sha256,
            "native_provenance_bundle_sha256": (self.native_provenance_bundle_sha256),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProvenanceScenarioBindingDTO":
        fields = {
            "scenario_id",
            "input_asset_hashes",
            "case_assets",
            "output_hashes",
            "run_result_object_sha256",
            "receipt_sha256",
            "receipt_object_sha256",
            "native_provenance_bundle_sha256",
        }
        _reject_unknown(value, fields, "provenance scenario binding")
        if set(value) != fields:
            raise RefineryInputError("provenance scenario binding is incomplete")

        def pairs(name: str) -> Tuple[Tuple[str, str], ...]:
            raw = _mapping(value.get(name), name)
            return tuple(
                sorted(
                    (
                        _strict_text(key, "{} key".format(name)),
                        _strict_text(digest, "{} sha256".format(name)),
                    )
                    for key, digest in raw.items()
                )
            )

        return cls(
            scenario_id=_strict_text(value.get("scenario_id"), "scenario_id"),
            input_asset_hashes=pairs("input_asset_hashes"),
            case_assets=_case_asset_tuple(value.get("case_assets")),
            output_hashes=pairs("output_hashes"),
            run_result_object_sha256=_strict_text(
                value.get("run_result_object_sha256"),
                "run_result_object_sha256",
            ),
            receipt_sha256=_strict_text(value.get("receipt_sha256"), "receipt_sha256"),
            receipt_object_sha256=_strict_text(
                value.get("receipt_object_sha256"), "receipt_object_sha256"
            ),
            native_provenance_bundle_sha256=_strict_text(
                value.get("native_provenance_bundle_sha256"),
                "native_provenance_bundle_sha256",
            ),
        )


@dataclass(frozen=True)
class ProvenanceClosureDTO:
    """Replayable closure from source evidence to native execution bytes."""

    phase: str
    workspace_id: str
    delta_sha256: str
    package_id: str
    package_version: str
    package_sha256: str
    manifest_sha256: str
    execution_projection_sha256: str
    source_evidence: Tuple[SourceEvidenceDTO, ...]
    candidate_envelope_sha256: str
    candidate_binding_sha256: str
    engagement_receipt_sha256: str
    transition_contexts: Tuple[Tuple[str, str, str], ...]
    runtime_source: RuntimeSourceIdentityDTO
    provenance_evidence_assets: Tuple[Tuple[str, str], ...]
    scenarios: Tuple[ProvenanceScenarioBindingDTO, ...]
    prior_closure_sha256: Optional[str]
    closure_sha256: str
    schema_version: str = REFINERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.phase not in {"execution", "regression", "release", "promotion"}:
            raise RefineryInputError("provenance closure phase is invalid")
        _validate_opaque_id(self.workspace_id, "closure workspace_id")
        _validate_package_id(self.package_id)
        _required_text(self.package_version, "closure package_version")
        for field, value in (
            ("delta_sha256", self.delta_sha256),
            ("package_sha256", self.package_sha256),
            ("manifest_sha256", self.manifest_sha256),
            ("execution_projection_sha256", self.execution_projection_sha256),
            ("candidate_envelope_sha256", self.candidate_envelope_sha256),
            ("candidate_binding_sha256", self.candidate_binding_sha256),
            ("engagement_receipt_sha256", self.engagement_receipt_sha256),
            ("closure_sha256", self.closure_sha256),
        ):
            _required_sha256(value, "closure {}".format(field))
        if self.prior_closure_sha256 is not None:
            _required_sha256(self.prior_closure_sha256, "prior_closure_sha256")
        if not self.source_evidence:
            raise RefineryInputError("provenance closure requires source evidence")
        _validate_unique_by(
            self.source_evidence,
            lambda item: item.source_id,
            "closure source evidence",
        )
        expected_context_order = tuple(
            sorted(
                self.transition_contexts,
                key=lambda item: _TRANSITION_CONTEXT_ORDER.get(item[0], 999),
            )
        )
        if expected_context_order != self.transition_contexts:
            raise RefineryInputError(
                "closure transition contexts must follow contract order"
            )
        _validate_unique_by(
            self.transition_contexts,
            lambda item: item[0],
            "closure transition action",
        )
        for action, context_sha, object_sha in self.transition_contexts:
            if action not in TRANSITION_CONTEXT_ACTIONS:
                raise RefineryInputError("closure transition action is invalid")
            _required_sha256(context_sha, "closure transition context_sha256")
            _required_sha256(object_sha, "closure transition object_sha256")
        if tuple(sorted(self.provenance_evidence_assets)) != (
            self.provenance_evidence_assets
        ):
            raise RefineryInputError("closure provenance assets must be sorted")
        _validate_unique_by(
            self.provenance_evidence_assets,
            lambda item: item[0],
            "closure provenance asset_id",
        )
        for asset_id, digest in self.provenance_evidence_assets:
            _validate_opaque_id(asset_id, "closure provenance asset_id")
            _required_sha256(digest, "closure provenance asset sha256")
        _validate_unique_by(
            self.scenarios,
            lambda item: item.scenario_id,
            "closure scenario_id",
        )
        if not self.runtime_source.complete:
            raise RefineryInputError("closure runtime source is incomplete")
        _require_schema(self.schema_version)
        if not self.verify_integrity():
            raise RefineryInputError("provenance closure hash mismatch")

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "phase": self.phase,
            "workspace_id": self.workspace_id,
            "delta_sha256": self.delta_sha256,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "package_sha256": self.package_sha256,
            "manifest_sha256": self.manifest_sha256,
            "execution_projection_sha256": self.execution_projection_sha256,
            "source_evidence": [item.as_dict() for item in self.source_evidence],
            "candidate_envelope_sha256": self.candidate_envelope_sha256,
            "candidate_binding_sha256": self.candidate_binding_sha256,
            "engagement_receipt_sha256": self.engagement_receipt_sha256,
            "transition_contexts": [
                {
                    "action": action,
                    "context_sha256": context_sha,
                    "context_object_sha256": object_sha,
                }
                for action, context_sha, object_sha in self.transition_contexts
            ],
            "runtime_source": self.runtime_source.as_dict(),
            "provenance_evidence_assets": dict(self.provenance_evidence_assets),
            "scenarios": [item.as_dict() for item in self.scenarios],
            "prior_closure_sha256": self.prior_closure_sha256,
        }

    def verify_integrity(self) -> bool:
        return self.closure_sha256 == sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "closure_sha256": self.closure_sha256}

    @classmethod
    def create(cls, **values: Any) -> "ProvenanceClosureDTO":
        content = {
            "schema_version": values.get("schema_version", REFINERY_SCHEMA_VERSION),
            "phase": values["phase"],
            "workspace_id": values["workspace_id"],
            "delta_sha256": values["delta_sha256"],
            "package_id": values["package_id"],
            "package_version": values["package_version"],
            "package_sha256": values["package_sha256"],
            "manifest_sha256": values["manifest_sha256"],
            "execution_projection_sha256": values["execution_projection_sha256"],
            "source_evidence": [item.as_dict() for item in values["source_evidence"]],
            "candidate_envelope_sha256": values["candidate_envelope_sha256"],
            "candidate_binding_sha256": values["candidate_binding_sha256"],
            "engagement_receipt_sha256": values["engagement_receipt_sha256"],
            "transition_contexts": [
                {
                    "action": action,
                    "context_sha256": context_sha,
                    "context_object_sha256": object_sha,
                }
                for action, context_sha, object_sha in values["transition_contexts"]
            ],
            "runtime_source": values["runtime_source"].as_dict(),
            "provenance_evidence_assets": dict(values["provenance_evidence_assets"]),
            "scenarios": [item.as_dict() for item in values["scenarios"]],
            "prior_closure_sha256": values.get("prior_closure_sha256"),
        }
        return cls(
            **values,
            closure_sha256=sha256_text(canonical_json(content)),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProvenanceClosureDTO":
        fields = {
            "schema_version",
            "phase",
            "workspace_id",
            "delta_sha256",
            "package_id",
            "package_version",
            "package_sha256",
            "manifest_sha256",
            "execution_projection_sha256",
            "source_evidence",
            "candidate_envelope_sha256",
            "candidate_binding_sha256",
            "engagement_receipt_sha256",
            "transition_contexts",
            "runtime_source",
            "provenance_evidence_assets",
            "scenarios",
            "prior_closure_sha256",
            "closure_sha256",
        }
        _reject_unknown(value, fields, "provenance closure")
        if set(value) != fields:
            raise RefineryInputError("provenance closure schema is incomplete")
        raw_contexts = _mapping_list(
            value.get("transition_contexts"), "transition_contexts"
        )
        contexts = []
        for item in raw_contexts:
            _reject_unknown(
                item,
                {"action", "context_sha256", "context_object_sha256"},
                "closure transition context",
            )
            contexts.append(
                (
                    _strict_text(item.get("action"), "closure action"),
                    _strict_text(item.get("context_sha256"), "closure context_sha256"),
                    _strict_text(
                        item.get("context_object_sha256"),
                        "closure context_object_sha256",
                    ),
                )
            )
        raw_assets = _mapping(
            value.get("provenance_evidence_assets"),
            "provenance_evidence_assets",
        )
        return cls(
            phase=_strict_text(value.get("phase"), "closure phase"),
            workspace_id=_strict_text(value.get("workspace_id"), "workspace_id"),
            delta_sha256=_strict_text(value.get("delta_sha256"), "delta_sha256"),
            package_id=_strict_text(value.get("package_id"), "package_id"),
            package_version=_strict_text(
                value.get("package_version"), "package_version"
            ),
            package_sha256=_strict_text(value.get("package_sha256"), "package_sha256"),
            manifest_sha256=_strict_text(
                value.get("manifest_sha256"), "manifest_sha256"
            ),
            execution_projection_sha256=_strict_text(
                value.get("execution_projection_sha256"),
                "execution_projection_sha256",
            ),
            source_evidence=tuple(
                SourceEvidenceDTO.from_dict(item)
                for item in _mapping_list(
                    value.get("source_evidence"), "source_evidence"
                )
            ),
            candidate_envelope_sha256=_strict_text(
                value.get("candidate_envelope_sha256"),
                "candidate_envelope_sha256",
            ),
            candidate_binding_sha256=_strict_text(
                value.get("candidate_binding_sha256"),
                "candidate_binding_sha256",
            ),
            engagement_receipt_sha256=_strict_text(
                value.get("engagement_receipt_sha256"),
                "engagement_receipt_sha256",
            ),
            transition_contexts=tuple(
                sorted(
                    contexts,
                    key=lambda item: _TRANSITION_CONTEXT_ORDER.get(item[0], 999),
                )
            ),
            runtime_source=RuntimeSourceIdentityDTO.from_dict(
                _mapping(value.get("runtime_source"), "runtime_source")
            ),
            provenance_evidence_assets=tuple(
                sorted(
                    (
                        _strict_text(key, "provenance asset_id"),
                        _strict_text(digest, "provenance asset sha256"),
                    )
                    for key, digest in raw_assets.items()
                )
            ),
            scenarios=tuple(
                ProvenanceScenarioBindingDTO.from_dict(item)
                for item in _mapping_list(value.get("scenarios"), "scenarios")
            ),
            prior_closure_sha256=(
                _strict_text(value["prior_closure_sha256"], "prior_closure_sha256")
                if value.get("prior_closure_sha256") is not None
                else None
            ),
            closure_sha256=_strict_text(value.get("closure_sha256"), "closure_sha256"),
            schema_version=_strict_text(value.get("schema_version"), "schema_version"),
        )


@dataclass(frozen=True)
class SubjectExecutionSuiteDTO:
    """Semantica-generated execution proof for one committed subject package."""

    workspace_id: str
    delta_sha256: str
    subject_package_id: str
    subject_package_version: str
    subject_package_sha256: str
    subject_manifest_sha256: str
    execution_projection_sha256: str
    execution_asset_hashes: Tuple[Tuple[str, str], ...]
    transition_context_sha256: str
    transition_context_object_sha256: str
    provenance_closure_sha256: str
    provenance_closure_object_sha256: str
    required_prior_cq_bindings: Tuple[Tuple[str, str], ...]
    required_prior_case_bindings: Tuple[Tuple[str, str], ...]
    cq_registry_bindings: Tuple[Tuple[str, str], ...]
    required_scenario_ids: Tuple[str, ...]
    required_cq_ids: Tuple[str, ...]
    required_case_kinds: Tuple[str, ...]
    runs: Tuple[SubjectScenarioRunDTO, ...]
    runtime_source: RuntimeSourceIdentityDTO
    observed_capabilities: Tuple[str, ...]
    status: str
    created_at: str
    suite_sha256: str
    schema_version: str = REFINERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_opaque_id(self.workspace_id, "suite workspace_id")
        _required_sha256(self.delta_sha256, "suite delta_sha256")
        _validate_package_id(self.subject_package_id)
        _required_text(self.subject_package_version, "suite subject version")
        for field, value in (
            ("subject_package_sha256", self.subject_package_sha256),
            ("subject_manifest_sha256", self.subject_manifest_sha256),
            ("execution_projection_sha256", self.execution_projection_sha256),
            ("transition_context_sha256", self.transition_context_sha256),
            (
                "transition_context_object_sha256",
                self.transition_context_object_sha256,
            ),
            ("provenance_closure_sha256", self.provenance_closure_sha256),
            (
                "provenance_closure_object_sha256",
                self.provenance_closure_object_sha256,
            ),
            ("suite_sha256", self.suite_sha256),
        ):
            _required_sha256(value, field)
        if tuple(sorted(self.execution_asset_hashes)) != self.execution_asset_hashes:
            raise RefineryInputError("execution_asset_hashes must be sorted")
        if len({key for key, _ in self.execution_asset_hashes}) != len(
            self.execution_asset_hashes
        ):
            raise RefineryInputError("execution_asset_hashes contains duplicates")
        for asset_id, digest in self.execution_asset_hashes:
            _validate_opaque_id(asset_id, "execution asset_id")
            _required_sha256(digest, "execution asset sha256")
        for field, pairs in (
            ("required_prior_cq_bindings", self.required_prior_cq_bindings),
            ("required_prior_case_bindings", self.required_prior_case_bindings),
            ("cq_registry_bindings", self.cq_registry_bindings),
        ):
            if tuple(sorted(pairs)) != pairs or len({key for key, _ in pairs}) != len(
                pairs
            ):
                raise RefineryInputError("{} must be sorted and unique".format(field))
            for key, digest in pairs:
                _required_text(key, "{} identity".format(field))
                _required_sha256(digest, "{} sha256".format(field))
        for field, items in (
            ("required_scenario_ids", self.required_scenario_ids),
            ("required_cq_ids", self.required_cq_ids),
            ("required_case_kinds", self.required_case_kinds),
            ("observed_capabilities", self.observed_capabilities),
        ):
            _validate_unique_text_tuple(items, field)
        if set(self.required_case_kinds) != set(CASE_KINDS):
            raise RefineryInputError("suite must bind all four case kinds")
        _validate_unique_by(self.runs, lambda item: item.scenario_id, "suite run")
        expected_status = (
            "complete"
            if set(self.required_scenario_ids)
            == {item.scenario_id for item in self.runs}
            and all(
                item.status == "passed" and item.release_status == "complete"
                for item in self.runs
            )
            else "blocked"
        )
        if self.status != expected_status:
            raise RefineryInputError("suite status does not match executed runs")
        _validate_timestamp(self.created_at, "suite created_at")
        _require_schema(self.schema_version)
        if not self.verify_integrity():
            raise RefineryInputError("execution suite hash mismatch")

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "workspace_id": self.workspace_id,
            "delta_sha256": self.delta_sha256,
            "subject_package_id": self.subject_package_id,
            "subject_package_version": self.subject_package_version,
            "subject_package_sha256": self.subject_package_sha256,
            "subject_manifest_sha256": self.subject_manifest_sha256,
            "execution_projection_sha256": self.execution_projection_sha256,
            "execution_asset_hashes": dict(self.execution_asset_hashes),
            "transition_context_sha256": self.transition_context_sha256,
            "transition_context_object_sha256": (self.transition_context_object_sha256),
            "provenance_closure_sha256": self.provenance_closure_sha256,
            "provenance_closure_object_sha256": (self.provenance_closure_object_sha256),
            "required_prior_cq_bindings": dict(self.required_prior_cq_bindings),
            "required_prior_case_bindings": dict(self.required_prior_case_bindings),
            "cq_registry_bindings": dict(self.cq_registry_bindings),
            "required_scenario_ids": list(self.required_scenario_ids),
            "required_cq_ids": list(self.required_cq_ids),
            "required_case_kinds": list(self.required_case_kinds),
            "runs": [item.as_dict() for item in self.runs],
            "runtime_source": self.runtime_source.as_dict(),
            "observed_capabilities": list(self.observed_capabilities),
            "status": self.status,
            "created_at": self.created_at,
        }

    def verify_integrity(self) -> bool:
        return self.suite_sha256 == sha256_text(canonical_json(self._content_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {**self._content_dict(), "suite_sha256": self.suite_sha256}

    @classmethod
    def create(cls, **values: Any) -> "SubjectExecutionSuiteDTO":
        content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "workspace_id": values["workspace_id"],
            "delta_sha256": values["delta_sha256"],
            "subject_package_id": values["subject_package_id"],
            "subject_package_version": values["subject_package_version"],
            "subject_package_sha256": values["subject_package_sha256"],
            "subject_manifest_sha256": values["subject_manifest_sha256"],
            "execution_projection_sha256": values["execution_projection_sha256"],
            "execution_asset_hashes": dict(values["execution_asset_hashes"]),
            "transition_context_sha256": values["transition_context_sha256"],
            "transition_context_object_sha256": values[
                "transition_context_object_sha256"
            ],
            "provenance_closure_sha256": values["provenance_closure_sha256"],
            "provenance_closure_object_sha256": values[
                "provenance_closure_object_sha256"
            ],
            "required_prior_cq_bindings": dict(values["required_prior_cq_bindings"]),
            "required_prior_case_bindings": dict(
                values["required_prior_case_bindings"]
            ),
            "cq_registry_bindings": dict(values["cq_registry_bindings"]),
            "required_scenario_ids": list(values["required_scenario_ids"]),
            "required_cq_ids": list(values["required_cq_ids"]),
            "required_case_kinds": list(values["required_case_kinds"]),
            "runs": [item.as_dict() for item in values["runs"]],
            "runtime_source": values["runtime_source"].as_dict(),
            "observed_capabilities": list(values["observed_capabilities"]),
            "status": values["status"],
            "created_at": values["created_at"],
        }
        return cls(
            **values,
            suite_sha256=sha256_text(canonical_json(content)),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SubjectExecutionSuiteDTO":
        allowed = {
            "schema_version",
            "workspace_id",
            "delta_sha256",
            "subject_package_id",
            "subject_package_version",
            "subject_package_sha256",
            "subject_manifest_sha256",
            "execution_projection_sha256",
            "execution_asset_hashes",
            "transition_context_sha256",
            "transition_context_object_sha256",
            "provenance_closure_sha256",
            "provenance_closure_object_sha256",
            "required_prior_cq_bindings",
            "required_prior_case_bindings",
            "cq_registry_bindings",
            "required_scenario_ids",
            "required_cq_ids",
            "required_case_kinds",
            "runs",
            "runtime_source",
            "observed_capabilities",
            "status",
            "created_at",
            "suite_sha256",
        }
        _reject_unknown(value, allowed, "subject execution suite")
        asset_hashes = _mapping(
            value.get("execution_asset_hashes"), "execution_asset_hashes"
        )
        pairs = []
        for asset_id, digest in asset_hashes.items():
            pairs.append(
                (
                    _strict_text(asset_id, "execution asset_id"),
                    _strict_text(digest, "execution asset sha256"),
                )
            )
        prior_cqs = _mapping(
            value.get("required_prior_cq_bindings"),
            "required_prior_cq_bindings",
        )
        prior_cases = _mapping(
            value.get("required_prior_case_bindings"),
            "required_prior_case_bindings",
        )
        cq_registry = _mapping(
            value.get("cq_registry_bindings"), "cq_registry_bindings"
        )
        return cls(
            workspace_id=_strict_text(value.get("workspace_id"), "workspace_id"),
            delta_sha256=_strict_text(value.get("delta_sha256"), "delta_sha256"),
            subject_package_id=_strict_text(
                value.get("subject_package_id"), "subject_package_id"
            ),
            subject_package_version=_strict_text(
                value.get("subject_package_version"), "subject_package_version"
            ),
            subject_package_sha256=_strict_text(
                value.get("subject_package_sha256"), "subject_package_sha256"
            ),
            subject_manifest_sha256=_strict_text(
                value.get("subject_manifest_sha256"), "subject_manifest_sha256"
            ),
            execution_projection_sha256=_strict_text(
                value.get("execution_projection_sha256"),
                "execution_projection_sha256",
            ),
            execution_asset_hashes=tuple(sorted(pairs)),
            transition_context_sha256=_strict_text(
                value.get("transition_context_sha256"),
                "transition_context_sha256",
            ),
            transition_context_object_sha256=_strict_text(
                value.get("transition_context_object_sha256"),
                "transition_context_object_sha256",
            ),
            provenance_closure_sha256=_strict_text(
                value.get("provenance_closure_sha256"),
                "provenance_closure_sha256",
            ),
            provenance_closure_object_sha256=_strict_text(
                value.get("provenance_closure_object_sha256"),
                "provenance_closure_object_sha256",
            ),
            required_prior_cq_bindings=tuple(
                sorted(
                    (
                        _strict_text(key, "prior CQ id"),
                        _strict_text(digest, "prior CQ sha256"),
                    )
                    for key, digest in prior_cqs.items()
                )
            ),
            required_prior_case_bindings=tuple(
                sorted(
                    (
                        _strict_text(key, "prior case asset_id"),
                        _strict_text(digest, "prior case sha256"),
                    )
                    for key, digest in prior_cases.items()
                )
            ),
            cq_registry_bindings=tuple(
                sorted(
                    (
                        _strict_text(key, "CQ registry id"),
                        _strict_text(digest, "CQ registry entry sha256"),
                    )
                    for key, digest in cq_registry.items()
                )
            ),
            required_scenario_ids=_text_tuple(
                value.get("required_scenario_ids"), "required_scenario_ids"
            ),
            required_cq_ids=_text_tuple(
                value.get("required_cq_ids"), "required_cq_ids"
            ),
            required_case_kinds=_text_tuple(
                value.get("required_case_kinds"), "required_case_kinds"
            ),
            runs=tuple(
                SubjectScenarioRunDTO.from_dict(item)
                for item in _mapping_list(value.get("runs"), "runs")
            ),
            runtime_source=RuntimeSourceIdentityDTO.from_dict(
                _mapping(value.get("runtime_source"), "runtime_source")
            ),
            observed_capabilities=_text_tuple(
                value.get("observed_capabilities"), "observed_capabilities"
            ),
            status=_strict_text(value.get("status"), "suite status"),
            created_at=_strict_text(value.get("created_at"), "suite created_at"),
            suite_sha256=_strict_text(value.get("suite_sha256"), "suite_sha256"),
            schema_version=_strict_text(
                value.get("schema_version", REFINERY_SCHEMA_VERSION),
                "schema_version",
            ),
        )


@dataclass(frozen=True)
class RefineryStateDTO:
    """Verified latest state for one immutable package delta."""

    delta_sha256: str
    package_id: str
    state: str
    sequence: int
    event_sha256: str
    previous_event_sha256: Optional[str]
    package_sha256: Optional[str]
    recorded_at: str

    def __post_init__(self) -> None:
        _required_sha256(self.delta_sha256, "state delta_sha256")
        _validate_package_id(self.package_id)
        if self.state not in REFINERY_STATES:
            raise RefineryInputError("unknown refinery state")
        if self.sequence < 1:
            raise RefineryInputError("state sequence must be positive")
        _required_sha256(self.event_sha256, "state event_sha256")
        if self.previous_event_sha256 is not None:
            _required_sha256(self.previous_event_sha256, "state previous_event_sha256")
        if self.package_sha256 is not None:
            _required_sha256(self.package_sha256, "state package_sha256")
        if (
            self.state
            in {
                "committed",
                "regression_passed",
                "release_complete",
                "promoted",
            }
            and self.package_sha256 is None
        ):
            raise RefineryInputError("post-commit state requires package_sha256")
        _validate_timestamp(self.recorded_at, "state recorded_at")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "delta_sha256": self.delta_sha256,
            "package_id": self.package_id,
            "state": self.state,
            "sequence": self.sequence,
            "event_sha256": self.event_sha256,
            "previous_event_sha256": self.previous_event_sha256,
            "package_sha256": self.package_sha256,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RefineryStateDTO":
        fields = {
            "delta_sha256",
            "package_id",
            "state",
            "sequence",
            "event_sha256",
            "previous_event_sha256",
            "package_sha256",
            "recorded_at",
        }
        _reject_unknown(value, fields, "refinery state")
        if set(value) != fields:
            raise RefineryInputError("refinery state schema is incomplete")
        return cls(
            delta_sha256=_strict_text(value.get("delta_sha256"), "delta_sha256"),
            package_id=_strict_text(value.get("package_id"), "package_id"),
            state=_strict_text(value.get("state"), "state"),
            sequence=value.get("sequence"),
            event_sha256=_strict_text(value.get("event_sha256"), "event_sha256"),
            previous_event_sha256=(
                _strict_text(value["previous_event_sha256"], "previous_event_sha256")
                if value.get("previous_event_sha256") is not None
                else None
            ),
            package_sha256=(
                _strict_text(value["package_sha256"], "package_sha256")
                if value.get("package_sha256") is not None
                else None
            ),
            recorded_at=_strict_text(value.get("recorded_at"), "recorded_at"),
        )


@dataclass(frozen=True)
class CandidateVerificationDTO:
    """Ordered regression/release result produced by one verification facade."""

    state: RefineryStateDTO
    execution_suite_sha256: str
    regression_evidence: RefineryGateEvidenceDTO
    release_evidence: RefineryGateEvidenceDTO
    verification_sha256: str
    schema_version: str = REFINERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.state.state != "release_complete":
            raise RefineryInputError(
                "candidate verification state must be release_complete"
            )
        _required_sha256(
            self.execution_suite_sha256,
            "candidate verification execution_suite_sha256",
        )
        if (
            self.regression_evidence.gate != "regression"
            or self.release_evidence.gate != "release"
        ):
            raise RefineryInputError(
                "candidate verification requires regression then release evidence"
            )
        if (
            self.regression_evidence.execution_suite_sha256
            != self.execution_suite_sha256
            or self.release_evidence.execution_suite_sha256
            != self.execution_suite_sha256
        ):
            raise RefineryInputError("candidate verification evidence suites differ")
        if (
            self.regression_evidence.package_sha256 != self.state.package_sha256
            or self.release_evidence.package_sha256 != self.state.package_sha256
        ):
            raise RefineryInputError(
                "candidate verification evidence package differs from state"
            )
        _required_sha256(self.verification_sha256, "verification_sha256")
        _require_schema(self.schema_version)
        if not self.verify_integrity():
            raise RefineryInputError("candidate verification hash mismatch")

    def _content_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "state": self.state.as_dict(),
            "execution_suite_sha256": self.execution_suite_sha256,
            "regression_evidence": self.regression_evidence.as_dict(),
            "release_evidence": self.release_evidence.as_dict(),
        }

    def verify_integrity(self) -> bool:
        return self.verification_sha256 == sha256_text(
            canonical_json(self._content_dict())
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            **self._content_dict(),
            "verification_sha256": self.verification_sha256,
        }

    @classmethod
    def create(
        cls,
        *,
        state: RefineryStateDTO,
        execution_suite_sha256: str,
        regression_evidence: RefineryGateEvidenceDTO,
        release_evidence: RefineryGateEvidenceDTO,
    ) -> "CandidateVerificationDTO":
        content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "state": state.as_dict(),
            "execution_suite_sha256": execution_suite_sha256,
            "regression_evidence": regression_evidence.as_dict(),
            "release_evidence": release_evidence.as_dict(),
        }
        return cls(
            state=state,
            execution_suite_sha256=execution_suite_sha256,
            regression_evidence=regression_evidence,
            release_evidence=release_evidence,
            verification_sha256=sha256_text(canonical_json(content)),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CandidateVerificationDTO":
        fields = {
            "schema_version",
            "state",
            "execution_suite_sha256",
            "regression_evidence",
            "release_evidence",
            "verification_sha256",
        }
        _reject_unknown(value, fields, "candidate verification")
        if set(value) != fields:
            raise RefineryInputError("candidate verification schema is incomplete")
        return cls(
            state=RefineryStateDTO.from_dict(
                _mapping(value.get("state"), "candidate verification state")
            ),
            execution_suite_sha256=_strict_text(
                value.get("execution_suite_sha256"),
                "candidate verification execution_suite_sha256",
            ),
            regression_evidence=RefineryGateEvidenceDTO.from_dict(
                _mapping(value.get("regression_evidence"), "regression evidence")
            ),
            release_evidence=RefineryGateEvidenceDTO.from_dict(
                _mapping(value.get("release_evidence"), "release evidence")
            ),
            verification_sha256=_strict_text(
                value.get("verification_sha256"), "verification_sha256"
            ),
            schema_version=_strict_text(value.get("schema_version"), "schema_version"),
        )


@dataclass(frozen=True)
class IndustryPackageDescriptorDTO:
    """Public package descriptor with no filesystem path."""

    package_id: str
    version: str
    package_sha256: str
    manifest_sha256: str
    promotion_record_sha256: str
    delta_sha256: str
    engagement_receipt_sha256: str
    regression_evidence_sha256: str
    release_evidence_sha256: str
    subject_execution_suite_sha256: str
    transition_context_sha256: str
    transition_context_object_sha256: str
    provenance_closure_sha256: str
    provenance_closure_object_sha256: str
    authorization_sha256: str
    authorization_object_sha256: str
    book_impact: str
    promoted_at: str

    def __post_init__(self) -> None:
        _validate_package_id(self.package_id)
        _required_text(self.version, "package version")
        for field, value in (
            ("package_sha256", self.package_sha256),
            ("manifest_sha256", self.manifest_sha256),
            ("promotion_record_sha256", self.promotion_record_sha256),
            ("delta_sha256", self.delta_sha256),
            ("engagement_receipt_sha256", self.engagement_receipt_sha256),
            ("regression_evidence_sha256", self.regression_evidence_sha256),
            ("release_evidence_sha256", self.release_evidence_sha256),
            (
                "subject_execution_suite_sha256",
                self.subject_execution_suite_sha256,
            ),
            ("transition_context_sha256", self.transition_context_sha256),
            (
                "transition_context_object_sha256",
                self.transition_context_object_sha256,
            ),
            ("provenance_closure_sha256", self.provenance_closure_sha256),
            (
                "provenance_closure_object_sha256",
                self.provenance_closure_object_sha256,
            ),
            ("authorization_sha256", self.authorization_sha256),
            ("authorization_object_sha256", self.authorization_object_sha256),
        ):
            _required_sha256(value, field)
        if self.book_impact not in BOOK_IMPACTS:
            raise RefineryInputError("promoted package has invalid book_impact")
        _validate_timestamp(self.promoted_at, "promoted_at")

    def as_dict(self) -> Dict[str, str]:
        return {
            "package_id": self.package_id,
            "version": self.version,
            "package_sha256": self.package_sha256,
            "manifest_sha256": self.manifest_sha256,
            "promotion_record_sha256": self.promotion_record_sha256,
            "delta_sha256": self.delta_sha256,
            "engagement_receipt_sha256": self.engagement_receipt_sha256,
            "regression_evidence_sha256": self.regression_evidence_sha256,
            "release_evidence_sha256": self.release_evidence_sha256,
            "subject_execution_suite_sha256": (self.subject_execution_suite_sha256),
            "transition_context_sha256": self.transition_context_sha256,
            "transition_context_object_sha256": (self.transition_context_object_sha256),
            "provenance_closure_sha256": self.provenance_closure_sha256,
            "provenance_closure_object_sha256": (self.provenance_closure_object_sha256),
            "authorization_sha256": self.authorization_sha256,
            "authorization_object_sha256": self.authorization_object_sha256,
            "book_impact": self.book_impact,
            "promoted_at": self.promoted_at,
        }


# ---------------------------------------------------------------------------
# Managed registry/workspace


class IndustryOntologyRegistry:
    """Semantica-managed append-only registry of promoted industry packages."""

    def __init__(self, workspace: Union[str, os.PathLike]) -> None:
        # Keep the caller's lexical root.  Resolving here would erase the fact
        # that the supplied workspace itself is a symlink and would turn later
        # containment checks into checks against the attacker's target.
        self.root = _lexical_absolute_path(workspace)
        _require_regular_directory(self.root, "refinery workspace")
        self._root_anchor = self.root.resolve(strict=True)
        self._workspace = self._read_workspace()

    @classmethod
    def create(
        cls,
        workspace: Union[str, os.PathLike],
        *,
        registry_id: str,
        created_at: Optional[str] = None,
    ) -> "IndustryOntologyRegistry":
        root = _lexical_absolute_path(workspace)
        _validate_opaque_id(registry_id, "registry_id")
        when = created_at or utc_now()
        _validate_timestamp(when, "registry created_at")
        root.parent.mkdir(parents=True, exist_ok=True)
        lock = root.parent / ".{}.semantica-refinery-init.lock".format(root.name)
        with _exclusive_lock(lock):
            if root.exists() or root.is_symlink():
                raise RefineryWorkspaceExistsError(
                    "refusing to overwrite refinery workspace: {}".format(root)
                )
            stage = Path(
                tempfile.mkdtemp(
                    prefix=".{}.semantica-refinery-".format(root.name),
                    dir=str(root.parent),
                )
            )
            try:
                for relative in (
                    "objects/sha256",
                    "engagements",
                    "execution-suites",
                    "refinements",
                    "packages",
                    "registry-events",
                ):
                    (stage / relative).mkdir(parents=True, exist_ok=True)
                workspace_doc = {
                    "schema_version": REFINERY_SCHEMA_VERSION,
                    "contract": REFINERY_CONTRACT,
                    "registry_id": registry_id,
                    "created_at": when,
                    "empty_package_sha256": EMPTY_PACKAGE_SHA256,
                }
                registry = {
                    "schema_version": REFINERY_SCHEMA_VERSION,
                    "registry_id": registry_id,
                    "sequence": 0,
                    "last_event_sha256": None,
                    "packages_sha256": sha256_text(canonical_json({})),
                    "packages": {},
                }
                _write_new(stage / "workspace.json", _json_bytes(workspace_doc))
                _write_new(stage / "registry.json", _json_bytes(registry))
                _fsync_directory(stage)
                os.rename(str(stage), str(root))
                _fsync_directory(root.parent)
            except Exception:
                if stage.exists():
                    shutil.rmtree(str(stage))
                raise
        return cls(root)

    @property
    def registry_id(self) -> str:
        return str(self._workspace["registry_id"])

    def _assert_managed_path(
        self,
        path: Path,
        *,
        require_exists: bool = False,
        require_directory: bool = False,
    ) -> Path:
        """Reject every symlink component below the lexical workspace root."""

        candidate = _lexical_absolute_path(path)
        try:
            relative = candidate.relative_to(self.root)
        except ValueError as exc:
            raise RefineryWorkspaceError(
                "managed path escapes refinery workspace: {}".format(candidate)
            ) from exc
        _require_regular_directory(self.root, "refinery workspace")
        current = self.root
        for part in relative.parts:
            current = current / part
            try:
                metadata = os.lstat(str(current))
            except FileNotFoundError:
                break
            if stat.S_ISLNK(metadata.st_mode):
                raise RefineryWorkspaceError(
                    "managed path contains a symlink: {}".format(current)
                )
        existing = candidate
        while not existing.exists() and existing != self.root:
            existing = existing.parent
        if existing.exists():
            try:
                existing.resolve(strict=True).relative_to(self._root_anchor)
            except (OSError, ValueError) as exc:
                raise RefineryWorkspaceError(
                    "managed path resolves outside refinery workspace: {}".format(
                        candidate
                    )
                ) from exc
        if require_exists:
            try:
                metadata = os.lstat(str(candidate))
            except FileNotFoundError as exc:
                raise RefineryWorkspaceError(
                    "required managed path is missing: {}".format(candidate)
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise RefineryWorkspaceError(
                    "managed path is a symlink: {}".format(candidate)
                )
            if require_directory and not stat.S_ISDIR(metadata.st_mode):
                raise RefineryWorkspaceError(
                    "managed path is not a directory: {}".format(candidate)
                )
        return candidate

    def _assert_workspace_layout(self) -> None:
        for relative in (
            "objects",
            "objects/sha256",
            "engagements",
            "execution-suites",
            "refinements",
            "packages",
            "registry-events",
        ):
            self._assert_managed_path(
                self.root / relative,
                require_exists=True,
                require_directory=True,
            )

    def record_engagement(
        self,
        envelope: SemanticTaskEnvelope,
        binding: ProjectOntologyBinding,
        receipt: SemanticEngagementReceipt,
    ) -> str:
        """Persist a complete or blocked engagement without changing truth."""

        self._assert_workspace_layout()
        self._validate_engagement_binding(envelope, binding, receipt)
        record = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "envelope": envelope.as_dict(),
            "binding": binding.as_dict(),
            "engagement_receipt": receipt.as_dict(),
        }
        payload = _json_bytes(record)
        digest = _sha256_bytes(payload)
        path = self._assert_managed_path(
            self.root / "engagements" / "{}.json".format(digest)
        )
        if path.exists():
            if _read_bytes(path) != payload:
                raise RefineryWorkspaceError("engagement digest collision")
        else:
            _write_new(path, payload)
        return digest

    def register_candidate(
        self,
        delta: PackageDelta,
        envelope: SemanticTaskEnvelope,
        binding: ProjectOntologyBinding,
        engagement: SemanticEngagementReceipt,
        *,
        recorded_at: Optional[str] = None,
    ) -> RefineryStateDTO:
        """Retain an immutable candidate; no ontology truth is changed."""

        self._assert_workspace_layout()
        when = recorded_at or utc_now()
        _validate_timestamp(when, "candidate recorded_at")
        self._validate_engagement_binding(envelope, binding, engagement)
        violations = self._candidate_violations(delta, envelope, binding, engagement)
        violations.extend(self._baseline_violations(delta, binding))
        if violations:
            raise RefineryGateError(violations)
        candidate_context = TransitionContextDTO.create(
            action="candidate",
            delta_sha256=delta.delta_sha256,
            envelope=envelope,
            binding=binding,
        )
        self._validate_transition_context(
            candidate_context,
            delta,
            binding,
            expected_action="candidate",
        )
        self.record_engagement(envelope, binding, engagement)
        candidate_context_object_sha256 = self._retain_transition_context(
            candidate_context
        )
        delta_root = self._delta_root(delta.delta_sha256)
        with _exclusive_lock(self.root / ".refinery.lock"):
            if delta_root.exists() or delta_root.is_symlink():
                raise RefineryWorkspaceError(
                    "candidate already exists; immutable deltas cannot be overwritten"
                )
            stage = self.root / "refinements" / ".staging-{}".format(uuid.uuid4().hex)
            self._assert_managed_path(stage)
            stage.mkdir()
            try:
                (stage / "events").mkdir()
                for item in delta.assets:
                    if item.content_bytes is not None:
                        self._put_object(item.content_bytes, expected=item.sha256)
                records = {
                    "delta.json": delta.as_dict(),
                    "envelope.json": envelope.as_dict(),
                    "binding.json": binding.as_dict(),
                    "engagement.json": engagement.as_dict(),
                }
                for name, value in records.items():
                    _write_new(stage / name, _json_bytes(value))
                state = self._write_initial_event(
                    stage,
                    delta=delta,
                    when=when,
                    payload={
                        "envelope_sha256": envelope.envelope_sha256,
                        "binding_sha256": binding.binding_sha256,
                        "engagement_receipt_sha256": engagement.receipt_sha256,
                        "engagement_status": engagement.status,
                        "transition_context_sha256": (candidate_context.context_sha256),
                        "transition_context_object_sha256": (
                            candidate_context_object_sha256
                        ),
                    },
                )
                _fsync_directory(stage)
                os.rename(str(stage), str(delta_root))
                _fsync_directory(delta_root.parent)
                return state
            except Exception:
                if stage.exists():
                    shutil.rmtree(str(stage))
                raise

    def propose(
        self,
        delta_sha256: str,
        *,
        context: TransitionContextDTO,
        recorded_at: Optional[str] = None,
    ) -> RefineryStateDTO:
        """Advance a complete candidate to a non-authoritative proposal."""

        when = recorded_at or utc_now()
        _validate_timestamp(when, "proposal recorded_at")
        with _exclusive_lock(self.root / ".refinery.lock"):
            state, docs = self._load_refinement(delta_sha256)
            self._require_transition(state, "proposed")
            engagement = SemanticEngagementReceipt.from_dict(docs["engagement"])
            if engagement.status != "complete":
                raise RefineryGateError(
                    ("candidate engagement is blocked; proposal cannot advance",)
                )
            binding = ProjectOntologyBinding.from_dict(docs["binding"])
            self._require_allowed(binding, "proposed")
            delta = PackageDelta.from_dict(docs["delta"])
            self._validate_transition_context(
                context,
                delta,
                binding,
                expected_action="proposed",
            )
            context_object_sha256 = self._retain_transition_context(context)
            return self._append_event(
                state,
                "proposed",
                payload={
                    "proposal": "candidate submitted for governed decision",
                    "transition_context_sha256": context.context_sha256,
                    "transition_context_object_sha256": context_object_sha256,
                },
                recorded_at=when,
            )

    def commit(
        self,
        delta_sha256: str,
        authorization: RefineryAuthorizationDTO,
        *,
        context: TransitionContextDTO,
        recorded_at: Optional[str] = None,
    ) -> RefineryStateDTO:
        """Freeze a proposed package after explicit decision-authority approval."""

        when = recorded_at or utc_now()
        _validate_timestamp(when, "commit recorded_at")
        with _exclusive_lock(self.root / ".refinery.lock"):
            state, docs = self._load_refinement(delta_sha256)
            self._require_transition(state, "committed")
            delta = PackageDelta.from_dict(docs["delta"])
            binding = ProjectOntologyBinding.from_dict(docs["binding"])
            engagement = SemanticEngagementReceipt.from_dict(docs["engagement"])
            violations = self._authorization_violations(
                authorization, delta, binding, action="commit"
            )
            if engagement.status != "complete":
                violations.append("engagement receipt is blocked")
            violations.extend(self._baseline_violations(delta, binding))
            if violations:
                raise RefineryGateError(violations)
            self._validate_transition_context(
                context,
                delta,
                binding,
                expected_action="committed",
            )
            context_object_sha256 = self._retain_transition_context(context)
            manifest, package_sha256 = self._materialize_package(delta)
            manifest_bytes = _json_bytes(manifest)
            manifest_sha256 = self._put_object(manifest_bytes)
            authorization_object_sha256 = self._put_object(
                _json_bytes(authorization.as_dict())
            )
            return self._append_event(
                state,
                "committed",
                package_sha256=package_sha256,
                payload={
                    "manifest_sha256": manifest_sha256,
                    "authorization_sha256": authorization.authorization_sha256,
                    "authorization_object_sha256": authorization_object_sha256,
                    "engagement_receipt_sha256": engagement.receipt_sha256,
                    "transition_context_sha256": context.context_sha256,
                    "transition_context_object_sha256": context_object_sha256,
                },
                recorded_at=when,
            )

    def record_regression(
        self,
        delta_sha256: str,
        evidence: RefineryGateEvidenceDTO,
        *,
        context: TransitionContextDTO,
        recorded_at: Optional[str] = None,
    ) -> RefineryStateDTO:
        """Advance only on complete, capability-bound regression evidence."""

        when = recorded_at or utc_now()
        _validate_timestamp(when, "regression recorded_at")
        with _exclusive_lock(self.root / ".refinery.lock"):
            state, docs = self._load_refinement(delta_sha256)
            self._require_transition(state, "regression_passed")
            delta = PackageDelta.from_dict(docs["delta"])
            binding = ProjectOntologyBinding.from_dict(docs["binding"])
            engagement = SemanticEngagementReceipt.from_dict(docs["engagement"])
            self._require_allowed(binding, "regression_passed")
            self._validate_transition_context(
                context,
                delta,
                binding,
                expected_action="regression_passed",
            )
            # Regression is meaningful only for a fully deliverable package,
            # not merely for a manifest whose category labels look complete.
            self._committed_manifest(state)
            violations = self._gate_evidence_violations(
                evidence,
                state,
                docs,
                delta,
                engagement,
                expected_gate="regression",
            )
            if violations:
                raise RefineryGateError(violations)
            context_object_sha256 = self._retain_transition_context(context)
            evidence_object_sha256 = self._put_object(_json_bytes(evidence.as_dict()))
            return self._append_event(
                state,
                "regression_passed",
                package_sha256=state.package_sha256,
                payload={
                    "regression_evidence_sha256": evidence.evidence_sha256,
                    "regression_evidence_object_sha256": evidence_object_sha256,
                    "execution_suite_sha256": evidence.execution_suite_sha256,
                    "execution_suite_object_sha256": (
                        evidence.execution_suite_object_sha256
                    ),
                    "transition_context_sha256": context.context_sha256,
                    "transition_context_object_sha256": context_object_sha256,
                    "provenance_closure_sha256": (evidence.provenance_closure_sha256),
                    "provenance_closure_object_sha256": (
                        evidence.provenance_closure_object_sha256
                    ),
                },
                recorded_at=when,
            )

    def record_release(
        self,
        delta_sha256: str,
        evidence: RefineryGateEvidenceDTO,
        *,
        context: TransitionContextDTO,
        recorded_at: Optional[str] = None,
    ) -> RefineryStateDTO:
        """Advance only when complete package coverage and release evidence pass."""

        when = recorded_at or utc_now()
        _validate_timestamp(when, "release recorded_at")
        with _exclusive_lock(self.root / ".refinery.lock"):
            state, docs = self._load_refinement(delta_sha256)
            self._require_transition(state, "release_complete")
            delta = PackageDelta.from_dict(docs["delta"])
            binding = ProjectOntologyBinding.from_dict(docs["binding"])
            engagement = SemanticEngagementReceipt.from_dict(docs["engagement"])
            self._require_allowed(binding, "release_complete")
            self._validate_transition_context(
                context,
                delta,
                binding,
                expected_action="release_complete",
            )
            violations = self._gate_evidence_violations(
                evidence,
                state,
                docs,
                delta,
                engagement,
                expected_gate="release",
            )
            regression_event = self._verified_history(state)[-1]
            if regression_event.get("state") != "regression_passed":
                violations.append("release is not based on regression_passed state")
            elif (
                regression_event.get("payload", {}).get("execution_suite_sha256")
                != evidence.execution_suite_sha256
            ):
                violations.append(
                    "release evidence suite differs from regression suite"
                )
            elif (
                regression_event.get("payload", {}).get("execution_suite_object_sha256")
                != evidence.execution_suite_object_sha256
            ):
                violations.append(
                    "release evidence suite object differs from regression suite"
                )
            manifest = self._committed_manifest(state)
            violations.extend(_package_coverage_violations(manifest))
            if violations:
                raise RefineryGateError(violations)
            context_object_sha256 = self._retain_transition_context(context)
            evidence_object_sha256 = self._put_object(_json_bytes(evidence.as_dict()))
            return self._append_event(
                state,
                "release_complete",
                package_sha256=state.package_sha256,
                payload={
                    "release_evidence_sha256": evidence.evidence_sha256,
                    "release_evidence_object_sha256": evidence_object_sha256,
                    "execution_suite_sha256": evidence.execution_suite_sha256,
                    "execution_suite_object_sha256": (
                        evidence.execution_suite_object_sha256
                    ),
                    "transition_context_sha256": context.context_sha256,
                    "transition_context_object_sha256": context_object_sha256,
                    "provenance_closure_sha256": (evidence.provenance_closure_sha256),
                    "provenance_closure_object_sha256": (
                        evidence.provenance_closure_object_sha256
                    ),
                },
                recorded_at=when,
            )

    def promote(
        self,
        delta_sha256: str,
        authorization: RefineryAuthorizationDTO,
        *,
        context: TransitionContextDTO,
        recorded_at: Optional[str] = None,
    ) -> IndustryPackageDescriptorDTO:
        """Promote without overwrite after explicit package-scoped authority.

        The refinement event is prepared before the registry pointer moves.
        Every intermediate artifact is immutable and deterministic, so a retry
        with the exact same authorization safely completes an interrupted
        cross-ledger promotion.  Public ``status`` still fails closed until the
        refinement and registry agree.
        """

        when = recorded_at or utc_now()
        _validate_timestamp(when, "promotion recorded_at")
        with _exclusive_lock(self.root / ".refinery.lock"):
            self._recover_registry_if_needed()
            state, docs = self._load_refinement(delta_sha256)
            delta = PackageDelta.from_dict(docs["delta"])
            binding = ProjectOntologyBinding.from_dict(docs["binding"])
            engagement = SemanticEngagementReceipt.from_dict(docs["engagement"])
            violations = self._authorization_violations(
                authorization, delta, binding, action="promote"
            )
            try:
                self._validate_transition_context(
                    context,
                    delta,
                    binding,
                    expected_action="promoted",
                )
            except RefineryGateError as exc:
                violations.extend(exc.violations)
            if violations:
                raise RefineryGateError(violations)

            if state.state == "promoted":
                event = self._verified_history(state)[-1]
                payload = event["payload"]
                if payload.get("authorization_sha256") != (
                    authorization.authorization_sha256
                ):
                    raise RefineryGateError(
                        ("retry authorization differs from promoted event",)
                    )
                if payload.get("transition_context_sha256") != (
                    context.context_sha256
                ) or payload.get("transition_context_object_sha256") != (
                    _sha256_bytes(_json_bytes(context.as_dict()))
                ):
                    raise RefineryGateError(
                        ("retry transition context differs from promoted event",)
                    )
                retry_context_object_sha256 = _required_sha256(
                    payload.get("transition_context_object_sha256"),
                    "promotion transition_context_object_sha256",
                )
                provenance_closure, provenance_closure_object_sha256 = (
                    self._build_promotion_provenance_closure(
                        state,
                        delta,
                        context=context,
                        context_object_sha256=retry_context_object_sha256,
                        persist=False,
                    )
                )
                record = self._build_promotion_record(
                    state,
                    delta,
                    engagement,
                    authorization,
                    authorization_object_sha256=str(
                        payload.get("authorization_object_sha256", "")
                    ),
                    context=context,
                    context_object_sha256=retry_context_object_sha256,
                    provenance_closure=provenance_closure,
                    provenance_closure_object_sha256=(provenance_closure_object_sha256),
                    promoted_at=_strict_text(event.get("recorded_at"), "promoted_at"),
                )
                if payload.get("promotion_record_sha256") != record.get(
                    "promotion_record_sha256"
                ):
                    raise RefineryWorkspaceError(
                        "promoted event does not bind deterministic registry record"
                    )
                try:
                    existing = self.resolve_package(
                        delta.package_id, version=delta.target_version
                    )
                except IndustryPackageNotFoundError:
                    violations = self._baseline_violations(delta, binding)
                    if violations:
                        raise RefineryGateError(violations)
                    self._publish_registry_record(record)
                    return _descriptor_from_record(record)
                if (
                    existing.promotion_record_sha256
                    != record["promotion_record_sha256"]
                ):
                    raise RefineryWorkspaceError(
                        "registry version conflicts with promoted refinement"
                    )
                return existing

            self._require_transition(state, "promoted")
            violations = self._baseline_violations(delta, binding)
            if violations:
                raise RefineryGateError(violations)
            context_object_sha256 = self._retain_transition_context(context)
            authorization_object_sha256 = self._put_object(
                _json_bytes(authorization.as_dict())
            )
            provenance_closure, provenance_closure_object_sha256 = (
                self._build_promotion_provenance_closure(
                    state,
                    delta,
                    context=context,
                    context_object_sha256=context_object_sha256,
                    persist=True,
                )
            )
            record = self._build_promotion_record(
                state,
                delta,
                engagement,
                authorization,
                authorization_object_sha256=authorization_object_sha256,
                context=context,
                context_object_sha256=context_object_sha256,
                provenance_closure=provenance_closure,
                provenance_closure_object_sha256=(provenance_closure_object_sha256),
                promoted_at=when,
            )
            self._append_event(
                state,
                "promoted",
                package_sha256=state.package_sha256,
                payload={
                    "promotion_record_sha256": record["promotion_record_sha256"],
                    "authorization_sha256": authorization.authorization_sha256,
                    "authorization_object_sha256": authorization_object_sha256,
                    "promotion_target": binding.promotion_target,
                    "transition_context_sha256": context.context_sha256,
                    "transition_context_object_sha256": context_object_sha256,
                    "provenance_closure_sha256": (provenance_closure.closure_sha256),
                    "provenance_closure_object_sha256": (
                        provenance_closure_object_sha256
                    ),
                },
                recorded_at=when,
            )
            try:
                self._publish_registry_record(record)
            except Exception as exc:
                raise RefineryWorkspaceError(
                    "promotion is prepared but registry publication is incomplete; "
                    "retry with the exact authorization"
                ) from exc
            return _descriptor_from_record(record)

    def _build_promotion_provenance_closure(
        self,
        state: RefineryStateDTO,
        delta: PackageDelta,
        *,
        context: TransitionContextDTO,
        context_object_sha256: str,
        persist: bool,
    ) -> Tuple[ProvenanceClosureDTO, str]:
        lifecycle = self._verified_history(state)
        regression_event = next(
            item for item in lifecycle if item["state"] == "regression_passed"
        )
        release_event = next(
            item for item in lifecycle if item["state"] == "release_complete"
        )
        regression_evidence = RefineryGateEvidenceDTO.from_dict(
            self._get_json_object(
                _required_sha256(
                    regression_event["payload"].get(
                        "regression_evidence_object_sha256"
                    ),
                    "regression_evidence_object_sha256",
                )
            )
        )
        release_evidence = RefineryGateEvidenceDTO.from_dict(
            self._get_json_object(
                _required_sha256(
                    release_event["payload"].get("release_evidence_object_sha256"),
                    "release_evidence_object_sha256",
                )
            )
        )
        suite, _ = self._load_execution_suite(
            delta.delta_sha256, release_evidence.execution_suite_sha256
        )
        execution_closure = ProvenanceClosureDTO.from_dict(
            self._get_json_object(suite.provenance_closure_object_sha256)
        )
        regression_closure = ProvenanceClosureDTO.from_dict(
            self._get_json_object(regression_evidence.provenance_closure_object_sha256)
        )
        release_closure = ProvenanceClosureDTO.from_dict(
            self._get_json_object(release_evidence.provenance_closure_object_sha256)
        )
        contexts: Dict[str, Tuple[str, str]] = {}
        for closure in (
            execution_closure,
            regression_closure,
            release_closure,
        ):
            for action, context_sha, object_sha in closure.transition_contexts:
                previous = contexts.get(action)
                if previous is not None and previous != (context_sha, object_sha):
                    raise RefineryWorkspaceError(
                        "provenance closures disagree on transition context"
                    )
                contexts[action] = (context_sha, object_sha)
        for event in lifecycle:
            payload = _mapping(event.get("payload"), "event payload")
            action = _EVENT_CONTEXT_ACTION[str(event.get("state"))]
            binding_value = (
                _required_sha256(
                    payload.get("transition_context_sha256"),
                    "event transition_context_sha256",
                ),
                _required_sha256(
                    payload.get("transition_context_object_sha256"),
                    "event transition_context_object_sha256",
                ),
            )
            previous = contexts.get(action)
            if previous is not None and previous != binding_value:
                raise RefineryWorkspaceError(
                    "event and provenance closure transition contexts differ"
                )
            contexts[action] = binding_value
        if contexts.get("promoted") not in {
            None,
            (
                context.context_sha256,
                context_object_sha256,
            ),
        }:
            raise RefineryWorkspaceError(
                "promotion transition context differs from lifecycle"
            )
        contexts["promoted"] = (
            context.context_sha256,
            context_object_sha256,
        )
        closure = ProvenanceClosureDTO.create(
            phase="promotion",
            workspace_id=execution_closure.workspace_id,
            delta_sha256=execution_closure.delta_sha256,
            package_id=execution_closure.package_id,
            package_version=execution_closure.package_version,
            package_sha256=execution_closure.package_sha256,
            manifest_sha256=execution_closure.manifest_sha256,
            execution_projection_sha256=(execution_closure.execution_projection_sha256),
            source_evidence=execution_closure.source_evidence,
            candidate_envelope_sha256=(execution_closure.candidate_envelope_sha256),
            candidate_binding_sha256=(execution_closure.candidate_binding_sha256),
            engagement_receipt_sha256=(execution_closure.engagement_receipt_sha256),
            transition_contexts=tuple(
                sorted(
                    (
                        (action, value[0], value[1])
                        for action, value in contexts.items()
                    ),
                    key=lambda item: _TRANSITION_CONTEXT_ORDER[item[0]],
                )
            ),
            runtime_source=execution_closure.runtime_source,
            provenance_evidence_assets=(execution_closure.provenance_evidence_assets),
            scenarios=execution_closure.scenarios,
            prior_closure_sha256=release_closure.closure_sha256,
        )
        object_sha = self._retain_or_verify_object(
            _json_bytes(closure.as_dict()), persist=persist
        )
        return closure, object_sha

    def _build_promotion_record(
        self,
        state: RefineryStateDTO,
        delta: PackageDelta,
        engagement: SemanticEngagementReceipt,
        authorization: RefineryAuthorizationDTO,
        *,
        authorization_object_sha256: str,
        context: TransitionContextDTO,
        context_object_sha256: str,
        provenance_closure: ProvenanceClosureDTO,
        provenance_closure_object_sha256: str,
        promoted_at: str,
    ) -> Mapping[str, Any]:
        _required_sha256(authorization_object_sha256, "authorization_object_sha256")
        manifest = self._committed_manifest(state)
        manifest_sha256 = _sha256_bytes(_json_bytes(manifest))
        lifecycle = self._verified_history(state)
        regression_event = next(
            item for item in lifecycle if item["state"] == "regression_passed"
        )
        release_event = next(
            item for item in lifecycle if item["state"] == "release_complete"
        )
        release_evidence = RefineryGateEvidenceDTO.from_dict(
            self._get_json_object(
                _required_sha256(
                    release_event["payload"].get("release_evidence_object_sha256"),
                    "release_evidence_object_sha256",
                )
            )
        )
        record_content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "package_id": delta.package_id,
            "version": delta.target_version,
            "package_sha256": state.package_sha256,
            "manifest_sha256": manifest_sha256,
            "delta_sha256": delta.delta_sha256,
            "engagement_receipt_sha256": engagement.receipt_sha256,
            "regression_evidence_sha256": regression_event["payload"][
                "regression_evidence_sha256"
            ],
            "release_evidence_sha256": release_event["payload"][
                "release_evidence_sha256"
            ],
            "subject_execution_suite_sha256": release_event["payload"][
                "execution_suite_sha256"
            ],
            "transition_context_sha256": context.context_sha256,
            "transition_context_object_sha256": context_object_sha256,
            "provenance_closure_sha256": provenance_closure.closure_sha256,
            "provenance_closure_object_sha256": (provenance_closure_object_sha256),
            "authorization_sha256": authorization.authorization_sha256,
            "authorization_object_sha256": authorization_object_sha256,
            "book_impact": delta.book_impact,
            "runtime_source": release_evidence.runtime_source.as_dict(),
            "promoted_at": promoted_at,
            "status": "promoted",
        }
        record_sha256 = sha256_text(canonical_json(record_content))
        return {**record_content, "promotion_record_sha256": record_sha256}

    def status(self, delta_sha256: str) -> RefineryStateDTO:
        """Return the verified latest state for one exact candidate digest."""

        with _exclusive_lock(self.root / ".refinery.lock"):
            state, docs = self._load_refinement(delta_sha256)
            self._verify_promoted_registry(state, docs)
            return state

    def history(self, delta_sha256: str) -> Tuple[Mapping[str, Any], ...]:
        """Verify and return the unbroken immutable event chain."""

        with _exclusive_lock(self.root / ".refinery.lock"):
            state, docs = self._load_refinement(delta_sha256)
            self._verify_promoted_registry(state, docs)
            return self._verified_history(state)

    def _verify_promoted_registry(
        self,
        state: RefineryStateDTO,
        docs: Mapping[str, Mapping[str, Any]],
    ) -> None:
        if state.state != "promoted":
            return
        delta = PackageDelta.from_dict(docs["delta"])
        engagement = SemanticEngagementReceipt.from_dict(docs["engagement"])
        lifecycle = self._verified_history(state)
        event = lifecycle[-1]
        commit_event = next(item for item in lifecycle if item["state"] == "committed")
        regression_event = next(
            item for item in lifecycle if item["state"] == "regression_passed"
        )
        release_event = next(
            item for item in lifecycle if item["state"] == "release_complete"
        )
        try:
            descriptor = self.resolve_package(
                delta.package_id, version=delta.target_version
            )
        except IndustryPackageNotFoundError as exc:
            raise RefineryWorkspaceError(
                "promoted refinement is absent from the industry registry"
            ) from exc
        expected = {
            "package_sha256": state.package_sha256,
            "manifest_sha256": commit_event["payload"].get("manifest_sha256"),
            "promotion_record_sha256": event["payload"].get("promotion_record_sha256"),
            "delta_sha256": delta.delta_sha256,
            "engagement_receipt_sha256": engagement.receipt_sha256,
            "regression_evidence_sha256": regression_event["payload"].get(
                "regression_evidence_sha256"
            ),
            "release_evidence_sha256": release_event["payload"].get(
                "release_evidence_sha256"
            ),
            "subject_execution_suite_sha256": release_event["payload"].get(
                "execution_suite_sha256"
            ),
            "transition_context_sha256": event["payload"].get(
                "transition_context_sha256"
            ),
            "transition_context_object_sha256": event["payload"].get(
                "transition_context_object_sha256"
            ),
            "provenance_closure_sha256": event["payload"].get(
                "provenance_closure_sha256"
            ),
            "provenance_closure_object_sha256": event["payload"].get(
                "provenance_closure_object_sha256"
            ),
            "authorization_sha256": event["payload"].get("authorization_sha256"),
            "authorization_object_sha256": event["payload"].get(
                "authorization_object_sha256"
            ),
        }
        for field, expected_value in expected.items():
            if getattr(descriptor, field) != expected_value:
                raise RefineryWorkspaceError(
                    "promoted refinement and registry differ at {}".format(field)
                )

    def _verified_history(
        self, state: RefineryStateDTO
    ) -> Tuple[Mapping[str, Any], ...]:
        event_dir = self._delta_root(state.delta_sha256) / "events"
        self._assert_managed_path(
            event_dir, require_exists=True, require_directory=True
        )
        events = []
        previous: Optional[str] = None
        for sequence, path in enumerate(sorted(event_dir.glob("*.json")), start=1):
            value = _read_json(path)
            try:
                _validate_refinery_event(value)
            except RefineryInputError as exc:
                raise RefineryWorkspaceError(
                    "refinery event schema/integrity check failed"
                ) from exc
            if value.get("sequence") != sequence:
                raise RefineryWorkspaceError(
                    "refinery event sequence is not contiguous"
                )
            if value.get("previous_event_sha256") != previous:
                raise RefineryWorkspaceError("refinery event hash chain is broken")
            declared = _required_sha256(value.get("event_sha256"), "event_sha256")
            content = dict(value)
            content.pop("event_sha256", None)
            actual = sha256_text(canonical_json(content))
            if actual != declared or path.stem != "{:06d}-{}".format(sequence, actual):
                raise RefineryWorkspaceError("refinery event integrity check failed")
            self._verify_event_objects(value)
            events.append(value)
            previous = actual
        if len(events) != state.sequence or previous != state.event_sha256:
            raise RefineryWorkspaceError("refinery current pointer is not latest event")
        expected_states = REFINERY_STATES[: len(events)]
        if tuple(item.get("state") for item in events) != expected_states:
            raise RefineryWorkspaceError("refinery state history is invalid")
        return tuple(events)

    def _verify_event_objects(self, event: Mapping[str, Any]) -> None:
        state = event.get("state")
        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            raise RefineryWorkspaceError("refinery event payload must be a mapping")
        try:
            context = self._load_transition_context(
                _required_sha256(
                    payload.get("transition_context_sha256"),
                    "event transition_context_sha256",
                ),
                _required_sha256(
                    payload.get("transition_context_object_sha256"),
                    "event transition_context_object_sha256",
                ),
            )
            event_delta = _required_sha256(
                event.get("delta_sha256"), "event delta_sha256"
            )
            root = self._delta_root(event_delta)
            delta = PackageDelta.from_dict(_read_json(root / "delta.json"))
            binding = ProjectOntologyBinding.from_dict(
                _read_json(root / "binding.json")
            )
            self._validate_transition_context(
                context,
                delta,
                binding,
                expected_action=_EVENT_CONTEXT_ACTION[str(state)],
            )
        except (KeyError, RefineryInputError, RefineryGateError) as exc:
            raise RefineryWorkspaceError(
                "refinery event transition context is invalid"
            ) from exc
        if state == "committed":
            object_sha = _required_sha256(
                payload.get("authorization_object_sha256"),
                "authorization_object_sha256",
            )
            authorization = RefineryAuthorizationDTO.from_dict(
                self._get_json_object(object_sha)
            )
            if authorization.authorization_sha256 != payload.get(
                "authorization_sha256"
            ):
                raise RefineryWorkspaceError(
                    "commit authorization object identity mismatch"
                )
        elif state in {"regression_passed", "release_complete"}:
            prefix = "regression" if state == "regression_passed" else "release"
            object_sha = _required_sha256(
                payload.get("{}_evidence_object_sha256".format(prefix)),
                "{}_evidence_object_sha256".format(prefix),
            )
            evidence = RefineryGateEvidenceDTO.from_dict(
                self._get_json_object(object_sha)
            )
            if evidence.evidence_sha256 != payload.get(
                "{}_evidence_sha256".format(prefix)
            ):
                raise RefineryWorkspaceError(
                    "{} evidence object identity mismatch".format(prefix)
                )
            if evidence.execution_suite_sha256 != payload.get(
                "execution_suite_sha256"
            ) or evidence.execution_suite_object_sha256 != payload.get(
                "execution_suite_object_sha256"
            ):
                raise RefineryWorkspaceError(
                    "{} evidence suite identity mismatch".format(prefix)
                )
            if evidence.provenance_closure_sha256 != payload.get(
                "provenance_closure_sha256"
            ) or evidence.provenance_closure_object_sha256 != payload.get(
                "provenance_closure_object_sha256"
            ):
                raise RefineryWorkspaceError(
                    "{} evidence provenance closure identity mismatch".format(prefix)
                )
            closure = ProvenanceClosureDTO.from_dict(
                self._get_json_object(evidence.provenance_closure_object_sha256)
            )
            if closure.closure_sha256 != evidence.provenance_closure_sha256:
                raise RefineryWorkspaceError(
                    "{} provenance closure object identity mismatch".format(prefix)
                )
            suite, suite_object_sha = self._load_execution_suite(
                str(event.get("delta_sha256")), evidence.execution_suite_sha256
            )
            if (
                suite_object_sha != evidence.execution_suite_object_sha256
                or suite.suite_sha256 != evidence.execution_suite_sha256
            ):
                raise RefineryWorkspaceError(
                    "{} evidence suite object is inconsistent".format(prefix)
                )
            for check in evidence.checks:
                output = self._get_json_object(check.output_sha256)
                if (
                    output.get("gate") != evidence.gate
                    or output.get("check_id") != check.check_id
                    or output.get("execution_suite_sha256")
                    != evidence.execution_suite_sha256
                    or output.get("transition_context_sha256")
                    != evidence.transition_context_sha256
                    or output.get("provenance_closure_sha256")
                    != evidence.provenance_closure_sha256
                    or output.get("passed") != check.passed
                    or output.get("message") != check.message
                ):
                    raise RefineryWorkspaceError(
                        "{} gate check output identity mismatch".format(prefix)
                    )
        elif state == "promoted":
            object_sha = _required_sha256(
                payload.get("authorization_object_sha256"),
                "promotion authorization_object_sha256",
            )
            authorization = RefineryAuthorizationDTO.from_dict(
                self._get_json_object(object_sha)
            )
            if authorization.authorization_sha256 != payload.get(
                "authorization_sha256"
            ):
                raise RefineryWorkspaceError(
                    "promotion authorization object identity mismatch"
                )
            closure = ProvenanceClosureDTO.from_dict(
                self._get_json_object(
                    _required_sha256(
                        payload.get("provenance_closure_object_sha256"),
                        "promotion provenance_closure_object_sha256",
                    )
                )
            )
            if (
                closure.closure_sha256 != payload.get("provenance_closure_sha256")
                or closure.phase != "promotion"
            ):
                raise RefineryWorkspaceError(
                    "promotion provenance closure identity mismatch"
                )

    def list_packages(self) -> Tuple[IndustryPackageDescriptorDTO, ...]:
        registry = self._read_registry()
        descriptors = []
        for package_id, package in sorted(registry["packages"].items()):
            for version in sorted(package["versions"]):
                descriptors.append(self.resolve_package(package_id, version=version))
        return tuple(descriptors)

    def resolve_package(
        self, package_id: str, *, version: Optional[str] = None
    ) -> IndustryPackageDescriptorDTO:
        """Resolve only an allowlisted registry ID; never interpret it as a path."""

        _validate_package_id(package_id)
        registry = self._read_registry()
        package = registry["packages"].get(package_id)
        if not isinstance(package, Mapping):
            raise IndustryPackageNotFoundError(
                "unknown industry package ID: {}".format(package_id)
            )
        requested = (
            _strict_text(version, "package version")
            if version is not None
            else _strict_text(package.get("current_version"), "current_version")
        )
        entry = package["versions"].get(requested)
        if not isinstance(entry, Mapping):
            raise IndustryPackageNotFoundError(
                "unknown industry package version: {}@{}".format(package_id, requested)
            )
        record = self._read_package_record(
            package_id, requested, str(entry["record_sha256"])
        )
        return _descriptor_from_record(record)

    def read_asset(
        self,
        package_id: str,
        asset_id: str,
        *,
        version: Optional[str] = None,
    ) -> bytes:
        """Read an exact registered asset by opaque IDs only."""

        descriptor = self.resolve_package(package_id, version=version)
        _validate_opaque_id(asset_id, "asset_id")
        manifest = self._get_json_object(descriptor.manifest_sha256)
        matches = [
            item
            for item in manifest.get("assets", [])
            if item.get("asset_id") == asset_id
        ]
        if len(matches) != 1:
            raise IndustryPackageNotFoundError(
                "package asset ID is absent or ambiguous: {}".format(asset_id)
            )
        digest = _required_sha256(matches[0].get("sha256"), "asset sha256")
        return self._get_object(digest)

    def execution_manifest(
        self, package_id: str, *, version: Optional[str] = None
    ) -> Mapping[str, Any]:
        """Build a path-free runner manifest for one promoted package."""

        descriptor = self.resolve_package(package_id, version=version)
        manifest = self._get_json_object(descriptor.manifest_sha256)
        if manifest.get("package_sha256") != descriptor.package_sha256:
            raise RefineryWorkspaceError(
                "registered subject manifest differs from package descriptor"
            )
        execution_manifest, _ = self._build_execution_manifest(manifest)
        return execution_manifest

    def execute_candidate(
        self,
        delta_sha256: str,
        *,
        context: TransitionContextDTO,
        runtime_source: RuntimeSourceIdentityDTO,
        created_at: Optional[str] = None,
    ) -> SubjectExecutionSuiteDTO:
        """Run the contract-locked gate suite inside Semantica and retain it."""

        if not runtime_source.complete:
            raise RefineryGateError(("execution runtime source is incomplete",))
        when = created_at or utc_now()
        _validate_timestamp(when, "execution suite created_at")
        with _exclusive_lock(self.root / ".refinery.lock"):
            state, docs = self._load_refinement(delta_sha256)
            if state.state not in {
                "committed",
                "regression_passed",
                "release_complete",
            }:
                raise RefineryStateError(
                    "execute_candidate requires a committed subject package"
                )
            delta = PackageDelta.from_dict(docs["delta"])
            binding = ProjectOntologyBinding.from_dict(docs["binding"])
            self._validate_transition_context(
                context,
                delta,
                binding,
                expected_action="execute_candidate",
            )
            context_object_sha256 = self._retain_transition_context(context)
            manifest = self._committed_manifest(state)
            execution_manifest, projection = self._build_execution_manifest(manifest)
            commit_event = next(
                item
                for item in self._verified_history(state)
                if item["state"] == "committed"
            )
            manifest_sha = _required_sha256(
                commit_event["payload"].get("manifest_sha256"),
                "subject manifest_sha256",
            )
            cq_registry_bindings = self._cq_registry_bindings(manifest, projection)
            required_prior_cqs, required_prior_cases = self._derive_prior_requirements(
                state=state,
                delta=delta,
                manifest=manifest,
                projection=projection,
            )
            # Fail before native result writes if package provenance does not
            # exactly mirror the delta's source-evidence identities/hashes.
            self._provenance_evidence_bindings(
                delta=delta,
                manifest=manifest,
                projection=projection,
            )
            gate_suite = _mapping(projection.get("gate_suite"), "gate_suite")
            scenario_ids = tuple(
                sorted(
                    {
                        scenario_id
                        for check in gate_suite.values()
                        for scenario_id in _text_tuple(
                            _mapping(check, "gate suite check").get("scenario_ids"),
                            "gate suite scenario_ids",
                        )
                    }
                )
            )
            cq_ids = tuple(
                sorted(
                    {
                        cq_id
                        for check in gate_suite.values()
                        for cq_id in _text_tuple(
                            _mapping(check, "gate suite check").get("cq_ids"),
                            "gate suite cq_ids",
                            allow_empty=True,
                        )
                    }
                )
            )
            from semantica.chapter_packages.runner import SemanticPackageRunner

            runner = SemanticPackageRunner()
            runs = []
            observed_capabilities = set()
            case_assets_by_id = {
                item["asset_id"]: (item["case_kind"], item["sha256"])
                for item in manifest["assets"]
                if item.get("category") == "cases"
            }
            for scenario_id in scenario_ids:
                result = runner.run_manifest(
                    execution_manifest,
                    scenario_id,
                    runtime_commit=runtime_source.runtime_commit,
                    runtime_artifact_sha256=(runtime_source.runtime_artifact_sha256),
                    runtime_version=runtime_source.runtime_version,
                    created_at=when,
                )
                verdict = runner.verify(result, checked_at=when)
                receipt = result.receipt
                if receipt is None or not receipt.verify_integrity():
                    raise RefineryGateError(
                        (
                            "Semantica runner did not produce an integral native "
                            "receipt for {}".format(scenario_id),
                        )
                    )
                if (
                    receipt.runtime_commit != runtime_source.runtime_commit
                    or receipt.runtime_artifact_sha256
                    != runtime_source.runtime_artifact_sha256
                    or receipt.runtime_version != runtime_source.runtime_version
                ):
                    raise RefineryGateError(
                        ("native runner receipt source identity mismatch",)
                    )
                capability_payload = receipt.capability_report.payload
                if isinstance(capability_payload, Mapping):
                    profile = capability_payload.get("profile")
                    if isinstance(profile, Mapping):
                        raw_capabilities = profile.get("capabilities")
                        if isinstance(raw_capabilities, list):
                            observed_capabilities.update(
                                item
                                for item in raw_capabilities
                                if isinstance(item, str) and item
                            )
                run_object_sha = self._put_object(_json_bytes(result.as_dict()))
                receipt_object_sha = self._put_object(_json_bytes(receipt.as_dict()))
                cq_payload = result.cq_report.payload
                raw_cq_ids = (
                    cq_payload.get("competency_question_ids", [])
                    if isinstance(cq_payload, Mapping)
                    else []
                )
                actual_cq_ids = tuple(
                    sorted(
                        {item for item in raw_cq_ids if isinstance(item, str) and item}
                    )
                )
                loaded_asset_ids = {
                    operation.payload.get("asset_id")
                    for operation in result.operations
                    if operation.operation in {"load", "load_asset"}
                    and isinstance(operation.payload, Mapping)
                }
                actual_cases = tuple(
                    sorted(
                        (
                            case_assets_by_id[asset_id][0],
                            asset_id,
                            case_assets_by_id[asset_id][1],
                        )
                        for asset_id in loaded_asset_ids
                        if asset_id in case_assets_by_id
                    )
                )
                runs.append(
                    SubjectScenarioRunDTO(
                        scenario_id=scenario_id,
                        run_result_object_sha256=run_object_sha,
                        receipt_sha256=receipt.receipt_sha256,
                        receipt_object_sha256=receipt_object_sha,
                        executor_package_id=result.package_id,
                        executor_package_version=result.package_version,
                        executor_package_digest=result.package_digest,
                        cq_ids=actual_cq_ids,
                        case_assets=actual_cases,
                        status=result.status,
                        release_status=verdict.status,
                    )
                )

            execution_assets = tuple(
                sorted(
                    (
                        str(item["asset_id"]),
                        _required_sha256(item.get("sha256"), "execution asset sha"),
                    )
                    for item in execution_manifest["assets"]
                )
            )
            status = (
                "complete"
                if runs
                and all(
                    item.status == "passed" and item.release_status == "complete"
                    for item in runs
                )
                else "blocked"
            )
            provenance_closure = self._build_execution_provenance_closure(
                state=state,
                docs=docs,
                delta=delta,
                manifest_sha256=manifest_sha,
                projection=projection,
                manifest=manifest,
                runs=runs,
                runtime_source=runtime_source,
                context=context,
                context_object_sha256=context_object_sha256,
            )
            provenance_closure_object_sha256 = self._put_object(
                _json_bytes(provenance_closure.as_dict())
            )
            suite = SubjectExecutionSuiteDTO.create(
                workspace_id=self.registry_id,
                delta_sha256=delta.delta_sha256,
                subject_package_id=delta.package_id,
                subject_package_version=delta.target_version,
                subject_package_sha256=_required_sha256(
                    state.package_sha256, "subject package_sha256"
                ),
                subject_manifest_sha256=manifest_sha,
                execution_projection_sha256=_required_sha256(
                    projection.get("_projection_sha256"),
                    "execution projection sha256",
                ),
                execution_asset_hashes=execution_assets,
                transition_context_sha256=context.context_sha256,
                transition_context_object_sha256=context_object_sha256,
                provenance_closure_sha256=(provenance_closure.closure_sha256),
                provenance_closure_object_sha256=(provenance_closure_object_sha256),
                required_prior_cq_bindings=required_prior_cqs,
                required_prior_case_bindings=required_prior_cases,
                cq_registry_bindings=cq_registry_bindings,
                required_scenario_ids=scenario_ids,
                required_cq_ids=cq_ids,
                required_case_kinds=CASE_KINDS,
                runs=tuple(sorted(runs, key=lambda item: item.scenario_id)),
                runtime_source=runtime_source,
                observed_capabilities=tuple(sorted(observed_capabilities)),
                status=status,
                created_at=when,
            )
            suite_object_sha = self._put_object(_json_bytes(suite.as_dict()))
            self._index_execution_suite(suite, suite_object_sha)
            return suite

    def gate_evidence(
        self,
        delta_sha256: str,
        *,
        context: TransitionContextDTO,
        gate: str,
        execution_suite_sha256: str,
        recorded_at: Optional[str] = None,
    ) -> RefineryGateEvidenceDTO:
        """Derive a gate DTO only from a verified Semantica execution suite."""

        when = recorded_at or utc_now()
        _validate_timestamp(when, "gate recorded_at")
        with _exclusive_lock(self.root / ".refinery.lock"):
            state, docs = self._load_refinement(delta_sha256)
            delta = PackageDelta.from_dict(docs["delta"])
            binding = ProjectOntologyBinding.from_dict(docs["binding"])
            expected_action = (
                "derive_regression_gate"
                if gate == "regression"
                else "derive_release_gate"
                if gate == "release"
                else ""
            )
            if not expected_action:
                raise RefineryInputError("gate must be regression or release")
            required_state = (
                "committed" if gate == "regression" else "regression_passed"
            )
            if state.state != required_state:
                raise RefineryStateError(
                    "{} gate derivation requires exact {} state".format(
                        gate, required_state
                    )
                )
            self._validate_transition_context(
                context,
                delta,
                binding,
                expected_action=expected_action,
            )
            context_object_sha256 = self._retain_transition_context(context)
            return self._derive_gate_evidence(
                state,
                docs,
                gate=gate,
                suite_sha256=execution_suite_sha256,
                recorded_at=when,
                context=context,
                context_object_sha256=context_object_sha256,
                persist=True,
            )

    def _build_execution_manifest(
        self, manifest: Mapping[str, Any]
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        self._verify_manifest_assets(manifest)
        assets = manifest.get("assets")
        if not isinstance(assets, list):
            raise RefineryWorkspaceError("subject manifest assets are invalid")
        contract_assets = [
            item for item in assets if item.get("category") == "contract"
        ]
        if len(contract_assets) != 1:
            raise RefineryGateError(
                ("executable package requires exactly one contract asset",)
            )
        contract = contract_assets[0]
        projection_sha = _required_sha256(
            contract.get("sha256"), "execution projection sha256"
        )
        try:
            projection = json.loads(self._get_object(projection_sha).decode("utf-8"))
        except Exception as exc:
            raise RefineryGateError(("contract asset must be UTF-8 JSON",)) from exc
        if not isinstance(projection, Mapping):
            raise RefineryGateError(("execution projection must be a mapping",))
        projection = dict(projection)
        try:
            _validate_execution_projection(projection, assets)
        except RefineryInputError as exc:
            raise RefineryGateError(
                ("invalid execution projection: {}".format(exc),)
            ) from exc
        projection["_projection_sha256"] = projection_sha
        metadata = _mapping(projection.get("assets"), "projection assets")
        runtime_assets = []
        for item in assets:
            asset_id = _strict_text(item.get("asset_id"), "asset_id")
            settings = _mapping(metadata.get(asset_id), "asset runtime metadata")
            runtime_asset = {
                "asset_id": asset_id,
                "role": settings["role"],
                "data": self._get_object(
                    _required_sha256(item.get("sha256"), "asset sha256")
                ),
                "sha256": item["sha256"],
                "format": settings["format"],
                "kind": settings["kind"],
                "load_into_dataset": settings["load_into_dataset"],
            }
            if settings.get("graph_name") is not None:
                runtime_asset["graph_name"] = settings["graph_name"]
            runtime_assets.append(runtime_asset)
        self._validate_projection_registries(projection, runtime_assets)
        return (
            {
                "schema_version": "1.0",
                "package_id": manifest["package_id"],
                "version": manifest["version"],
                "namespace": projection["namespace"],
                "release_status": projection["release_status"],
                "execution": projection["execution"],
                "assets": runtime_assets,
            },
            projection,
        )

    def _validate_projection_registries(
        self,
        projection: Mapping[str, Any],
        runtime_assets: Sequence[Mapping[str, Any]],
    ) -> None:
        """Bind every declared gate scenario and CQ to retained registry bytes."""

        by_id = {
            _strict_text(item.get("asset_id"), "runtime asset_id"): item
            for item in runtime_assets
        }
        execution = _mapping(projection.get("execution"), "projection execution")
        scenario_asset_id = _strict_text(
            execution.get("scenario_registry_asset_id"),
            "scenario_registry_asset_id",
        )
        cq_asset_id = _strict_text(
            execution.get("cq_registry_asset_id"), "cq_registry_asset_id"
        )
        try:
            scenario_registry = _json_mapping_from_bytes(
                bytes(by_id[scenario_asset_id]["data"]),
                "scenario registry asset",
            )
            cq_registry = _json_mapping_from_bytes(
                bytes(by_id[cq_asset_id]["data"]), "CQ registry asset"
            )
        except (KeyError, RefineryInputError, RefineryWorkspaceError) as exc:
            raise RefineryGateError(
                ("execution registries are absent or invalid JSON",)
            ) from exc
        if scenario_registry.get("runner_contract") != (
            SEMANTIC_PACKAGE_RUNNER_CONTRACT
        ):
            raise RefineryGateError(
                ("scenario registry runner_contract is unsupported",)
            )
        raw_scenarios = scenario_registry.get("scenarios")
        if not isinstance(raw_scenarios, list) or not raw_scenarios:
            raise RefineryGateError(("scenario registry has no scenarios",))
        scenario_ids = []
        for item in raw_scenarios:
            if not isinstance(item, Mapping):
                raise RefineryGateError(("scenario registry entry is invalid",))
            scenario_ids.append(_strict_text(item.get("id"), "scenario id"))
        if len(scenario_ids) != len(set(scenario_ids)):
            raise RefineryGateError(("scenario registry IDs are duplicated",))

        raw_cqs = cq_registry.get("competency_questions")
        if not isinstance(raw_cqs, list) or not raw_cqs:
            raise RefineryGateError(("CQ registry has no competency questions",))
        cq_bindings: Dict[str, Tuple[str, ...]] = {}
        for item in raw_cqs:
            if not isinstance(item, Mapping):
                raise RefineryGateError(("CQ registry entry is invalid",))
            cq_id = _strict_text(item.get("id"), "CQ id")
            if cq_id in cq_bindings:
                raise RefineryGateError(("CQ registry IDs are duplicated",))
            cq_bindings[cq_id] = _text_tuple(
                item.get("scenario_ids"), "CQ scenario_ids"
            )
        unknown_cq_scenarios = sorted(
            {
                scenario_id
                for bindings in cq_bindings.values()
                for scenario_id in bindings
                if scenario_id not in scenario_ids
            }
        )
        if unknown_cq_scenarios:
            raise RefineryGateError(
                (
                    "CQ registry binds unknown scenarios: {}".format(
                        ", ".join(unknown_cq_scenarios)
                    ),
                )
            )

        gate_suite = _mapping(projection.get("gate_suite"), "gate_suite")
        violations = []
        for check_id in REGRESSION_REQUIRED_CHECK_IDS:
            check = _mapping(gate_suite.get(check_id), "gate suite check")
            declared_scenarios = _text_tuple(
                check.get("scenario_ids"), "gate scenario_ids"
            )
            declared_cqs = _text_tuple(
                check.get("cq_ids"), "gate cq_ids", allow_empty=True
            )
            for scenario_id in declared_scenarios:
                if scenario_id not in scenario_ids:
                    violations.append(
                        "{} binds unknown scenario {}".format(check_id, scenario_id)
                    )
            for cq_id in declared_cqs:
                bindings = cq_bindings.get(cq_id)
                if bindings is None:
                    violations.append("{} binds unknown CQ {}".format(check_id, cq_id))
                elif not set(bindings).intersection(declared_scenarios):
                    violations.append(
                        "{} CQ {} is not bound to its declared scenarios".format(
                            check_id, cq_id
                        )
                    )
        if violations:
            raise RefineryGateError(violations)

    def _cq_registry_bindings(
        self,
        manifest: Mapping[str, Any],
        projection: Mapping[str, Any],
    ) -> Tuple[Tuple[str, str], ...]:
        """Return exact canonical hashes for every CQ entry in a projection."""

        execution = _mapping(projection.get("execution"), "projection execution")
        registry_id = _strict_text(
            execution.get("cq_registry_asset_id"), "cq_registry_asset_id"
        )
        matches = [
            item
            for item in manifest.get("assets", [])
            if isinstance(item, Mapping) and item.get("asset_id") == registry_id
        ]
        if len(matches) != 1:
            raise RefineryGateError(("CQ registry asset is absent or ambiguous",))
        registry = _json_mapping_from_bytes(
            self._get_object(
                _required_sha256(matches[0].get("sha256"), "CQ registry sha256")
            ),
            "CQ registry asset",
        )
        raw = registry.get("competency_questions")
        if not isinstance(raw, list) or not raw:
            raise RefineryGateError(("CQ registry has no competency questions",))
        bindings = []
        for entry in raw:
            if not isinstance(entry, Mapping):
                raise RefineryGateError(("CQ registry entry is invalid",))
            cq_id = _validate_opaque_id(entry.get("id"), "CQ id")
            bindings.append((cq_id, sha256_text(canonical_json(dict(entry)))))
        if len({item[0] for item in bindings}) != len(bindings):
            raise RefineryGateError(("CQ registry IDs are duplicated",))
        return tuple(sorted(bindings))

    def _authorized_mutation_keys(
        self,
        state: RefineryStateDTO,
        delta: PackageDelta,
    ) -> frozenset:
        lifecycle = self._verified_history(state)
        committed = next(item for item in lifecycle if item["state"] == "committed")
        payload = committed["payload"]
        authorization = RefineryAuthorizationDTO.from_dict(
            self._get_json_object(
                _required_sha256(
                    payload.get("authorization_object_sha256"),
                    "commit authorization_object_sha256",
                )
            )
        )
        if authorization.authorization_sha256 != payload.get("authorization_sha256"):
            raise RefineryWorkspaceError("commit authorization identity mismatch")
        delta_keys = {
            (
                item.category,
                item.asset_id,
                item.operation,
                item.replaces_sha256,
            )
            for item in delta.assets
            if item.operation in {"replace", "remove"}
        }
        decision_keys = {item.key for item in authorization.decisions}
        if decision_keys != delta_keys:
            raise RefineryWorkspaceError(
                "commit authorization decisions differ from exact delta mutations"
            )
        return frozenset(decision_keys)

    def _derive_prior_requirements(
        self,
        *,
        state: RefineryStateDTO,
        delta: PackageDelta,
        manifest: Mapping[str, Any],
        projection: Mapping[str, Any],
    ) -> Tuple[Tuple[Tuple[str, str], ...], Tuple[Tuple[str, str], ...]]:
        """Derive prior coverage from immutable release truth, never target labels."""

        if delta.base_version == "0":
            cq_bindings = dict(self._cq_registry_bindings(manifest, projection))
            gate_suite = _mapping(projection.get("gate_suite"), "gate_suite")
            prior_cq_ids = _text_tuple(
                _mapping(gate_suite.get("cq.prior"), "cq.prior").get("cq_ids"),
                "bootstrap prior CQ IDs",
            )
            prior_case_ids = _text_tuple(
                _mapping(
                    gate_suite.get("case.prior_release"),
                    "case.prior_release",
                ).get("case_asset_ids"),
                "bootstrap prior case IDs",
            )
            manifest_cases = {
                str(item.get("asset_id")): str(item.get("sha256"))
                for item in manifest.get("assets", [])
                if isinstance(item, Mapping) and item.get("category") == "cases"
            }
            try:
                return (
                    tuple(sorted((item, cq_bindings[item]) for item in prior_cq_ids)),
                    tuple(
                        sorted((item, manifest_cases[item]) for item in prior_case_ids)
                    ),
                )
            except KeyError as exc:
                raise RefineryGateError(
                    ("bootstrap prior requirement is absent from target assets",)
                ) from exc

        descriptor = self.resolve_package(delta.package_id, version=delta.base_version)
        if descriptor.package_sha256 != delta.base_package_sha256:
            raise RefineryGateError(("immutable base descriptor digest mismatch",))
        base_manifest = self._get_json_object(descriptor.manifest_sha256)
        if base_manifest.get("package_sha256") != descriptor.package_sha256:
            raise RefineryWorkspaceError(
                "immutable base manifest differs from descriptor"
            )
        self._verify_manifest_assets(base_manifest)
        _, base_projection = self._build_execution_manifest(base_manifest)
        mutations = self._authorized_mutation_keys(state, delta)
        base_assets = {
            (str(item.get("category")), str(item.get("asset_id"))): item
            for item in base_manifest.get("assets", [])
            if isinstance(item, Mapping)
        }

        def changed(category: str, asset_id: str, digest: str) -> bool:
            return any(
                key[0] == category
                and key[1] == asset_id
                and key[2] in {"replace", "remove"}
                and key[3] == digest
                for key in mutations
            )

        base_execution = _mapping(
            base_projection.get("execution"), "base projection execution"
        )
        base_cq_asset_id = _strict_text(
            base_execution.get("cq_registry_asset_id"),
            "base cq_registry_asset_id",
        )
        base_cq_asset = base_assets.get(("competency_questions", base_cq_asset_id))
        if not isinstance(base_cq_asset, Mapping):
            raise RefineryWorkspaceError(
                "immutable base CQ registry manifest binding is missing"
            )
        _required_sha256(base_cq_asset.get("sha256"), "base CQ registry sha256")
        # The current mutation model authorises whole package assets, not
        # individual CQ entries.  Replacing/removing a registry asset therefore
        # cannot silently authorise dropping every CQ it once contained.  Until
        # an exact CQ-item decision DTO exists, prior CQs are append-only.
        prior_cqs = self._cq_registry_bindings(base_manifest, base_projection)
        prior_cases = []
        for (category, asset_id), item in sorted(base_assets.items()):
            if category != "cases":
                continue
            digest = _required_sha256(item.get("sha256"), "base case sha256")
            if not changed(category, asset_id, digest):
                prior_cases.append((asset_id, digest))
        return tuple(prior_cqs), tuple(prior_cases)

    def _provenance_evidence_bindings(
        self,
        *,
        delta: PackageDelta,
        manifest: Mapping[str, Any],
        projection: Mapping[str, Any],
    ) -> Tuple[Tuple[str, str], ...]:
        """Verify named package provenance JSON exactly mirrors source evidence."""

        ids = _text_tuple(
            projection.get("provenance_evidence_asset_ids"),
            "provenance_evidence_asset_ids",
        )
        by_id = {
            str(item.get("asset_id")): item
            for item in manifest.get("assets", [])
            if isinstance(item, Mapping)
        }
        expected = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "kind": "semantica.source-evidence-binding",
            "source_evidence": [item.as_dict() for item in delta.source_evidence],
        }
        bindings = []
        for asset_id in ids:
            item = by_id.get(asset_id)
            if not isinstance(item, Mapping) or item.get("category") != "provenance":
                raise RefineryGateError(("named provenance-evidence asset is absent",))
            digest = _required_sha256(item.get("sha256"), "provenance evidence sha256")
            try:
                value = _json_mapping_from_bytes(
                    self._get_object(digest),
                    "provenance evidence asset",
                )
            except (RefineryInputError, RefineryWorkspaceError) as exc:
                raise RefineryGateError(
                    ("provenance-evidence asset is not strict JSON",)
                ) from exc
            _reject_unknown(value, set(expected), "provenance evidence asset")
            if set(value) != set(expected) or canonical_json(value) != canonical_json(
                expected
            ):
                raise RefineryGateError(
                    (
                        "provenance-evidence asset does not exactly bind delta source_evidence",
                    )
                )
            bindings.append((asset_id, digest))
        return tuple(sorted(bindings))

    def _execution_transition_bindings(
        self,
        state: RefineryStateDTO,
        *,
        execution_context: TransitionContextDTO,
        execution_context_object_sha256: str,
    ) -> Tuple[Tuple[str, str, str], ...]:
        lifecycle = self._verified_history(state)
        expected_states = ("candidate", "proposed", "committed")
        values = []
        for expected_state in expected_states:
            event = next(
                item for item in lifecycle if item.get("state") == expected_state
            )
            payload = _mapping(event.get("payload"), "event payload")
            values.append(
                (
                    _EVENT_CONTEXT_ACTION[expected_state],
                    _required_sha256(
                        payload.get("transition_context_sha256"),
                        "transition context_sha256",
                    ),
                    _required_sha256(
                        payload.get("transition_context_object_sha256"),
                        "transition context_object_sha256",
                    ),
                )
            )
        values.append(
            (
                "execute_candidate",
                execution_context.context_sha256,
                execution_context_object_sha256,
            )
        )
        return tuple(
            sorted(values, key=lambda item: _TRANSITION_CONTEXT_ORDER[item[0]])
        )

    def _closure_scenario_bindings(
        self, runs: Sequence[SubjectScenarioRunDTO]
    ) -> Tuple[ProvenanceScenarioBindingDTO, ...]:
        values = []
        for run in runs:
            result = self._get_json_object(run.run_result_object_sha256)
            receipt = self._get_json_object(run.receipt_object_sha256)
            output_hashes = _mapping(
                receipt.get("output_hashes"), "native receipt output_hashes"
            )
            provenance_bundle = _mapping(
                receipt.get("provenance_bundle"),
                "native receipt provenance_bundle",
            )
            values.append(
                ProvenanceScenarioBindingDTO(
                    scenario_id=run.scenario_id,
                    input_asset_hashes=tuple(
                        sorted(_loaded_assets_from_result(result).items())
                    ),
                    case_assets=run.case_assets,
                    output_hashes=tuple(
                        sorted(
                            (
                                _strict_text(key, "native output id"),
                                _strict_text(digest, "native output sha256"),
                            )
                            for key, digest in output_hashes.items()
                        )
                    ),
                    run_result_object_sha256=run.run_result_object_sha256,
                    receipt_sha256=run.receipt_sha256,
                    receipt_object_sha256=run.receipt_object_sha256,
                    native_provenance_bundle_sha256=_strict_text(
                        provenance_bundle.get("bundle_sha256"),
                        "native provenance bundle_sha256",
                    ),
                )
            )
        return tuple(sorted(values, key=lambda item: item.scenario_id))

    def _build_execution_provenance_closure(
        self,
        *,
        state: RefineryStateDTO,
        docs: Mapping[str, Mapping[str, Any]],
        delta: PackageDelta,
        manifest_sha256: str,
        projection: Mapping[str, Any],
        manifest: Mapping[str, Any],
        runs: Sequence[SubjectScenarioRunDTO],
        runtime_source: RuntimeSourceIdentityDTO,
        context: TransitionContextDTO,
        context_object_sha256: str,
    ) -> ProvenanceClosureDTO:
        envelope = SemanticTaskEnvelope.from_dict(docs["envelope"])
        binding = ProjectOntologyBinding.from_dict(docs["binding"])
        engagement = SemanticEngagementReceipt.from_dict(docs["engagement"])
        return ProvenanceClosureDTO.create(
            phase="execution",
            workspace_id=self.registry_id,
            delta_sha256=delta.delta_sha256,
            package_id=delta.package_id,
            package_version=delta.target_version,
            package_sha256=_required_sha256(
                state.package_sha256, "closure package_sha256"
            ),
            manifest_sha256=manifest_sha256,
            execution_projection_sha256=_required_sha256(
                projection.get("_projection_sha256"),
                "closure execution_projection_sha256",
            ),
            source_evidence=delta.source_evidence,
            candidate_envelope_sha256=envelope.envelope_sha256,
            candidate_binding_sha256=binding.binding_sha256,
            engagement_receipt_sha256=engagement.receipt_sha256,
            transition_contexts=self._execution_transition_bindings(
                state,
                execution_context=context,
                execution_context_object_sha256=context_object_sha256,
            ),
            runtime_source=runtime_source,
            provenance_evidence_assets=self._provenance_evidence_bindings(
                delta=delta,
                manifest=manifest,
                projection=projection,
            ),
            scenarios=self._closure_scenario_bindings(runs),
            prior_closure_sha256=None,
        )

    def _extend_provenance_closure(
        self,
        *,
        state: RefineryStateDTO,
        suite: SubjectExecutionSuiteDTO,
        gate: str,
        context: TransitionContextDTO,
        context_object_sha256: str,
        persist: bool,
    ) -> Tuple[ProvenanceClosureDTO, str]:
        if gate == "regression":
            prior = ProvenanceClosureDTO.from_dict(
                self._get_json_object(suite.provenance_closure_object_sha256)
            )
            if prior.closure_sha256 != suite.provenance_closure_sha256:
                raise RefineryWorkspaceError(
                    "suite provenance closure object identity mismatch"
                )
        elif gate == "release":
            lifecycle = self._verified_history(state)
            regression_event = next(
                item for item in lifecycle if item["state"] == "regression_passed"
            )
            regression_payload = _mapping(
                regression_event.get("payload"), "regression event payload"
            )
            regression_evidence = RefineryGateEvidenceDTO.from_dict(
                self._get_json_object(
                    _required_sha256(
                        regression_payload.get("regression_evidence_object_sha256"),
                        "regression_evidence_object_sha256",
                    )
                )
            )
            prior = ProvenanceClosureDTO.from_dict(
                self._get_json_object(
                    regression_evidence.provenance_closure_object_sha256
                )
            )
            if (
                prior.closure_sha256 != regression_evidence.provenance_closure_sha256
                or prior.phase != "regression"
            ):
                raise RefineryWorkspaceError(
                    "release prior regression closure identity mismatch"
                )
        else:
            raise RefineryInputError("gate must be regression or release")
        contexts = {
            action: (context_sha, object_sha)
            for action, context_sha, object_sha in prior.transition_contexts
        }
        if gate == "release":
            regression_payload = _mapping(
                regression_event.get("payload"), "regression event payload"
            )
            contexts["regression_passed"] = (
                _required_sha256(
                    regression_payload.get("transition_context_sha256"),
                    "regression transition_context_sha256",
                ),
                _required_sha256(
                    regression_payload.get("transition_context_object_sha256"),
                    "regression transition_context_object_sha256",
                ),
            )
        if context.action in contexts:
            raise RefineryWorkspaceError(
                "provenance closure transition action is duplicated"
            )
        contexts[context.action] = (
            context.context_sha256,
            context_object_sha256,
        )
        closure = ProvenanceClosureDTO.create(
            phase=gate,
            workspace_id=prior.workspace_id,
            delta_sha256=prior.delta_sha256,
            package_id=prior.package_id,
            package_version=prior.package_version,
            package_sha256=prior.package_sha256,
            manifest_sha256=prior.manifest_sha256,
            execution_projection_sha256=prior.execution_projection_sha256,
            source_evidence=prior.source_evidence,
            candidate_envelope_sha256=prior.candidate_envelope_sha256,
            candidate_binding_sha256=prior.candidate_binding_sha256,
            engagement_receipt_sha256=prior.engagement_receipt_sha256,
            transition_contexts=tuple(
                sorted(
                    (
                        (action, values[0], values[1])
                        for action, values in contexts.items()
                    ),
                    key=lambda item: _TRANSITION_CONTEXT_ORDER[item[0]],
                )
            ),
            runtime_source=prior.runtime_source,
            provenance_evidence_assets=prior.provenance_evidence_assets,
            scenarios=prior.scenarios,
            prior_closure_sha256=prior.closure_sha256,
        )
        object_sha = self._retain_or_verify_object(
            _json_bytes(closure.as_dict()), persist=persist
        )
        return closure, object_sha

    def _index_execution_suite(
        self, suite: SubjectExecutionSuiteDTO, object_sha256: str
    ) -> None:
        root = self.root / "execution-suites" / suite.delta_sha256
        self._assert_managed_path(root)
        root.mkdir(parents=True, exist_ok=True)
        self._assert_managed_path(root, require_exists=True, require_directory=True)
        record = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "suite_sha256": suite.suite_sha256,
            "suite_object_sha256": object_sha256,
        }
        path = root / "{}.json".format(suite.suite_sha256)
        payload = _json_bytes(record)
        if path.exists():
            if _read_bytes(path) != payload:
                raise RefineryWorkspaceError("execution suite index collision")
        else:
            _write_new(path, payload)

    def _load_execution_suite(
        self, delta_sha256: str, suite_sha256: str
    ) -> Tuple[SubjectExecutionSuiteDTO, str]:
        digest = _required_sha256(suite_sha256, "execution suite_sha256")
        path = self._assert_managed_path(
            self.root
            / "execution-suites"
            / _required_sha256(delta_sha256, "delta_sha256")
            / "{}.json".format(digest),
            require_exists=True,
        )
        index = _read_json(path)
        _reject_unknown(
            index,
            {"schema_version", "suite_sha256", "suite_object_sha256"},
            "execution suite index",
        )
        if index.get("suite_sha256") != digest:
            raise RefineryWorkspaceError("execution suite index identity mismatch")
        object_sha = _required_sha256(
            index.get("suite_object_sha256"), "suite_object_sha256"
        )
        suite = SubjectExecutionSuiteDTO.from_dict(self._get_json_object(object_sha))
        if suite.suite_sha256 != digest or suite.delta_sha256 != delta_sha256:
            raise RefineryWorkspaceError("execution suite content identity mismatch")
        self._verify_execution_suite_objects(suite)
        return suite, object_sha

    def _verify_execution_suite_objects(self, suite: SubjectExecutionSuiteDTO) -> None:
        """Revalidate the complete runner result and native receipt CAS objects."""

        violations = []
        root = self._delta_root(suite.delta_sha256)
        try:
            delta = PackageDelta.from_dict(_read_json(root / "delta.json"))
            envelope = SemanticTaskEnvelope.from_dict(
                _read_json(root / "envelope.json")
            )
            binding = ProjectOntologyBinding.from_dict(
                _read_json(root / "binding.json")
            )
            engagement = SemanticEngagementReceipt.from_dict(
                _read_json(root / "engagement.json")
            )
            execution_context = self._load_transition_context(
                suite.transition_context_sha256,
                suite.transition_context_object_sha256,
            )
            self._validate_transition_context(
                execution_context,
                delta,
                binding,
                expected_action="execute_candidate",
            )
            closure = ProvenanceClosureDTO.from_dict(
                self._get_json_object(suite.provenance_closure_object_sha256)
            )
            if closure.closure_sha256 != suite.provenance_closure_sha256:
                violations.append("suite provenance closure identity mismatch")
            event_bindings = []
            event_paths = sorted((root / "events").glob("*.json"))[:3]
            if len(event_paths) != 3:
                violations.append("suite lifecycle prefix is incomplete")
            for expected_state, path in zip(
                ("candidate", "proposed", "committed"), event_paths
            ):
                event = _read_json(path)
                _validate_refinery_event(event)
                if event.get("state") != expected_state:
                    violations.append("suite lifecycle prefix is invalid")
                    continue
                payload = _mapping(event.get("payload"), "event payload")
                event_bindings.append(
                    (
                        _EVENT_CONTEXT_ACTION[expected_state],
                        _required_sha256(
                            payload.get("transition_context_sha256"),
                            "event transition context_sha256",
                        ),
                        _required_sha256(
                            payload.get("transition_context_object_sha256"),
                            "event transition context_object_sha256",
                        ),
                    )
                )
            event_bindings.append(
                (
                    "execute_candidate",
                    suite.transition_context_sha256,
                    suite.transition_context_object_sha256,
                )
            )
            manifest = self._get_json_object(suite.subject_manifest_sha256)
            _, projection = self._build_execution_manifest(manifest)
            expected_closure = {
                "phase": "execution",
                "workspace_id": self.registry_id,
                "delta_sha256": delta.delta_sha256,
                "package_id": delta.package_id,
                "package_version": delta.target_version,
                "package_sha256": suite.subject_package_sha256,
                "manifest_sha256": suite.subject_manifest_sha256,
                "execution_projection_sha256": suite.execution_projection_sha256,
                "source_evidence": delta.source_evidence,
                "candidate_envelope_sha256": envelope.envelope_sha256,
                "candidate_binding_sha256": binding.binding_sha256,
                "engagement_receipt_sha256": engagement.receipt_sha256,
                "transition_contexts": tuple(
                    sorted(
                        event_bindings,
                        key=lambda item: _TRANSITION_CONTEXT_ORDER[item[0]],
                    )
                ),
                "runtime_source": suite.runtime_source,
                "provenance_evidence_assets": self._provenance_evidence_bindings(
                    delta=delta,
                    manifest=manifest,
                    projection=projection,
                ),
                "prior_closure_sha256": None,
            }
            for field, expected in expected_closure.items():
                if getattr(closure, field) != expected:
                    violations.append(
                        "suite provenance closure {} mismatch".format(field)
                    )
        except (RefineryInputError, RefineryGateError, RefineryWorkspaceError) as exc:
            violations.append(
                "suite provenance closure cannot be replayed: {}".format(exc)
            )
            closure = None
        observed_capabilities = set()
        for run in suite.runs:
            try:
                result = self._get_json_object(run.run_result_object_sha256)
                receipt = self._get_json_object(run.receipt_object_sha256)
            except (RefineryInputError, RefineryWorkspaceError) as exc:
                violations.append(
                    "{} execution object cannot be loaded: {}".format(
                        run.scenario_id, exc
                    )
                )
                continue
            observed_capabilities.update(_capabilities_from_result(result))
            violations.extend(
                _subject_run_object_violations(
                    suite=suite,
                    run=run,
                    result=result,
                    receipt_object=receipt,
                )
            )
        if closure is not None and closure.scenarios != (
            self._closure_scenario_bindings(suite.runs)
        ):
            violations.append("suite provenance closure scenario artifacts mismatch")
        if tuple(sorted(observed_capabilities)) != suite.observed_capabilities:
            violations.append(
                "suite observed capabilities differ from native runner reports"
            )
        if violations:
            raise RefineryWorkspaceError(
                "execution suite object verification failed: {}".format(
                    "; ".join(violations)
                )
            )

    def _derive_gate_evidence(
        self,
        state: RefineryStateDTO,
        docs: Mapping[str, Mapping[str, Any]],
        *,
        gate: str,
        suite_sha256: str,
        recorded_at: str,
        context: TransitionContextDTO,
        context_object_sha256: str,
        persist: bool,
    ) -> RefineryGateEvidenceDTO:
        if gate not in {"regression", "release"}:
            raise RefineryInputError("gate must be regression or release")
        if state.state not in {
            "committed",
            "regression_passed",
            "release_complete",
            "promoted",
        }:
            raise RefineryStateError("gate evidence requires a committed package")
        delta = PackageDelta.from_dict(docs["delta"])
        binding = ProjectOntologyBinding.from_dict(docs["binding"])
        expected_action = (
            "derive_regression_gate" if gate == "regression" else "derive_release_gate"
        )
        self._validate_transition_context(
            context,
            delta,
            binding,
            expected_action=expected_action,
        )
        if _sha256_bytes(_json_bytes(context.as_dict())) != (
            _required_sha256(
                context_object_sha256,
                "gate transition context_object_sha256",
            )
        ):
            raise RefineryWorkspaceError(
                "gate transition context object digest mismatch"
            )
        if not persist:
            loaded_context = self._load_transition_context(
                context.context_sha256, context_object_sha256
            )
            if loaded_context != context:
                raise RefineryWorkspaceError("gate transition context replay differs")
        suite, suite_object_sha = self._load_execution_suite(
            delta.delta_sha256, suite_sha256
        )
        execution_context = self._load_transition_context(
            suite.transition_context_sha256,
            suite.transition_context_object_sha256,
        )
        self._validate_transition_context(
            execution_context,
            delta,
            binding,
            expected_action="execute_candidate",
        )
        manifest = self._committed_manifest(state)
        execution_manifest, projection = self._build_execution_manifest(manifest)
        lifecycle = self._verified_history(state)
        committed = next(item for item in lifecycle if item["state"] == "committed")
        expected_manifest_sha = _required_sha256(
            committed["payload"].get("manifest_sha256"), "manifest_sha256"
        )
        expected_assets = tuple(
            sorted(
                (
                    _strict_text(item.get("asset_id"), "execution asset_id"),
                    _required_sha256(item.get("sha256"), "execution asset sha256"),
                )
                for item in execution_manifest["assets"]
            )
        )
        gate_suite = _mapping(projection.get("gate_suite"), "gate_suite")
        expected_scenarios = tuple(
            sorted(
                {
                    scenario_id
                    for check in gate_suite.values()
                    for scenario_id in _text_tuple(
                        _mapping(check, "gate suite check").get("scenario_ids"),
                        "gate scenario_ids",
                    )
                }
            )
        )
        expected_cqs = tuple(
            sorted(
                {
                    cq_id
                    for check in gate_suite.values()
                    for cq_id in _text_tuple(
                        _mapping(check, "gate suite check").get("cq_ids"),
                        "gate cq_ids",
                        allow_empty=True,
                    )
                }
            )
        )
        expected_prior_cqs, expected_prior_cases = self._derive_prior_requirements(
            state=state,
            delta=delta,
            manifest=manifest,
            projection=projection,
        )
        expected_cq_registry_bindings = self._cq_registry_bindings(manifest, projection)
        identity_violations = []
        expected_identity = {
            "workspace_id": self.registry_id,
            "delta_sha256": delta.delta_sha256,
            "subject_package_id": delta.package_id,
            "subject_package_version": delta.target_version,
            "subject_package_sha256": state.package_sha256,
            "subject_manifest_sha256": expected_manifest_sha,
            "execution_projection_sha256": projection.get("_projection_sha256"),
            "execution_asset_hashes": expected_assets,
            "required_scenario_ids": expected_scenarios,
            "required_cq_ids": expected_cqs,
            "required_case_kinds": CASE_KINDS,
            "required_prior_cq_bindings": expected_prior_cqs,
            "required_prior_case_bindings": expected_prior_cases,
            "cq_registry_bindings": expected_cq_registry_bindings,
        }
        for field, expected in expected_identity.items():
            if getattr(suite, field) != expected:
                identity_violations.append(
                    "execution suite {} differs from committed subject".format(field)
                )

        try:
            from semantica.ontology.runtime import SemanticRuntime

            executor_identity = (
                SemanticRuntime(profile="ontology-runtime", backend="rdflib")
                .load_package(execution_manifest)
                .identity
            )
        except Exception as exc:
            raise RefineryGateError(
                ("execution projection cannot be registered by SemanticRuntime",)
            ) from exc
        for run in suite.runs:
            if (
                run.executor_package_id != executor_identity.package_id
                or run.executor_package_version != executor_identity.version
                or run.executor_package_digest != executor_identity.digest
            ):
                identity_violations.append(
                    "run {} executor identity differs from the current projection".format(
                        run.scenario_id
                    )
                )
            result = self._get_json_object(run.run_result_object_sha256)
            loaded_assets = _loaded_assets_from_result(result)
            manifest_cases = {
                str(item.get("asset_id")): (
                    str(item.get("case_kind")),
                    str(item.get("sha256")),
                )
                for item in manifest.get("assets", [])
                if isinstance(item, Mapping) and item.get("category") == "cases"
            }
            actual_cases = tuple(
                sorted(
                    (
                        manifest_cases[asset_id][0],
                        asset_id,
                        manifest_cases[asset_id][1],
                    )
                    for asset_id, digest in loaded_assets.items()
                    if asset_id in manifest_cases
                    and digest == manifest_cases[asset_id][1]
                )
            )
            if run.case_assets != actual_cases:
                identity_violations.append(
                    "run {} actual case I/O differs from suite".format(run.scenario_id)
                )
        if identity_violations:
            raise RefineryGateError(identity_violations)

        regression_results = {
            check_id: self._evaluate_regression_check(
                check_id,
                _mapping(gate_suite.get(check_id), "gate suite check"),
                suite,
                manifest,
            )
            for check_id in REGRESSION_REQUIRED_CHECK_IDS
        }
        if gate == "regression":
            evaluations = tuple(
                (check_id, *regression_results[check_id])
                for check_id in REGRESSION_REQUIRED_CHECK_IDS
            )
        else:
            evaluations = self._evaluate_release_checks(
                delta=delta,
                suite=suite,
                manifest=manifest,
                projection=projection,
                regression_results=regression_results,
            )
        provenance_closure, provenance_closure_object_sha256 = (
            self._extend_provenance_closure(
                state=state,
                suite=suite,
                gate=gate,
                context=context,
                context_object_sha256=context_object_sha256,
                persist=persist,
            )
        )
        checks = []
        for check_id, passed, message, details in evaluations:
            output = {
                "schema_version": REFINERY_SCHEMA_VERSION,
                "gate": gate,
                "check_id": check_id,
                "delta_sha256": delta.delta_sha256,
                "package_sha256": state.package_sha256,
                "execution_suite_sha256": suite.suite_sha256,
                "transition_context_sha256": context.context_sha256,
                "provenance_closure_sha256": (provenance_closure.closure_sha256),
                "passed": passed,
                "message": message,
                "details": details,
            }
            output_sha = self._retain_or_verify_object(
                _json_bytes(output), persist=persist
            )
            checks.append(
                GateCheckDTO(
                    check_id=check_id,
                    passed=passed,
                    message=message,
                    output_sha256=output_sha,
                )
            )
        return RefineryGateEvidenceDTO.create(
            gate=gate,
            package_sha256=_required_sha256(
                state.package_sha256, "committed package_sha256"
            ),
            execution_suite_sha256=suite.suite_sha256,
            execution_suite_object_sha256=suite_object_sha,
            transition_context_sha256=context.context_sha256,
            transition_context_object_sha256=context_object_sha256,
            provenance_closure_sha256=provenance_closure.closure_sha256,
            provenance_closure_object_sha256=(provenance_closure_object_sha256),
            runtime_source=suite.runtime_source,
            required_capabilities=delta.required_capabilities,
            observed_capabilities=suite.observed_capabilities,
            checks=checks,
            recorded_at=recorded_at,
        )

    def _evaluate_regression_check(
        self,
        check_id: str,
        contract: Mapping[str, Any],
        suite: SubjectExecutionSuiteDTO,
        manifest: Mapping[str, Any],
    ) -> Tuple[bool, str, Mapping[str, Any]]:
        scenario_ids = _text_tuple(contract.get("scenario_ids"), "gate scenario_ids")
        cq_ids = _text_tuple(contract.get("cq_ids"), "gate cq_ids", allow_empty=True)
        case_ids = _text_tuple(
            contract.get("case_asset_ids"),
            "gate case_asset_ids",
            allow_empty=True,
        )
        prior_cq_bindings = (
            suite.required_prior_cq_bindings if check_id == "cq.prior" else ()
        )
        prior_case_bindings = (
            suite.required_prior_case_bindings
            if check_id == "case.prior_release"
            else ()
        )
        if check_id == "cq.prior":
            cq_ids = tuple(item[0] for item in prior_cq_bindings)
        if check_id == "case.prior_release":
            case_ids = tuple(item[0] for item in prior_case_bindings)
        run_by_id = {item.scenario_id: item for item in suite.runs}
        bound_runs = [run_by_id.get(item) for item in scenario_ids]
        missing_scenarios = [
            item for item, run in zip(scenario_ids, bound_runs) if run is None
        ]
        green_scenarios = [
            run.scenario_id
            for run in bound_runs
            if run is not None
            and run.status == "passed"
            and run.release_status == "complete"
        ]
        coverage_runs = (
            list(suite.runs)
            if check_id in {"cq.prior", "case.prior_release"}
            else bound_runs
        )
        actual_cqs = sorted(
            {cq_id for run in coverage_runs if run is not None for cq_id in run.cq_ids}
        )
        cq_registry = dict(suite.cq_registry_bindings)
        actual_cq_bindings = {
            (cq_id, cq_registry[cq_id]) for cq_id in actual_cqs if cq_id in cq_registry
        }
        actual_cases = sorted(
            {
                (case_kind, asset_id, digest)
                for run in coverage_runs
                if run is not None
                for case_kind, asset_id, digest in run.case_assets
            }
        )
        manifest_cases = {
            str(item.get("asset_id")): (
                str(item.get("case_kind")),
                str(item.get("sha256")),
            )
            for item in manifest.get("assets", [])
            if isinstance(item, Mapping) and item.get("category") == "cases"
        }
        missing_cqs = sorted(set(cq_ids) - set(actual_cqs))
        missing_cq_bindings = sorted(set(prior_cq_bindings) - actual_cq_bindings)
        missing_cases = []
        for asset_id in case_ids:
            expected = manifest_cases.get(asset_id)
            required_digest = dict(prior_case_bindings).get(asset_id)
            if required_digest is not None:
                present = any(
                    current_id == asset_id and digest == required_digest
                    for _, current_id, digest in actual_cases
                )
            else:
                present = bool(
                    expected is not None
                    and (expected[0], asset_id, expected[1]) in actual_cases
                )
            if not present:
                missing_cases.append(asset_id)
        passed = bool(
            not missing_scenarios
            and set(green_scenarios) == set(scenario_ids)
            and not missing_cqs
            and not missing_cq_bindings
            and not missing_cases
        )
        message = (
            "contract-bound scenarios, CQs, and case inputs passed"
            if passed
            else "contract-bound execution output is incomplete or blocked"
        )
        details = {
            "scenario_ids": list(scenario_ids),
            "green_scenario_ids": sorted(green_scenarios),
            "missing_scenario_ids": sorted(missing_scenarios),
            "required_cq_ids": list(cq_ids),
            "actual_cq_ids": actual_cqs,
            "missing_cq_ids": missing_cqs,
            "required_prior_cq_bindings": dict(prior_cq_bindings),
            "actual_cq_bindings": dict(sorted(actual_cq_bindings)),
            "missing_prior_cq_bindings": [
                {"cq_id": cq_id, "sha256": digest}
                for cq_id, digest in missing_cq_bindings
            ],
            "required_case_asset_ids": list(case_ids),
            "required_prior_case_bindings": dict(prior_case_bindings),
            "actual_case_assets": [
                {"case_kind": kind, "asset_id": asset_id, "sha256": digest}
                for kind, asset_id, digest in actual_cases
            ],
            "missing_case_asset_ids": missing_cases,
        }
        return passed, message, details

    def _evaluate_release_checks(
        self,
        *,
        delta: PackageDelta,
        suite: SubjectExecutionSuiteDTO,
        manifest: Mapping[str, Any],
        projection: Mapping[str, Any],
        regression_results: Mapping[str, Tuple[bool, str, Mapping[str, Any]]],
    ) -> Tuple[Tuple[str, bool, str, Mapping[str, Any]], ...]:
        coverage_violations = _package_coverage_violations(manifest)
        package_coverage = not coverage_violations
        missing_capabilities = sorted(
            set(delta.required_capabilities) - set(suite.observed_capabilities)
        )
        receipt_binding = bool(
            suite.status == "complete"
            and suite.runs
            and all(
                item.status == "passed" and item.release_status == "complete"
                for item in suite.runs
            )
        )
        provenance_evidence = self._provenance_evidence_bindings(
            delta=delta,
            manifest=manifest,
            projection=projection,
        )
        execution_closure = ProvenanceClosureDTO.from_dict(
            self._get_json_object(suite.provenance_closure_object_sha256)
        )
        provenance_binding = bool(
            receipt_binding
            and provenance_evidence
            and execution_closure.closure_sha256 == suite.provenance_closure_sha256
            and execution_closure.scenarios
            == self._closure_scenario_bindings(suite.runs)
            and execution_closure.provenance_evidence_assets == provenance_evidence
        )
        rights_ids = _text_tuple(
            projection.get("rights_evidence_asset_ids"),
            "rights_evidence_asset_ids",
        )
        manifest_by_id = {
            str(item.get("asset_id")): item
            for item in manifest.get("assets", [])
            if isinstance(item, Mapping)
        }
        rights_bindings = []
        for asset_id in rights_ids:
            item = manifest_by_id.get(asset_id)
            if item is not None:
                rights_bindings.append(
                    {
                        "asset_id": asset_id,
                        "sha256": item.get("sha256"),
                        "category": item.get("category"),
                    }
                )
        rights_bound = bool(
            rights_ids
            and len(rights_bindings) == len(rights_ids)
            and all(item["category"] == "provenance" for item in rights_bindings)
        )
        io_binding = all(value[0] for value in regression_results.values())
        return (
            (
                "package.coverage",
                package_coverage,
                (
                    "all eight asset families and four case kinds are content-bound"
                    if package_coverage
                    else "package asset-family or case-kind coverage is incomplete"
                ),
                {"violations": coverage_violations},
            ),
            (
                "capability.coverage",
                not missing_capabilities,
                (
                    "the Semantica execution profile covers required capabilities"
                    if not missing_capabilities
                    else "required runtime capabilities are missing"
                ),
                {
                    "required": list(delta.required_capabilities),
                    "observed": list(suite.observed_capabilities),
                    "missing": missing_capabilities,
                },
            ),
            (
                "receipt.binding",
                receipt_binding,
                (
                    "full runner results and native receipts bind every scenario"
                    if receipt_binding
                    else "one or more runner results or native receipts are blocked"
                ),
                {
                    "suite_status": suite.status,
                    "run_result_object_sha256": [
                        item.run_result_object_sha256 for item in suite.runs
                    ],
                    "receipt_object_sha256": [
                        item.receipt_object_sha256 for item in suite.runs
                    ],
                },
            ),
            (
                "provenance.binding",
                provenance_binding,
                (
                    "package provenance assets and native provenance bundles are bound"
                    if provenance_binding
                    else "package or native execution provenance is incomplete"
                ),
                {
                    "provenance_evidence_assets": [
                        {
                            "asset_id": asset_id,
                            "sha256": digest,
                        }
                        for asset_id, digest in provenance_evidence
                    ],
                    "receipt_sha256": [item.receipt_sha256 for item in suite.runs],
                    "execution_provenance_closure_sha256": (
                        suite.provenance_closure_sha256
                    ),
                    "legal_ruling": "not_inferred",
                },
            ),
            (
                "source.rights",
                rights_bound,
                (
                    "named rights-evidence bytes are content-bound; no legal ruling is inferred"
                    if rights_bound
                    else "named rights-evidence bytes are absent or unbound"
                ),
                {
                    "rights_evidence": rights_bindings,
                    "legal_ruling": "not_inferred",
                },
            ),
            (
                "io.binding",
                io_binding,
                (
                    "actual CQ and case I/O is bound to the fixed regression suite"
                    if io_binding
                    else "actual CQ or case I/O does not satisfy the fixed suite"
                ),
                {
                    "regression_checks": {
                        check_id: value[0]
                        for check_id, value in regression_results.items()
                    }
                },
            ),
        )

    # ---- validation -----------------------------------------------------

    def _validate_transition_context(
        self,
        context: TransitionContextDTO,
        delta: PackageDelta,
        binding: ProjectOntologyBinding,
        *,
        expected_action: str,
    ) -> None:
        """Fail closed unless this invocation is bound to current retained truth."""

        if not isinstance(context, TransitionContextDTO):
            raise RefineryInputError(
                "a strict TransitionContextDTO is required for every refinery write"
            )
        violations = []
        if context.action != expected_action:
            violations.append(
                "transition context action must be exactly {}".format(expected_action)
            )
        if context.delta_sha256 != delta.delta_sha256:
            violations.append("transition context does not bind exact delta")
        if context.binding.binding_sha256 != binding.binding_sha256 or (
            canonical_json(context.binding.as_dict())
            != canonical_json(binding.as_dict())
        ):
            violations.append(
                "transition context binding differs from retained current binding"
            )
        if context.binding.workspace_id != self.registry_id:
            violations.append("transition context workspace differs from registry")
        if context.binding.package_id != delta.package_id:
            violations.append("transition context package differs from delta")
        if context.binding.semantic_api_contract != REFINERY_CONTRACT:
            violations.append("transition context semantic contract is unsupported")
        if (
            context.envelope.project_id != binding.project_id
            or context.envelope.domain != binding.domain
        ):
            violations.append(
                "transition task project/domain differs from retained binding"
            )
        if context.envelope.requested_actions != (expected_action,):
            violations.append("transition task must request exactly the invoked action")
        if not set(delta.required_capabilities).issubset(
            set(context.envelope.required_capabilities)
        ):
            violations.append(
                "transition task omits delta-required runtime capabilities"
            )
        for source in context.envelope.evidence:
            if not _uri_within_root(source.uri, binding.evidence_root):
                violations.append(
                    "transition task evidence is outside retained evidence_root"
                )
        if not context.verify_integrity():
            violations.append("transition context integrity failed")
        if violations:
            raise RefineryGateError(violations)

    def _retain_transition_context(self, context: TransitionContextDTO) -> str:
        return self._put_object(_json_bytes(context.as_dict()))

    def _load_transition_context(
        self,
        context_sha256: str,
        context_object_sha256: str,
    ) -> TransitionContextDTO:
        context = TransitionContextDTO.from_dict(
            self._get_json_object(
                _required_sha256(
                    context_object_sha256,
                    "transition context_object_sha256",
                )
            )
        )
        if context.context_sha256 != _required_sha256(
            context_sha256, "transition context_sha256"
        ):
            raise RefineryWorkspaceError("transition context object identity mismatch")
        return context

    def _validate_engagement_binding(
        self,
        envelope: SemanticTaskEnvelope,
        binding: ProjectOntologyBinding,
        receipt: SemanticEngagementReceipt,
    ) -> None:
        violations = []
        if binding.workspace_id != self.registry_id:
            violations.append("binding workspace_id differs from registry_id")
        if (
            envelope.project_id != binding.project_id
            or envelope.domain != binding.domain
        ):
            violations.append("task project/domain differs from binding")
        if receipt.envelope_sha256 != envelope.envelope_sha256:
            violations.append("engagement receipt does not bind task envelope")
        if receipt.binding_sha256 != binding.binding_sha256:
            violations.append(
                "engagement receipt does not bind project ontology binding"
            )
        if receipt.required_capabilities != envelope.required_capabilities:
            violations.append(
                "engagement receipt capabilities differ from task envelope"
            )
        for source in envelope.evidence:
            if not _uri_within_root(source.uri, binding.evidence_root):
                violations.append(
                    "task evidence URI is outside binding evidence_root: {}".format(
                        source.source_id
                    )
                )
        if not receipt.verify_integrity():
            violations.append("engagement receipt integrity failed")
        if violations:
            raise RefineryGateError(violations)

    def _candidate_violations(
        self,
        delta: PackageDelta,
        envelope: SemanticTaskEnvelope,
        binding: ProjectOntologyBinding,
        engagement: SemanticEngagementReceipt,
    ) -> List[str]:
        violations = []
        if delta.package_id in _reserved_semantica_package_ids():
            violations.append(
                "industry package_id collides with a built-in Semantica package"
            )
        if delta.package_id != binding.package_id:
            violations.append("delta package_id differs from binding")
        if delta.base_version != binding.baseline_version:
            violations.append("delta base_version differs from binding")
        if delta.base_package_sha256 != binding.baseline_package_sha256:
            violations.append("delta base digest differs from binding")
        if delta.created_by not in binding.fact_authorities:
            violations.append("delta creator is not a bound fact authority")
        if "candidate" not in binding.allowed_actions:
            violations.append("binding does not allow candidate creation")
        if not self._task_requests(envelope, "candidate"):
            violations.append("task envelope does not request candidate creation")
        if engagement.status != "complete":
            violations.append(
                "candidate requires a complete semantic engagement receipt"
            )
        if engagement.learning.status != "candidate":
            violations.append("engagement learning result is not candidate")
        elif engagement.learning.delta_sha256 != delta.delta_sha256:
            violations.append("learning result does not bind candidate delta")
        if not set(delta.required_capabilities).issubset(
            set(envelope.required_capabilities)
        ):
            violations.append("delta capabilities are not requested by task envelope")
        task_evidence = {canonical_json(item.as_dict()) for item in envelope.evidence}
        for source in delta.source_evidence:
            if canonical_json(source.as_dict()) not in task_evidence:
                violations.append(
                    "delta source is not exact hashed task evidence: {}".format(
                        source.source_id
                    )
                )
            if not _uri_within_root(source.uri, binding.evidence_root):
                violations.append(
                    "delta evidence URI is outside binding evidence_root: {}".format(
                        source.source_id
                    )
                )
        return violations

    def _authorization_violations(
        self,
        authorization: RefineryAuthorizationDTO,
        delta: PackageDelta,
        binding: ProjectOntologyBinding,
        *,
        action: str,
    ) -> List[str]:
        violations = []
        if authorization.action != action:
            violations.append("authorization action is not {}".format(action))
        if authorization.package_id != delta.package_id:
            violations.append("authorization package_id differs from delta")
        if authorization.delta_sha256 != delta.delta_sha256:
            violations.append("authorization does not bind exact delta")
        if authorization.actor_id not in binding.decision_authorities:
            violations.append("authorization actor is not a decision authority")
        if authorization.authority not in binding.decision_authorities:
            violations.append("authorization authority is not bound")
        if authorization.promotion_target != binding.promotion_target:
            violations.append("authorization promotion_target differs from binding")
        if not _uri_within_root(authorization.source.uri, binding.evidence_root):
            violations.append(
                "authorization evidence URI is outside binding evidence_root"
            )
        required_action = "committed" if action == "commit" else "promoted"
        if required_action not in binding.allowed_actions:
            violations.append("binding does not allow {}".format(required_action))
        if action == "commit":
            expected = {
                (
                    item.category,
                    item.asset_id,
                    item.operation,
                    item.replaces_sha256,
                )
                for item in delta.assets
                if item.operation in {"replace", "remove"}
            }
            actual = {item.key for item in authorization.decisions}
            for key in sorted(expected - actual):
                violations.append(
                    "authorization is missing approve decision for {}:{} {} {}".format(
                        *key
                    )
                )
            for key in sorted(actual - expected):
                violations.append(
                    "authorization has unmatched asset decision for {}:{} {} {}".format(
                        *key
                    )
                )
        elif authorization.decisions:
            violations.append(
                "promotion authorization must not contain asset mutation decisions"
            )
        return violations

    def _baseline_violations(
        self, delta: PackageDelta, binding: ProjectOntologyBinding
    ) -> List[str]:
        violations = []
        registry = self._read_registry()
        current = registry["packages"].get(delta.package_id)
        if delta.base_version == "0":
            if current is not None:
                violations.append(
                    "initial package baseline is stale; package now exists"
                )
        else:
            if not isinstance(current, Mapping):
                violations.append("bound baseline package is absent")
            else:
                if current.get("current_version") != delta.base_version:
                    violations.append("bound baseline version is not registry current")
                if current.get("current_package_sha256") != delta.base_package_sha256:
                    violations.append("bound baseline digest is not registry current")
        if binding.baseline_version != delta.base_version or (
            binding.baseline_package_sha256 != delta.base_package_sha256
        ):
            violations.append("project binding and delta baseline differ")
        return violations

    def _gate_evidence_violations(
        self,
        evidence: RefineryGateEvidenceDTO,
        state: RefineryStateDTO,
        docs: Mapping[str, Mapping[str, Any]],
        delta: PackageDelta,
        engagement: SemanticEngagementReceipt,
        *,
        expected_gate: str,
    ) -> List[str]:
        violations = []
        if evidence.gate != expected_gate:
            violations.append("wrong gate evidence type")
        if not evidence.complete or evidence.status != "complete":
            violations.append("{} evidence is blocked".format(expected_gate))
        if evidence.package_sha256 != state.package_sha256:
            violations.append("gate evidence does not bind committed package")
        if not set(delta.required_capabilities).issubset(
            set(evidence.required_capabilities)
        ):
            violations.append("gate evidence omits delta-required capabilities")
        if not evidence.runtime_source.complete:
            violations.append("gate runtime source identity is incomplete")
        if evidence.runtime_source != engagement.runtime_source:
            violations.append(
                "gate runtime source identity differs from engagement receipt"
            )
        try:
            derive_context = self._load_transition_context(
                evidence.transition_context_sha256,
                evidence.transition_context_object_sha256,
            )
            derived = self._derive_gate_evidence(
                state,
                docs,
                gate=expected_gate,
                suite_sha256=evidence.execution_suite_sha256,
                recorded_at=evidence.recorded_at,
                context=derive_context,
                context_object_sha256=(evidence.transition_context_object_sha256),
                persist=False,
            )
        except OntologyRefineryError as exc:
            violations.append(
                "{} evidence cannot be replayed: {}".format(expected_gate, exc)
            )
        else:
            if canonical_json(derived.as_dict()) != canonical_json(evidence.as_dict()):
                violations.append(
                    "{} evidence is not the exact Semantica-derived gate output".format(
                        expected_gate
                    )
                )
        return violations

    def _require_allowed(self, binding: ProjectOntologyBinding, state: str) -> None:
        if state not in binding.allowed_actions:
            raise RefineryGateError(
                ("binding does not allow lifecycle action {}".format(state),)
            )

    @staticmethod
    def _task_requests(envelope: SemanticTaskEnvelope, state: str) -> bool:
        return envelope.requested_actions == (state,)

    @staticmethod
    def _require_transition(state: RefineryStateDTO, target: str) -> None:
        if _NEXT_STATE.get(state.state) != target:
            raise RefineryStateError(
                "invalid refinery transition: {} -> {}".format(state.state, target)
            )

    # ---- materialisation ------------------------------------------------

    def _materialize_package(
        self, delta: PackageDelta
    ) -> Tuple[Mapping[str, Any], str]:
        assets: Dict[Tuple[str, str], Dict[str, Any]] = {}
        if delta.base_version != "0":
            descriptor = self.resolve_package(
                delta.package_id, version=delta.base_version
            )
            if descriptor.package_sha256 != delta.base_package_sha256:
                raise RefineryGateError(("base package digest mismatch",))
            base = self._get_json_object(descriptor.manifest_sha256)
            self._verify_manifest_assets(base)
            for item in base.get("assets", []):
                if not isinstance(item, Mapping):
                    raise RefineryWorkspaceError("base package asset is invalid")
                key = (item.get("category"), item.get("asset_id"))
                assets[key] = dict(item)

        for change in delta.assets:
            key = (change.category, change.asset_id)
            existing = assets.get(key)
            if change.operation == "add":
                if existing is not None:
                    raise RefineryGateError(
                        (
                            "add would overwrite existing asset {}".format(
                                change.asset_id
                            ),
                        )
                    )
                assets[key] = _asset_manifest_record(change)
            elif change.operation == "replace":
                if existing is None:
                    raise RefineryGateError(
                        ("replace target is absent: {}".format(change.asset_id),)
                    )
                if existing.get("sha256") != change.replaces_sha256:
                    raise RefineryGateError(
                        ("replace target digest mismatch: {}".format(change.asset_id),)
                    )
                assets[key] = _asset_manifest_record(change)
            else:
                if existing is None:
                    raise RefineryGateError(
                        ("remove target is absent: {}".format(change.asset_id),)
                    )
                if existing.get("sha256") != change.replaces_sha256:
                    raise RefineryGateError(
                        ("remove target digest mismatch: {}".format(change.asset_id),)
                    )
                del assets[key]

        manifest_content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "contract": REFINERY_CONTRACT,
            "package_id": delta.package_id,
            "version": delta.target_version,
            "base_version": delta.base_version,
            "base_package_sha256": delta.base_package_sha256,
            "delta_sha256": delta.delta_sha256,
            "required_capabilities": list(delta.required_capabilities),
            "source_evidence": [item.as_dict() for item in delta.source_evidence],
            "book_impact": delta.book_impact,
            "assets": [assets[key] for key in sorted(assets)],
        }
        asset_ids = [item["asset_id"] for item in manifest_content["assets"]]
        if len(asset_ids) != len(set(asset_ids)):
            raise RefineryGateError(
                ("materialized package asset_id values are not globally unique",)
            )
        package_sha256 = sha256_text(canonical_json(manifest_content))
        return (
            {**manifest_content, "package_sha256": package_sha256},
            package_sha256,
        )

    def _committed_manifest(self, state: RefineryStateDTO) -> Mapping[str, Any]:
        history = self._verified_history(state)
        commit_event = next(item for item in history if item["state"] == "committed")
        manifest_sha256 = _required_sha256(
            commit_event["payload"].get("manifest_sha256"), "manifest_sha256"
        )
        manifest = self._get_json_object(manifest_sha256)
        content = dict(manifest)
        declared = content.pop("package_sha256", None)
        actual = sha256_text(canonical_json(content))
        if declared != actual or declared != state.package_sha256:
            raise RefineryWorkspaceError("committed package manifest hash mismatch")
        self._verify_manifest_assets(manifest)
        return manifest

    def _verify_manifest_assets(self, manifest: Mapping[str, Any]) -> None:
        assets = manifest.get("assets")
        if not isinstance(assets, list):
            raise RefineryWorkspaceError("package manifest assets are missing")
        identities = []
        for item in assets:
            if not isinstance(item, Mapping):
                raise RefineryWorkspaceError("package manifest asset is invalid")
            category = item.get("category")
            if category not in PACKAGE_ASSET_CATEGORIES:
                raise RefineryWorkspaceError(
                    "package manifest asset category is invalid"
                )
            asset_id = _validate_opaque_id(item.get("asset_id"), "asset_id")
            identities.append(asset_id)
            _required_text(item.get("media_type"), "asset media_type")
            digest = _required_sha256(item.get("sha256"), "asset sha256")
            role = item.get("role")
            if role is not None:
                _required_text(role, "asset role")
            case_kind = item.get("case_kind")
            if category == "cases":
                if case_kind not in CASE_KINDS:
                    raise RefineryWorkspaceError(
                        "case manifest asset has invalid case_kind"
                    )
            elif case_kind is not None:
                raise RefineryWorkspaceError(
                    "non-case manifest asset declares case_kind"
                )
            # Loading by digest checks both existence and exact byte identity.
            self._get_object(digest)
        if len(identities) != len(set(identities)):
            raise RefineryWorkspaceError(
                "package manifest asset_id values must be globally unique"
            )

    # ---- registry publication ------------------------------------------

    def _publish_registry_record(self, record: Mapping[str, Any]) -> None:
        self._assert_workspace_layout()
        # Parse and hash the complete record before creating any package path.
        descriptor = _descriptor_from_record(record)
        package_id = descriptor.package_id
        version = descriptor.version
        record_bytes = _json_bytes(record)
        record_content = dict(record)
        declared_record_sha = record_content.pop("promotion_record_sha256", None)
        if declared_record_sha != sha256_text(canonical_json(record_content)):
            raise RefineryInputError("promotion record digest does not match content")
        registry = dict(self._read_registry())
        packages = {key: dict(value) for key, value in registry["packages"].items()}
        package = dict(
            packages.get(
                package_id,
                {
                    "storage_key": _storage_key(package_id),
                    "current_version": None,
                    "current_package_sha256": None,
                    "versions": {},
                },
            )
        )
        versions = {key: dict(value) for key, value in package["versions"].items()}
        if version in versions:
            raise IndustryPackageVersionExistsError(
                "immutable package version already exists: {}@{}".format(
                    package_id, version
                )
            )
        package_key = _storage_key(package_id)
        version_key = _storage_key(version)
        record_sha = _required_sha256(
            record.get("promotion_record_sha256"), "promotion_record_sha256"
        )
        version_dir = self.root / "packages" / package_key / "versions" / version_key
        self._assert_managed_path(version_dir)
        version_parent = version_dir.parent
        version_parent.mkdir(parents=True, exist_ok=True)
        if version_dir.exists() or version_dir.is_symlink():
            self._assert_managed_path(
                version_dir, require_exists=True, require_directory=True
            )
            existing_record = version_dir / "record.json"
            if _read_bytes(existing_record) != record_bytes:
                raise IndustryPackageVersionExistsError(
                    "immutable package storage conflicts: {}@{}".format(
                        package_id, version
                    )
                )
        else:
            stage = version_parent / ".staging-{}".format(uuid.uuid4().hex)
            self._assert_managed_path(stage)
            stage.mkdir()
            try:
                _write_new(stage / "record.json", record_bytes)
                _fsync_directory(stage)
                os.rename(str(stage), str(version_dir))
                _fsync_directory(version_parent)
            except Exception:
                if stage.exists():
                    shutil.rmtree(str(stage))
                raise
        versions[version] = {
            "version_key": version_key,
            "record_sha256": record_sha,
        }
        package.update(
            {
                "storage_key": package_key,
                "current_version": version,
                "current_package_sha256": record["package_sha256"],
                "versions": versions,
            }
        )
        packages[package_id] = package
        packages_sha256 = sha256_text(canonical_json(packages))
        sequence = int(registry["sequence"]) + 1
        event_content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "sequence": sequence,
            "previous_event_sha256": registry.get("last_event_sha256"),
            "operation": "promote",
            "package_id": package_id,
            "version": version,
            "package_sha256": record["package_sha256"],
            "promotion_record_sha256": record_sha,
            "packages_sha256": packages_sha256,
            "recorded_at": record["promoted_at"],
        }
        event_sha = sha256_text(canonical_json(event_content))
        event = {**event_content, "event_sha256": event_sha}
        _validate_registry_event_document(event)
        _write_new(
            self.root
            / "registry-events"
            / "{:06d}-{}.json".format(sequence, event_sha),
            _json_bytes(event),
        )
        updated = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "registry_id": self.registry_id,
            "sequence": sequence,
            "last_event_sha256": event_sha,
            "packages_sha256": packages_sha256,
            "packages": packages,
        }
        _atomic_replace(self.root / "registry.json", _json_bytes(updated))

    def _read_package_record(
        self, package_id: str, version: str, expected_sha256: str
    ) -> Mapping[str, Any]:
        # Both directory components are hashes, never user identifiers.
        path = (
            self.root
            / "packages"
            / _storage_key(package_id)
            / "versions"
            / _storage_key(version)
            / "record.json"
        )
        self._assert_managed_path(path, require_exists=True)
        value = _read_json(path)
        content = dict(value)
        declared = content.pop("promotion_record_sha256", None)
        actual = sha256_text(canonical_json(content))
        if declared != actual or expected_sha256 != actual:
            raise RefineryWorkspaceError("promotion record hash mismatch")
        if value.get("package_id") != package_id or value.get("version") != version:
            raise RefineryWorkspaceError("promotion record identity mismatch")
        return value

    # ---- event/object integrity ----------------------------------------

    def _write_initial_event(
        self,
        stage: Path,
        *,
        delta: PackageDelta,
        when: str,
        payload: Mapping[str, Any],
    ) -> RefineryStateDTO:
        self._assert_managed_path(stage, require_exists=True, require_directory=True)
        _validate_timestamp(when, "candidate recorded_at")
        content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "sequence": 1,
            "state": "candidate",
            "delta_sha256": delta.delta_sha256,
            "package_id": delta.package_id,
            "previous_event_sha256": None,
            "package_sha256": None,
            "recorded_at": when,
            "payload": dict(payload),
        }
        event_sha = sha256_text(canonical_json(content))
        event = {**content, "event_sha256": event_sha}
        _validate_refinery_event(event)
        _write_new(
            stage / "events" / "000001-{}.json".format(event_sha),
            _json_bytes(event),
        )
        pointer = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "delta_sha256": delta.delta_sha256,
            "package_id": delta.package_id,
            "state": "candidate",
            "sequence": 1,
            "event_sha256": event_sha,
            "previous_event_sha256": None,
            "package_sha256": None,
            "recorded_at": when,
        }
        state = _state_from_pointer(pointer)
        _write_new(stage / "current.json", _json_bytes(pointer))
        return state

    def _append_event(
        self,
        current: RefineryStateDTO,
        state: str,
        *,
        payload: Mapping[str, Any],
        package_sha256: Optional[str] = None,
        recorded_at: Optional[str] = None,
    ) -> RefineryStateDTO:
        self._assert_workspace_layout()
        expected = _NEXT_STATE.get(current.state)
        if expected != state:
            raise RefineryStateError(
                "invalid refinery transition: {} -> {}".format(current.state, state)
            )
        when = recorded_at or utc_now()
        _validate_timestamp(when, "refinery event recorded_at")
        sequence = current.sequence + 1
        package_digest = package_sha256 or current.package_sha256
        content = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "sequence": sequence,
            "state": state,
            "delta_sha256": current.delta_sha256,
            "package_id": current.package_id,
            "previous_event_sha256": current.event_sha256,
            "package_sha256": package_digest,
            "recorded_at": when,
            "payload": dict(payload),
        }
        event_sha = sha256_text(canonical_json(content))
        event = {**content, "event_sha256": event_sha}
        _validate_refinery_event(event)
        event_path = (
            self._delta_root(current.delta_sha256)
            / "events"
            / "{:06d}-{}.json".format(sequence, event_sha)
        )
        self._assert_managed_path(event_path)
        pointer = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "delta_sha256": current.delta_sha256,
            "package_id": current.package_id,
            "state": state,
            "sequence": sequence,
            "event_sha256": event_sha,
            "previous_event_sha256": current.event_sha256,
            "package_sha256": package_digest,
            "recorded_at": when,
        }
        result = _state_from_pointer(pointer)
        delta_root = self._delta_root(current.delta_sha256)
        pending_path = self._assert_managed_path(delta_root / "pending-event.json")
        transaction = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "prior_event_sha256": current.event_sha256,
            "event": event,
            "pointer": pointer,
        }
        # Validate/serialize the complete transaction before the first write.
        transaction_bytes = _json_bytes(transaction)
        _write_new(pending_path, transaction_bytes)
        _fsync_directory(delta_root)
        _write_new(event_path, _json_bytes(event))
        _fsync_directory(event_path.parent)
        _atomic_replace(delta_root / "current.json", _json_bytes(pointer))
        pending_path.unlink()
        _fsync_directory(delta_root)
        return result

    def _load_refinement(
        self, delta_sha256: str
    ) -> Tuple[RefineryStateDTO, Dict[str, Mapping[str, Any]]]:
        digest = _required_sha256(delta_sha256, "delta_sha256")
        root = self._delta_root(digest)
        self._assert_workspace_layout()
        try:
            self._assert_managed_path(root, require_exists=True, require_directory=True)
        except RefineryWorkspaceError as exc:
            raise RefineryWorkspaceError(
                "unknown or unsafe refinery candidate"
            ) from exc
        self._recover_refinement_if_needed(root)
        pointer = _read_json(root / "current.json")
        state = _state_from_pointer(pointer)
        if state.delta_sha256 != digest:
            raise RefineryWorkspaceError("refinery pointer delta mismatch")
        event_path = (
            root
            / "events"
            / "{:06d}-{}.json".format(state.sequence, state.event_sha256)
        )
        event = _read_json(event_path)
        content = dict(event)
        declared = content.pop("event_sha256", None)
        if declared != sha256_text(canonical_json(content)):
            raise RefineryWorkspaceError("current refinery event hash mismatch")
        for field in (
            "delta_sha256",
            "package_id",
            "state",
            "sequence",
            "event_sha256",
            "previous_event_sha256",
            "package_sha256",
            "recorded_at",
        ):
            if pointer.get(field) != event.get(field):
                raise RefineryWorkspaceError(
                    "current refinery pointer differs from event: {}".format(field)
                )
        # Every public load, including status and every transition, verifies
        # the complete append-only chain rather than trusting only the tip.
        verified_history = self._verified_history(state)
        docs = {
            "delta": _read_json(root / "delta.json"),
            "envelope": _read_json(root / "envelope.json"),
            "binding": _read_json(root / "binding.json"),
            "engagement": _read_json(root / "engagement.json"),
        }
        if PackageDelta.from_dict(docs["delta"]).delta_sha256 != digest:
            raise RefineryWorkspaceError("saved package delta digest mismatch")
        envelope = SemanticTaskEnvelope.from_dict(docs["envelope"])
        binding = ProjectOntologyBinding.from_dict(docs["binding"])
        engagement = SemanticEngagementReceipt.from_dict(docs["engagement"])
        candidate_payload = verified_history[0].get("payload", {})
        expected_candidate_bindings = {
            "envelope_sha256": envelope.envelope_sha256,
            "binding_sha256": binding.binding_sha256,
            "engagement_receipt_sha256": engagement.receipt_sha256,
            "engagement_status": engagement.status,
        }
        for field, expected in expected_candidate_bindings.items():
            if candidate_payload.get(field) != expected:
                raise RefineryWorkspaceError(
                    "candidate event does not bind saved {}".format(field)
                )
        try:
            candidate_context = self._load_transition_context(
                _required_sha256(
                    candidate_payload.get("transition_context_sha256"),
                    "candidate transition_context_sha256",
                ),
                _required_sha256(
                    candidate_payload.get("transition_context_object_sha256"),
                    "candidate transition_context_object_sha256",
                ),
            )
            self._validate_transition_context(
                candidate_context,
                PackageDelta.from_dict(docs["delta"]),
                binding,
                expected_action="candidate",
            )
            if candidate_context.envelope.envelope_sha256 != (envelope.envelope_sha256):
                raise RefineryGateError(
                    ("candidate context task differs from retained envelope",)
                )
        except (RefineryInputError, RefineryGateError, RefineryWorkspaceError) as exc:
            raise RefineryWorkspaceError(
                "candidate transition context is inconsistent"
            ) from exc
        try:
            self._validate_engagement_binding(envelope, binding, engagement)
        except RefineryGateError as exc:
            raise RefineryWorkspaceError(
                "saved engagement binding is inconsistent: {}".format(exc)
            ) from exc
        return state, docs

    def _recover_refinement_if_needed(self, root: Path) -> None:
        """Complete or discard one verified write-ahead event transaction."""

        pending_path = self._assert_managed_path(root / "pending-event.json")
        if not pending_path.exists():
            return
        transaction = _read_json(pending_path)
        try:
            _reject_unknown(
                transaction,
                {"schema_version", "prior_event_sha256", "event", "pointer"},
                "refinement pending transaction",
            )
            _require_schema(
                _strict_text(
                    transaction.get("schema_version"),
                    "pending schema_version",
                )
            )
            prior = _required_sha256(
                transaction.get("prior_event_sha256"),
                "pending prior_event_sha256",
            )
            event = _mapping(transaction.get("event"), "pending event")
            pointer = _mapping(transaction.get("pointer"), "pending pointer")
            _validate_refinery_event(event)
            next_state = _state_from_pointer(pointer)
        except RefineryInputError as exc:
            raise RefineryWorkspaceError(
                "invalid refinement pending transaction"
            ) from exc
        if next_state.event_sha256 != event.get("event_sha256"):
            raise RefineryWorkspaceError(
                "pending transaction pointer does not bind event"
            )
        current_path = self._assert_managed_path(
            root / "current.json", require_exists=True
        )
        current = _state_from_pointer(_read_json(current_path))
        event_path = self._assert_managed_path(
            root
            / "events"
            / "{:06d}-{}.json".format(next_state.sequence, next_state.event_sha256)
        )
        if event_path.exists():
            if _read_bytes(event_path) != _json_bytes(event):
                raise RefineryWorkspaceError(
                    "pending refinery event differs from immutable event"
                )
            if current.event_sha256 == prior:
                _atomic_replace(current_path, _json_bytes(pointer))
            elif current.event_sha256 != next_state.event_sha256:
                raise RefineryWorkspaceError(
                    "pending refinery transaction conflicts with current pointer"
                )
        elif current.event_sha256 != prior:
            raise RefineryWorkspaceError("pending refinery transaction lost its event")
        pending_path.unlink()
        _fsync_directory(root)

    def _delta_root(self, delta_sha256: str) -> Path:
        digest = _required_sha256(delta_sha256, "delta_sha256")
        return self.root / "refinements" / digest

    def _put_object(self, payload: bytes, *, expected: Optional[str] = None) -> str:
        self._assert_workspace_layout()
        digest = _sha256_bytes(payload)
        if expected is not None and digest != expected:
            raise RefineryInputError("object bytes do not match expected digest")
        path = self._object_path(digest)
        self._assert_managed_path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._assert_managed_path(
            path.parent, require_exists=True, require_directory=True
        )
        if path.exists():
            if path.is_symlink() or _sha256_bytes(_read_bytes(path)) != digest:
                raise RefineryWorkspaceError("content-addressed object is corrupt")
        else:
            _write_new(path, payload)
        return digest

    def _retain_or_verify_object(self, payload: bytes, *, persist: bool) -> str:
        """Write once during derivation, or require the exact CAS byte on replay."""

        digest = _sha256_bytes(payload)
        if persist:
            return self._put_object(payload, expected=digest)
        if self._get_object(digest) != payload:
            raise RefineryWorkspaceError("replayed CAS object bytes differ")
        return digest

    def _get_object(self, digest: str) -> bytes:
        path = self._object_path(digest)
        self._assert_managed_path(path, require_exists=True)
        payload = _read_bytes(path)
        if _sha256_bytes(payload) != digest:
            raise RefineryWorkspaceError("content-addressed object hash mismatch")
        return payload

    def _get_json_object(self, digest: str) -> Mapping[str, Any]:
        return _json_mapping_from_bytes(
            self._get_object(digest), "object {}".format(digest)
        )

    def _object_path(self, digest: str) -> Path:
        value = _required_sha256(digest, "object digest")
        return self.root / "objects" / "sha256" / value[:2] / value

    def _read_workspace(self) -> Mapping[str, Any]:
        self._assert_workspace_layout()
        value = _read_json(self.root / "workspace.json")
        if value.get("schema_version") != REFINERY_SCHEMA_VERSION:
            raise RefineryWorkspaceError("unsupported refinery workspace schema")
        if value.get("contract") != REFINERY_CONTRACT:
            raise RefineryWorkspaceError("unsupported refinery workspace contract")
        if value.get("empty_package_sha256") != EMPTY_PACKAGE_SHA256:
            raise RefineryWorkspaceError("empty package identity mismatch")
        _validate_opaque_id(value.get("registry_id"), "registry_id")
        return value

    def _read_registry(self) -> Mapping[str, Any]:
        value = self._read_registry_document()
        self._verify_registry_events(value)
        return value

    def _read_registry_document(self) -> Mapping[str, Any]:
        self._assert_workspace_layout()
        value = _read_json(self.root / "registry.json")
        if value.get("schema_version") != REFINERY_SCHEMA_VERSION:
            raise RefineryWorkspaceError("unsupported registry schema")
        if value.get("registry_id") != self.registry_id:
            raise RefineryWorkspaceError("registry identity mismatch")
        if not isinstance(value.get("packages"), Mapping):
            raise RefineryWorkspaceError("registry packages must be a mapping")
        expected_packages_sha256 = sha256_text(canonical_json(value["packages"]))
        if value.get("packages_sha256") != expected_packages_sha256:
            raise RefineryWorkspaceError("registry package index hash mismatch")
        sequence = value.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise RefineryWorkspaceError("registry sequence is invalid")
        last = value.get("last_event_sha256")
        if sequence == 0:
            if last is not None:
                raise RefineryWorkspaceError("empty registry has a last event")
        else:
            _required_sha256(last, "registry last_event_sha256")
        return value

    def _registry_event_paths(self) -> Tuple[Path, ...]:
        event_dir = self._assert_managed_path(
            self.root / "registry-events",
            require_exists=True,
            require_directory=True,
        )
        return tuple(sorted(event_dir.glob("*.json")))

    def _recover_registry_if_needed(self) -> None:
        """Recover one durable promotion event whose pointer write was torn."""

        registry = self._read_registry_document()
        sequence = int(registry["sequence"])
        paths = self._registry_event_paths()
        if len(paths) == sequence:
            self._verify_registry_events(registry, paths=paths)
            return
        if len(paths) != sequence + 1:
            raise RefineryWorkspaceError(
                "registry has an unrecoverable event-count divergence"
            )
        prefix_packages, prefix_last = self._reconstruct_registry_events(
            paths[:sequence]
        )
        if canonical_json(prefix_packages) != canonical_json(registry["packages"]):
            raise RefineryWorkspaceError(
                "registry pointer differs from its immutable event prefix"
            )
        if prefix_last != registry.get("last_event_sha256"):
            raise RefineryWorkspaceError(
                "registry pointer does not bind its immutable event prefix"
            )
        recovered_packages, recovered_last = self._reconstruct_registry_events(paths)
        updated = {
            "schema_version": REFINERY_SCHEMA_VERSION,
            "registry_id": self.registry_id,
            "sequence": sequence + 1,
            "last_event_sha256": recovered_last,
            "packages_sha256": sha256_text(canonical_json(recovered_packages)),
            "packages": recovered_packages,
        }
        self._verify_registry_events(updated, paths=paths)
        _atomic_replace(self.root / "registry.json", _json_bytes(updated))

    def _verify_registry_events(
        self,
        registry: Mapping[str, Any],
        *,
        paths: Optional[Sequence[Path]] = None,
    ) -> None:
        sequence = registry.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise RefineryWorkspaceError("registry sequence is invalid")
        paths = tuple(paths) if paths is not None else self._registry_event_paths()
        if len(paths) != sequence:
            raise RefineryWorkspaceError("registry event count mismatch")
        reconstructed, previous = self._reconstruct_registry_events(paths)
        if registry.get("last_event_sha256") != previous:
            raise RefineryWorkspaceError("registry pointer does not bind last event")
        if canonical_json(registry.get("packages")) != canonical_json(reconstructed):
            raise RefineryWorkspaceError(
                "registry package index differs from immutable promotion history"
            )

    def _reconstruct_registry_events(
        self, paths: Sequence[Path]
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        previous = None
        reconstructed: Dict[str, Any] = {}
        for index, path in enumerate(paths, start=1):
            self._assert_managed_path(path, require_exists=True)
            event = _read_json(path)
            try:
                _validate_registry_event_document(event)
            except RefineryInputError as exc:
                raise RefineryWorkspaceError(
                    "registry event schema is invalid"
                ) from exc
            if (
                event.get("sequence") != index
                or event.get("previous_event_sha256") != previous
            ):
                raise RefineryWorkspaceError("registry event chain is broken")
            content = dict(event)
            declared = content.pop("event_sha256", None)
            actual = sha256_text(canonical_json(content))
            if declared != actual or path.stem != "{:06d}-{}".format(index, actual):
                raise RefineryWorkspaceError("registry event integrity failed")
            if event.get("operation") != "promote":
                raise RefineryWorkspaceError("registry event operation is invalid")
            package_id = _validate_package_id(event.get("package_id"))
            version = _required_text(event.get("version"), "registry event version")
            record_sha256 = _required_sha256(
                event.get("promotion_record_sha256"),
                "registry event promotion_record_sha256",
            )
            record = self._read_package_record(package_id, version, record_sha256)
            if record.get("package_sha256") != event.get("package_sha256"):
                raise RefineryWorkspaceError(
                    "registry event package digest differs from promotion record"
                )
            package = dict(
                reconstructed.get(
                    package_id,
                    {
                        "storage_key": _storage_key(package_id),
                        "current_version": None,
                        "current_package_sha256": None,
                        "versions": {},
                    },
                )
            )
            versions = {key: dict(value) for key, value in package["versions"].items()}
            if version in versions:
                raise RefineryWorkspaceError(
                    "registry events repeat an immutable package version"
                )
            versions[version] = {
                "version_key": _storage_key(version),
                "record_sha256": record_sha256,
            }
            package.update(
                {
                    "storage_key": _storage_key(package_id),
                    "current_version": version,
                    "current_package_sha256": record["package_sha256"],
                    "versions": versions,
                }
            )
            reconstructed[package_id] = package
            if event.get("packages_sha256") != sha256_text(
                canonical_json(reconstructed)
            ):
                raise RefineryWorkspaceError(
                    "registry event package-index digest is invalid"
                )
            previous = actual
        return reconstructed, previous


# ---------------------------------------------------------------------------
# Stable workflow facade


def build_refinery_acceptance_delta(
    *,
    package_id: str,
    source_evidence: SourceEvidenceDTO,
    created_by: str,
    created_at: str,
    target_version: str = "1.0.0",
) -> PackageDelta:
    """Build Semantica's public native refinery acceptance package.

    This is deliberately a runnable package, not a policy example.  External
    integrations can exercise the complete control plane without copying RDF,
    SPARQL, rule, case, projection, or provenance payloads into another skill.
    """

    _validate_package_id(package_id)
    _required_text(created_by, "acceptance created_by")
    _validate_timestamp(created_at, "acceptance created_at")

    def asset(
        category: str,
        asset_id: str,
        content: str,
        *,
        media_type: str,
        case_kind: Optional[str] = None,
    ) -> PackageAssetDeltaDTO:
        return PackageAssetDeltaDTO.add_text(
            category=category,
            asset_id=asset_id,
            content=content,
            media_type=media_type,
            case_kind=case_kind,
        )

    ontology = asset(
        "ontology",
        "ontology-core",
        (
            "@prefix owl: <http://www.w3.org/2002/07/owl#> .\n"
            "<urn:semantica:refinery:acceptance> a owl:Ontology .\n"
        ),
        media_type="text/turtle",
    )
    cq_registry_value = {
        "schema_version": REFINERY_SCHEMA_VERSION,
        "package_id": package_id,
        "competency_questions": [
            {
                "id": "cq-current",
                "question": "Can the current acceptance value be retrieved?",
                "scenario_ids": ["scenario-current"],
            },
            {
                "id": "cq-prior",
                "question": "Does prior acceptance behavior still execute?",
                "scenario_ids": ["scenario-prior"],
            },
        ],
    }
    cq_registry = asset(
        "competency_questions",
        "cq-registry",
        canonical_json(cq_registry_value),
        media_type="application/json",
    )
    shapes = asset(
        "shapes",
        "acceptance-shapes",
        (
            "@prefix sh: <http://www.w3.org/ns/shacl#> .\n"
            "@prefix ex: <urn:semantica:acceptance:> .\n"
            "ex:NamedShape a sh:NodeShape ; sh:targetSubjectsOf ex:name .\n"
        ),
        media_type="text/turtle",
    )
    query = asset(
        "queries",
        "cq-primary",
        (
            "SELECT ?name WHERE { ?s <urn:semantica:acceptance:name> ?name . } "
            "ORDER BY ?name\n"
        ),
        media_type="application/sparql-query",
    )
    rule = asset(
        "rules",
        "acceptance-rules",
        "IF observed(?x) THEN reusable(?x)\n",
        media_type="text/plain",
    )
    case_values = {
        "positive": "positive",
        "negative": None,
        "ambiguity": "ambiguity",
        "prior_release": "prior",
    }
    cases = []
    for kind, value in case_values.items():
        content = (
            '<urn:semantica:case:{}> <urn:semantica:acceptance:name> "{}" .\n'.format(
                kind, value
            )
            if value is not None
            else "# deliberately empty negative graph\n"
        )
        cases.append(
            asset(
                "cases",
                "case-{}".format(kind),
                content,
                media_type="text/turtle",
                case_kind=kind,
            )
        )
    scenario_rows = {
        "scenario-current": ("case-positive", "positive", 1),
        "scenario-negative": ("case-negative", None, 0),
        "scenario-ambiguity": ("case-ambiguity", "ambiguity", 1),
        "scenario-prior": ("case-prior_release", "prior", 1),
    }
    scenarios = []
    for scenario_id, (case_id, value, count) in scenario_rows.items():
        oracle: Dict[str, Any] = {"row_count": count}
        if value is not None:
            oracle["bindings"] = {"name": [value]}
        scenarios.append(
            {
                "id": scenario_id,
                "status": "native",
                "execution": {
                    "provider": "SemanticRuntime",
                    "operation": "select_exact_multiset",
                    "query_asset_id": "cq-primary",
                },
                "inputs": [case_id, "case-negative"],
                "oracle": {
                    "id": "oracle-{}".format(scenario_id),
                    "status": "ready",
                    "positive": oracle,
                    "single_fault_negative": {"row_count": 0},
                },
            }
        )
    scenario_registry = asset(
        "provenance",
        "scenario-registry",
        canonical_json(
            {
                "schema_version": REFINERY_SCHEMA_VERSION,
                "package_id": package_id,
                "runner_contract": SEMANTIC_PACKAGE_RUNNER_CONTRACT,
                "scenarios": scenarios,
            }
        ),
        media_type="application/json",
    )
    rights_evidence = asset(
        "provenance",
        "rights-evidence",
        canonical_json(
            {
                "schema_version": REFINERY_SCHEMA_VERSION,
                "source_id": source_evidence.source_id,
                "source_sha256": source_evidence.sha256,
                "statement": "Bytes retained as rights evidence; no legal conclusion.",
            }
        ),
        media_type="application/json",
    )
    source_binding = asset(
        "provenance",
        "source-evidence-binding",
        canonical_json(
            {
                "schema_version": REFINERY_SCHEMA_VERSION,
                "kind": "semantica.source-evidence-binding",
                "source_evidence": [source_evidence.as_dict()],
            }
        ),
        media_type="application/json",
    )
    semantic_assets = (
        ontology,
        cq_registry,
        shapes,
        query,
        rule,
        *cases,
        scenario_registry,
        rights_evidence,
        source_binding,
    )
    metadata: Dict[str, Mapping[str, Any]] = {}
    for item in semantic_assets:
        if item.category == "ontology":
            role, format_name, kind, load = "ontology", "turtle", "rdf", True
        elif item.category == "competency_questions":
            role, format_name, kind, load = (
                "competency_questions",
                "json",
                "structured",
                False,
            )
        elif item.category == "shapes":
            role, format_name, kind, load = "shapes", "turtle", "rdf", False
        elif item.category == "queries":
            role, format_name, kind, load = "sparql", "sparql", "text", False
        elif item.category == "rules":
            role, format_name, kind, load = (
                "engineering_rules",
                "text",
                "text",
                False,
            )
        elif item.category == "cases":
            role, format_name, kind, load = "case", "turtle", "rdf", False
        elif item.asset_id == "scenario-registry":
            role, format_name, kind, load = (
                "scenario_registry",
                "json",
                "structured",
                False,
            )
        else:
            role, format_name, kind, load = (
                "provenance",
                "json",
                "structured",
                False,
            )
        metadata[item.asset_id] = {
            "role": role,
            "format": format_name,
            "kind": kind,
            "load_into_dataset": load,
        }
    metadata["package-contract"] = {
        "role": "contract",
        "format": "json",
        "kind": "structured",
        "load_into_dataset": False,
    }
    projection = {
        "schema_version": REFINERY_SCHEMA_VERSION,
        "runner_contract": SEMANTIC_PACKAGE_RUNNER_CONTRACT,
        "namespace": "urn:semantica:refinery:acceptance:",
        "release_status": "complete",
        "execution": {
            "scenario_registry_asset_id": "scenario-registry",
            "cq_registry_asset_id": "cq-registry",
        },
        "assets": metadata,
        "gate_suite": {
            "cq.prior": {
                "scenario_ids": ["scenario-prior"],
                "cq_ids": ["cq-prior"],
                "case_asset_ids": [],
            },
            "cq.current": {
                "scenario_ids": ["scenario-current"],
                "cq_ids": ["cq-current"],
                "case_asset_ids": [],
            },
            "case.positive": {
                "scenario_ids": ["scenario-current"],
                "cq_ids": [],
                "case_asset_ids": ["case-positive"],
            },
            "case.negative": {
                "scenario_ids": ["scenario-negative"],
                "cq_ids": [],
                "case_asset_ids": ["case-negative"],
            },
            "case.ambiguity": {
                "scenario_ids": ["scenario-ambiguity"],
                "cq_ids": [],
                "case_asset_ids": ["case-ambiguity"],
            },
            "case.prior_release": {
                "scenario_ids": ["scenario-prior"],
                "cq_ids": [],
                "case_asset_ids": ["case-prior_release"],
            },
        },
        "rights_evidence_asset_ids": ["rights-evidence"],
        "provenance_evidence_asset_ids": ["source-evidence-binding"],
    }
    contract = asset(
        "contract",
        "package-contract",
        canonical_json(projection),
        media_type="application/json",
    )
    return PackageDelta(
        package_id=package_id,
        base_version="0",
        base_package_sha256=EMPTY_PACKAGE_SHA256,
        target_version=target_version,
        rationale="Semantica native refinery acceptance package.",
        created_by=created_by,
        created_at=created_at,
        required_capabilities=("semantic.package.load",),
        source_evidence=(source_evidence,),
        book_impact="none",
        ontology=(ontology,),
        competency_questions=(cq_registry,),
        shapes=(shapes,),
        queries=(query,),
        rules=(rule,),
        cases=tuple(cases),
        contract=(contract,),
        provenance=(scenario_registry, rights_evidence, source_binding),
    )


def refinery_capabilities() -> Mapping[str, Any]:
    """Describe the exact native contract for safe feature detection."""

    return {
        "contract": REFINERY_CONTRACT,
        "schema_version": REFINERY_SCHEMA_VERSION,
        "states": list(REFINERY_STATES),
        "asset_categories": list(PACKAGE_ASSET_CATEGORIES),
        "delta_categories": list(PACKAGE_DELTA_CATEGORIES),
        "book_impacts": list(BOOK_IMPACTS),
        "case_kinds": list(CASE_KINDS),
        "regression_check_ids": list(REGRESSION_REQUIRED_CHECK_IDS),
        "release_check_ids": list(RELEASE_REQUIRED_CHECK_IDS),
        "transition_context_actions": list(TRANSITION_CONTEXT_ACTIONS),
        "transition_context_required_operations": [
            "propose_candidate",
            "commit_candidate",
            "execute_candidate",
            "derive_gate_evidence",
            "verify_candidate",
            "promote_candidate",
        ],
        "runner_contract": SEMANTIC_PACKAGE_RUNNER_CONTRACT,
        "operations": [
            "build_refinery_acceptance_delta",
            "open_engagement",
            "propose_candidate",
            "commit_candidate",
            "execute_candidate",
            "derive_gate_evidence",
            "verify_candidate",
            "promote_candidate",
            "history",
            "resolve_package",
            "execution_manifest",
            "run_registry",
        ],
        "publication_owned_externally": True,
    }


def open_engagement(
    workspace: Union[str, os.PathLike, IndustryOntologyRegistry],
    *,
    envelope: SemanticTaskEnvelope,
    binding: ProjectOntologyBinding,
    receipt: SemanticEngagementReceipt,
) -> SemanticEngagementReceipt:
    """Record and return the exact five-part semantic engagement receipt."""

    registry = _coerce_registry(workspace)
    registry.record_engagement(envelope, binding, receipt)
    return receipt


def propose_candidate(
    workspace: Union[str, os.PathLike, IndustryOntologyRegistry],
    *,
    delta: PackageDelta,
    envelope: SemanticTaskEnvelope,
    binding: ProjectOntologyBinding,
    engagement: SemanticEngagementReceipt,
    context: TransitionContextDTO,
    recorded_at: Optional[str] = None,
) -> RefineryStateDTO:
    """Retain/resume ``candidate`` and advance it to ``proposed``."""

    registry = _coerce_registry(workspace)
    candidate_root = registry._delta_root(delta.delta_sha256)
    if not candidate_root.exists():
        registry.register_candidate(
            delta,
            envelope,
            binding,
            engagement,
            recorded_at=recorded_at,
        )
        state = registry.status(delta.delta_sha256)
    else:
        state, docs = registry._load_refinement(delta.delta_sha256)
        expected = {
            "delta": delta.as_dict(),
            "envelope": envelope.as_dict(),
            "binding": binding.as_dict(),
            "engagement": engagement.as_dict(),
        }
        for name, expected_value in expected.items():
            if canonical_json(docs[name]) != canonical_json(expected_value):
                raise RefineryGateError(
                    ("retry {} differs from retained candidate".format(name),)
                )
    if state.state == "candidate":
        return registry.propose(
            delta.delta_sha256,
            context=context,
            recorded_at=recorded_at,
        )
    if state.state == "proposed":
        retained_binding = ProjectOntologyBinding.from_dict(docs["binding"])
        registry._validate_transition_context(
            context,
            delta,
            retained_binding,
            expected_action="proposed",
        )
        proposed_event = next(
            item
            for item in registry.history(delta.delta_sha256)
            if item["state"] == "proposed"
        )
        proposed_payload = proposed_event["payload"]
        recorded_context = registry._load_transition_context(
            _required_sha256(
                proposed_payload.get("transition_context_sha256"),
                "proposal transition_context_sha256",
            ),
            _required_sha256(
                proposed_payload.get("transition_context_object_sha256"),
                "proposal transition_context_object_sha256",
            ),
        )
        if canonical_json(context.as_dict()) != canonical_json(
            recorded_context.as_dict()
        ):
            raise RefineryGateError(
                ("retry transition context differs from proposed event",)
            )
        return state
    raise RefineryStateError(
        "propose_candidate cannot resume from {}".format(state.state)
    )


def commit_candidate(
    workspace: Union[str, os.PathLike, IndustryOntologyRegistry],
    *,
    delta_sha256: str,
    authorization: RefineryAuthorizationDTO,
    context: TransitionContextDTO,
    recorded_at: Optional[str] = None,
) -> RefineryStateDTO:
    """Advance one exact proposed candidate to an authorised commit."""

    return _coerce_registry(workspace).commit(
        delta_sha256,
        authorization,
        context=context,
        recorded_at=recorded_at,
    )


def execute_candidate(
    workspace: Union[str, os.PathLike, IndustryOntologyRegistry],
    *,
    delta_sha256: str,
    context: TransitionContextDTO,
    runtime_source: RuntimeSourceIdentityDTO,
    created_at: Optional[str] = None,
) -> SubjectExecutionSuiteDTO:
    """Execute the contract-locked subject scenarios inside Semantica."""

    return _coerce_registry(workspace).execute_candidate(
        delta_sha256,
        context=context,
        runtime_source=runtime_source,
        created_at=created_at,
    )


def derive_gate_evidence(
    workspace: Union[str, os.PathLike, IndustryOntologyRegistry],
    *,
    delta_sha256: str,
    context: TransitionContextDTO,
    gate: str,
    execution_suite_sha256: str,
    recorded_at: Optional[str] = None,
) -> RefineryGateEvidenceDTO:
    """Derive fixed gate checks from one verified execution suite."""

    return _coerce_registry(workspace).gate_evidence(
        delta_sha256,
        context=context,
        gate=gate,
        execution_suite_sha256=execution_suite_sha256,
        recorded_at=recorded_at,
    )


def verify_candidate(
    workspace: Union[str, os.PathLike, IndustryOntologyRegistry],
    *,
    delta_sha256: str,
    execution_suite_sha256: str,
    regression_evidence: Optional[RefineryGateEvidenceDTO],
    regression_context: Optional[TransitionContextDTO],
    release_derivation_context: TransitionContextDTO,
    release_context: TransitionContextDTO,
    recorded_at: Optional[str] = None,
) -> CandidateVerificationDTO:
    """Advance regression, then derive and record release in strict order."""

    registry = _coerce_registry(workspace)
    state = registry.status(delta_sha256)
    if state.state == "committed":
        if not isinstance(
            regression_evidence, RefineryGateEvidenceDTO
        ) or not isinstance(regression_context, TransitionContextDTO):
            raise RefineryInputError(
                "committed verification requires regression evidence and context"
            )
        if regression_evidence.execution_suite_sha256 != execution_suite_sha256:
            raise RefineryGateError(
                ("regression evidence differs from requested execution suite",)
            )
        state = registry.record_regression(
            delta_sha256,
            regression_evidence,
            context=regression_context,
            recorded_at=recorded_at,
        )
    elif state.state in {"regression_passed", "release_complete"}:
        if regression_evidence is not None or regression_context is not None:
            raise RefineryInputError(
                "verification restart must load recorded regression evidence"
            )
        lifecycle = registry.history(delta_sha256)
        regression_event = next(
            item for item in lifecycle if item["state"] == "regression_passed"
        )
        regression_payload = regression_event["payload"]
        regression_evidence = RefineryGateEvidenceDTO.from_dict(
            registry._get_json_object(
                _required_sha256(
                    regression_payload.get("regression_evidence_object_sha256"),
                    "regression_evidence_object_sha256",
                )
            )
        )
        if (
            regression_payload.get("regression_evidence_sha256")
            != regression_evidence.evidence_sha256
            or regression_evidence.execution_suite_sha256 != execution_suite_sha256
        ):
            raise RefineryGateError(
                ("retry regression evidence differs from recorded gate",)
            )
        replay_state, replay_docs = registry._load_refinement(delta_sha256)
        replay_delta = PackageDelta.from_dict(replay_docs["delta"])
        replay_engagement = SemanticEngagementReceipt.from_dict(
            replay_docs["engagement"]
        )
        replay_violations = registry._gate_evidence_violations(
            regression_evidence,
            replay_state,
            replay_docs,
            replay_delta,
            replay_engagement,
            expected_gate="regression",
        )
        if replay_violations:
            raise RefineryGateError(
                tuple(
                    "recorded regression replay: {}".format(item)
                    for item in replay_violations
                )
            )
    else:
        raise RefineryStateError(
            "verify_candidate requires committed, regression_passed, or "
            "release_complete state"
        )

    if state.state == "release_complete":
        release_event = next(
            item
            for item in registry.history(delta_sha256)
            if item["state"] == "release_complete"
        )
        release_payload = release_event["payload"]
        release_evidence = RefineryGateEvidenceDTO.from_dict(
            registry._get_json_object(
                _required_sha256(
                    release_payload.get("release_evidence_object_sha256"),
                    "release_evidence_object_sha256",
                )
            )
        )
        if release_evidence.execution_suite_sha256 != execution_suite_sha256:
            raise RefineryGateError(("retry release execution suite differs",))
        replay_state, replay_docs = registry._load_refinement(delta_sha256)
        replay_delta = PackageDelta.from_dict(replay_docs["delta"])
        replay_binding = ProjectOntologyBinding.from_dict(replay_docs["binding"])
        replay_engagement = SemanticEngagementReceipt.from_dict(
            replay_docs["engagement"]
        )
        registry._validate_transition_context(
            release_derivation_context,
            replay_delta,
            replay_binding,
            expected_action="derive_release_gate",
        )
        registry._validate_transition_context(
            release_context,
            replay_delta,
            replay_binding,
            expected_action="release_complete",
        )
        recorded_derivation_context = registry._load_transition_context(
            release_evidence.transition_context_sha256,
            release_evidence.transition_context_object_sha256,
        )
        recorded_release_context = registry._load_transition_context(
            _required_sha256(
                release_payload.get("transition_context_sha256"),
                "release transition_context_sha256",
            ),
            _required_sha256(
                release_payload.get("transition_context_object_sha256"),
                "release transition_context_object_sha256",
            ),
        )
        retry_contexts = (
            (release_derivation_context, recorded_derivation_context),
            (release_context, recorded_release_context),
        )
        if any(
            canonical_json(supplied.as_dict()) != canonical_json(recorded.as_dict())
            for supplied, recorded in retry_contexts
        ):
            raise RefineryGateError(
                ("retry release transition context differs from recorded gate",)
            )
        replay_violations = registry._gate_evidence_violations(
            release_evidence,
            replay_state,
            replay_docs,
            replay_delta,
            replay_engagement,
            expected_gate="release",
        )
        if replay_violations:
            raise RefineryGateError(
                tuple(
                    "recorded release replay: {}".format(item)
                    for item in replay_violations
                )
            )
        return CandidateVerificationDTO.create(
            state=state,
            execution_suite_sha256=execution_suite_sha256,
            regression_evidence=regression_evidence,
            release_evidence=release_evidence,
        )
    release_evidence = registry.gate_evidence(
        delta_sha256,
        context=release_derivation_context,
        gate="release",
        execution_suite_sha256=execution_suite_sha256,
        recorded_at=recorded_at,
    )
    state = registry.record_release(
        delta_sha256,
        release_evidence,
        context=release_context,
        recorded_at=recorded_at,
    )
    return CandidateVerificationDTO.create(
        state=state,
        execution_suite_sha256=execution_suite_sha256,
        regression_evidence=regression_evidence,
        release_evidence=release_evidence,
    )


def promote_candidate(
    workspace: Union[str, os.PathLike, IndustryOntologyRegistry],
    *,
    delta_sha256: str,
    authorization: RefineryAuthorizationDTO,
    context: TransitionContextDTO,
    recorded_at: Optional[str] = None,
) -> IndustryPackageDescriptorDTO:
    """Promote an exact release-complete candidate; never publish it."""

    return _coerce_registry(workspace).promote(
        delta_sha256,
        authorization,
        context=context,
        recorded_at=recorded_at,
    )


def history(
    workspace: Union[str, os.PathLike, IndustryOntologyRegistry],
    *,
    delta_sha256: str,
) -> Tuple[Mapping[str, Any], ...]:
    """Return the verified candidate lifecycle history."""

    return _coerce_registry(workspace).history(delta_sha256)


def _coerce_registry(
    value: Union[str, os.PathLike, IndustryOntologyRegistry],
) -> IndustryOntologyRegistry:
    if isinstance(value, IndustryOntologyRegistry):
        return value
    return IndustryOntologyRegistry(value)


# ---------------------------------------------------------------------------
# Helpers


def _package_coverage_violations(manifest: Mapping[str, Any]) -> List[str]:
    assets = manifest.get("assets")
    if not isinstance(assets, list):
        return ["package manifest assets are missing"]
    categories = {
        str(item.get("category")) for item in assets if isinstance(item, Mapping)
    }
    violations = [
        "package is missing {} assets".format(category)
        for category in PACKAGE_ASSET_CATEGORIES
        if category not in categories
    ]
    case_kinds = {
        str(item.get("case_kind"))
        for item in assets
        if isinstance(item, Mapping) and item.get("category") == "cases"
    }
    for kind in CASE_KINDS:
        if kind not in case_kinds:
            violations.append("package is missing {} case".format(kind))
    return violations


def _reserved_semantica_package_ids() -> frozenset:
    """Return package IDs owned by the immutable built-in registries."""

    from semantica.chapter_packages import (
        list_chapter_packages,
        list_domain_packages,
    )

    return frozenset(
        item.package_id for item in (*list_chapter_packages(), *list_domain_packages())
    )


def _case_asset_tuple(value: Any) -> Tuple[Tuple[str, str, str], ...]:
    """Parse the deliberately narrow case binding used by execution suites."""

    result = []
    for item in _mapping_list(value, "suite run case_assets"):
        _reject_unknown(
            item,
            {"case_kind", "asset_id", "sha256"},
            "suite run case asset",
        )
        if set(item) != {"case_kind", "asset_id", "sha256"}:
            raise RefineryInputError(
                "suite run case asset requires case_kind, asset_id, and sha256"
            )
        result.append(
            (
                _strict_text(item.get("case_kind"), "suite run case_kind"),
                _strict_text(item.get("asset_id"), "suite run case asset_id"),
                _strict_text(item.get("sha256"), "suite run case asset sha256"),
            )
        )
    return tuple(result)


def _validate_execution_projection(
    projection: Mapping[str, Any], manifest_assets: Sequence[Mapping[str, Any]]
) -> None:
    """Validate the only contract that may project a refinery package to a runner.

    The contract is intentionally closed.  In particular, it cannot override
    package identity, version, bytes, or hashes; it may only assign runtime
    roles to the already content-addressed manifest assets and bind the fixed
    gate suite to scenarios, CQs, and case assets.
    """

    top_level = {
        "schema_version",
        "runner_contract",
        "namespace",
        "release_status",
        "execution",
        "assets",
        "gate_suite",
        "rights_evidence_asset_ids",
        "provenance_evidence_asset_ids",
    }
    _reject_unknown(projection, top_level, "execution projection")
    if set(projection) != top_level:
        raise RefineryInputError(
            "execution projection requires exactly: {}".format(
                ", ".join(sorted(top_level))
            )
        )
    _require_schema(
        _strict_text(projection.get("schema_version"), "projection schema_version")
    )
    if projection.get("runner_contract") != SEMANTIC_PACKAGE_RUNNER_CONTRACT:
        raise RefineryInputError("execution projection runner_contract is unsupported")
    namespace = _strict_text(projection.get("namespace"), "projection namespace")
    parsed_namespace = urlsplit(namespace)
    if not parsed_namespace.scheme or any(
        character.isspace() for character in namespace
    ):
        raise RefineryInputError("projection namespace must be an absolute IRI")
    if projection.get("release_status") != "complete":
        raise RefineryInputError("execution projection release_status must be complete")

    manifest_by_id: Dict[str, Mapping[str, Any]] = {}
    for item in manifest_assets:
        if not isinstance(item, Mapping):
            raise RefineryInputError("subject manifest asset must be a mapping")
        asset_id = _validate_opaque_id(item.get("asset_id"), "manifest asset_id")
        manifest_by_id[asset_id] = item

    metadata = _mapping(projection.get("assets"), "projection assets")
    if set(metadata) != set(manifest_by_id):
        missing = sorted(set(manifest_by_id) - set(metadata))
        extra = sorted(set(metadata) - set(manifest_by_id))
        raise RefineryInputError(
            "projection asset map differs from manifest (missing={}, extra={})".format(
                missing, extra
            )
        )
    contract_roles = []
    for raw_asset_id, raw_settings in metadata.items():
        asset_id = _validate_opaque_id(raw_asset_id, "projection asset_id")
        settings = _mapping(raw_settings, "projection asset metadata")
        allowed = {"role", "format", "kind", "load_into_dataset", "graph_name"}
        _reject_unknown(settings, allowed, "projection asset metadata")
        required = {"role", "format", "kind", "load_into_dataset"}
        if not required.issubset(settings):
            raise RefineryInputError(
                "projection asset metadata is missing: {}".format(
                    ", ".join(sorted(required - set(settings)))
                )
            )
        role = _strict_text(settings.get("role"), "projection asset role")
        format_name = _strict_text(settings.get("format"), "projection asset format")
        kind = _strict_text(settings.get("kind"), "projection asset kind")
        load = settings.get("load_into_dataset")
        if not isinstance(load, bool):
            raise RefineryInputError(
                "projection asset load_into_dataset must be boolean"
            )
        graph_name = settings.get("graph_name")
        if graph_name is not None:
            graph_name = _strict_text(graph_name, "projection asset graph_name")
            parsed_graph = urlsplit(graph_name)
            if not parsed_graph.scheme or any(
                character.isspace() for character in graph_name
            ):
                raise RefineryInputError(
                    "projection asset graph_name must be an absolute IRI"
                )
            if not load:
                raise RefineryInputError(
                    "projection graph_name is only valid for a loaded RDF asset"
                )
        category = manifest_by_id[asset_id].get("category")
        if load and kind.lower() != "rdf":
            raise RefineryInputError(
                "only projection assets with kind rdf may load into the dataset"
            )
        if category == "cases" and (kind.lower() != "rdf" or load):
            raise RefineryInputError(
                "case assets must be RDF and scenario-loaded, not preloaded"
            )
        if category == "queries" and role != "sparql":
            raise RefineryInputError("query assets must use the sparql runner role")
        if category == "contract":
            contract_roles.append((asset_id, role, format_name, kind, load))
        elif role.lower().strip() in {"contract", "chapter_contract"}:
            raise RefineryInputError(
                "only the manifest contract asset may use a contract runner role"
            )
    if len(contract_roles) != 1:
        raise RefineryInputError("projection requires exactly one contract role")
    _, contract_role, contract_format, contract_kind, contract_load = contract_roles[0]
    if (
        contract_role != "contract"
        or contract_format.lower() != "json"
        or contract_kind.lower() != "structured"
        or contract_load
    ):
        raise RefineryInputError(
            "contract asset must be structured JSON with role contract and no preload"
        )

    execution = _mapping(projection.get("execution"), "projection execution")
    execution_fields = {"scenario_registry_asset_id", "cq_registry_asset_id"}
    _reject_unknown(execution, execution_fields, "projection execution")
    if set(execution) != execution_fields:
        raise RefineryInputError(
            "projection execution requires scenario and CQ registry asset IDs"
        )
    registry_ids = []
    for field in sorted(execution_fields):
        asset_id = _validate_opaque_id(execution.get(field), field)
        if asset_id not in manifest_by_id:
            raise RefineryInputError("{} is absent from the manifest".format(field))
        settings = _mapping(metadata.get(asset_id), "registry asset metadata")
        if (
            str(settings.get("format", "")).lower() != "json"
            or str(settings.get("kind", "")).lower() != "structured"
            or settings.get("load_into_dataset") is not False
        ):
            raise RefineryInputError(
                "execution registry assets must be non-preloaded structured JSON"
            )
        registry_ids.append(asset_id)
    if len(set(registry_ids)) != 2:
        raise RefineryInputError("scenario and CQ registries must be distinct assets")

    gate_suite = _mapping(projection.get("gate_suite"), "projection gate_suite")
    if set(gate_suite) != set(REGRESSION_REQUIRED_CHECK_IDS):
        raise RefineryInputError(
            "projection gate_suite must define exactly the six regression checks"
        )
    case_check_kinds = {
        "case.positive": "positive",
        "case.negative": "negative",
        "case.ambiguity": "ambiguity",
        "case.prior_release": "prior_release",
    }
    for check_id in REGRESSION_REQUIRED_CHECK_IDS:
        settings = _mapping(gate_suite.get(check_id), "gate suite check")
        fields = {"scenario_ids", "cq_ids", "case_asset_ids"}
        _reject_unknown(settings, fields, "gate suite check")
        if set(settings) != fields:
            raise RefineryInputError(
                "gate suite checks require scenario_ids, cq_ids, and case_asset_ids"
            )
        scenarios = _text_tuple(settings.get("scenario_ids"), "gate scenario_ids")
        cq_ids = _text_tuple(settings.get("cq_ids"), "gate cq_ids", allow_empty=True)
        case_ids = _text_tuple(
            settings.get("case_asset_ids"),
            "gate case_asset_ids",
            allow_empty=True,
        )
        if check_id.startswith("cq.") and not cq_ids:
            raise RefineryInputError("{} must bind at least one CQ".format(check_id))
        expected_kind = case_check_kinds.get(check_id)
        if expected_kind is not None and not case_ids:
            raise RefineryInputError(
                "{} must bind at least one case asset".format(check_id)
            )
        for scenario_id in scenarios:
            _validate_opaque_id(scenario_id, "gate scenario_id")
        for cq_id in cq_ids:
            _validate_opaque_id(cq_id, "gate cq_id")
        for case_asset_id in case_ids:
            _validate_opaque_id(case_asset_id, "gate case asset_id")
            case_asset = manifest_by_id.get(case_asset_id)
            if (
                not isinstance(case_asset, Mapping)
                or case_asset.get("category") != "cases"
            ):
                raise RefineryInputError(
                    "gate case asset is absent from the manifest cases"
                )
            if (
                expected_kind is not None
                and case_asset.get("case_kind") != expected_kind
            ):
                raise RefineryInputError(
                    "{} binds a case asset with the wrong case_kind".format(check_id)
                )

    rights_ids = _text_tuple(
        projection.get("rights_evidence_asset_ids"),
        "rights_evidence_asset_ids",
    )
    for asset_id in rights_ids:
        _validate_opaque_id(asset_id, "rights evidence asset_id")
        asset = manifest_by_id.get(asset_id)
        if not isinstance(asset, Mapping) or asset.get("category") != "provenance":
            raise RefineryInputError(
                "rights evidence must name a content-bound provenance asset"
            )
    provenance_ids = _text_tuple(
        projection.get("provenance_evidence_asset_ids"),
        "provenance_evidence_asset_ids",
    )
    for asset_id in provenance_ids:
        _validate_opaque_id(asset_id, "provenance evidence asset_id")
        asset = manifest_by_id.get(asset_id)
        if not isinstance(asset, Mapping) or asset.get("category") != "provenance":
            raise RefineryInputError(
                "provenance evidence must name a content-bound provenance asset"
            )


def _subject_run_object_violations(
    *,
    suite: SubjectExecutionSuiteDTO,
    run: SubjectScenarioRunDTO,
    result: Mapping[str, Any],
    receipt_object: Mapping[str, Any],
) -> List[str]:
    """Verify retained runner JSON without trusting the suite's summary fields."""

    prefix = "run {}".format(run.scenario_id)
    violations: List[str] = []
    result_fields = {
        "schema_version",
        "runner_contract",
        "package_id",
        "package_version",
        "package_digest",
        "scenario_id",
        "status",
        "created_at",
        "operations",
        "oracle_checks",
        "capability_report",
        "cq_report",
        "shacl_report",
        "oracle_report",
        "receipt",
        "release_verdict",
        "reasons",
    }
    if set(result) != result_fields:
        violations.append("{} result schema is not exact".format(prefix))
        return violations
    if (
        result.get("schema_version") != "1.0"
        or result.get("runner_contract") != SEMANTIC_PACKAGE_RUNNER_CONTRACT
    ):
        violations.append("{} runner contract/schema is invalid".format(prefix))
    expected_result_identity = {
        "package_id": run.executor_package_id,
        "package_version": run.executor_package_version,
        "package_digest": run.executor_package_digest,
        "scenario_id": run.scenario_id,
        "status": run.status,
    }
    for field, expected in expected_result_identity.items():
        if result.get(field) != expected:
            violations.append("{} result {} mismatch".format(prefix, field))
    if result.get("created_at") != suite.created_at:
        violations.append("{} result timestamp differs from suite".format(prefix))

    operations = result.get("operations")
    if not isinstance(operations, list):
        violations.append("{} operations are invalid".format(prefix))
        operations = []
    operation_hashes: Dict[str, str] = {}
    loaded_assets: Dict[str, str] = {}
    for operation in operations:
        if not isinstance(operation, Mapping):
            violations.append("{} operation is not a mapping".format(prefix))
            continue
        fields = {"operation_id", "operation", "status", "payload", "sha256"}
        if set(operation) != fields:
            violations.append("{} operation schema is not exact".format(prefix))
            continue
        operation_id = operation.get("operation_id")
        operation_name = operation.get("operation")
        status = operation.get("status")
        payload = operation.get("payload")
        digest = operation.get("sha256")
        if (
            not isinstance(operation_id, str)
            or not operation_id
            or not isinstance(operation_name, str)
            or not operation_name
            or status not in _PHASE_STATUSES
            or not isinstance(payload, Mapping)
        ):
            violations.append("{} operation fields are invalid".format(prefix))
            continue
        expected_digest = sha256_text(
            canonical_json(
                {
                    "operation_id": operation_id,
                    "operation": operation_name,
                    "status": status,
                    "payload": payload,
                }
            )
        )
        if digest != expected_digest:
            violations.append("{} operation hash mismatch".format(prefix))
        if operation_id in operation_hashes:
            violations.append("{} operation IDs are duplicated".format(prefix))
        operation_hashes[operation_id] = str(digest)
        if operation_name in {"load", "load_asset"}:
            asset_id = payload.get("asset_id")
            asset_sha = payload.get("asset_sha256")
            if not isinstance(asset_id, str) or not is_sha256(asset_sha):
                violations.append(
                    "{} load operation lacks asset binding".format(prefix)
                )
            elif asset_id in loaded_assets and loaded_assets[asset_id] != asset_sha:
                violations.append("{} load asset hash is inconsistent".format(prefix))
            else:
                loaded_assets[asset_id] = asset_sha

    oracle_checks = result.get("oracle_checks")
    if not isinstance(oracle_checks, list) or not oracle_checks:
        violations.append("{} exact oracle checks are missing".format(prefix))
    else:
        for oracle in oracle_checks:
            if not isinstance(oracle, Mapping) or set(oracle) != {
                "check_id",
                "status",
                "expected",
                "actual",
                "message",
            }:
                violations.append("{} oracle check schema is invalid".format(prefix))
                continue
            if oracle.get("status") not in _PHASE_STATUSES:
                violations.append("{} oracle check status is invalid".format(prefix))

    report_hashes: Dict[str, str] = {}
    for field, kind in (
        ("capability_report", "capability"),
        ("cq_report", "cq"),
        ("shacl_report", "shacl"),
        ("oracle_report", "oracle"),
    ):
        report = result.get(field)
        if not _execution_report_mapping_integral(report, expected_kind=kind):
            violations.append("{} {} is not integral".format(prefix, field))
        elif isinstance(report, Mapping):
            report_hashes[kind] = str(report.get("sha256"))

    embedded_receipt = result.get("receipt")
    if not isinstance(embedded_receipt, Mapping):
        violations.append("{} native receipt is missing".format(prefix))
    elif canonical_json(embedded_receipt) != canonical_json(receipt_object):
        violations.append("{} receipt CAS object differs from result".format(prefix))
    violations.extend(
        _native_receipt_mapping_violations(
            receipt_object,
            expected_asset_hashes=dict(suite.execution_asset_hashes),
            expected_output_hashes=operation_hashes,
            expected_report_hashes=report_hashes,
            expected_contract_sha256=suite.execution_projection_sha256,
            expected_runtime=suite.runtime_source,
            expected_package_id=run.executor_package_id,
            expected_package_version=run.executor_package_version,
            expected_package_digest=run.executor_package_digest,
            prefix=prefix,
        )
    )
    if receipt_object.get("receipt_sha256") != run.receipt_sha256:
        violations.append("{} receipt_sha256 differs from suite".format(prefix))

    cq_report = result.get("cq_report")
    cq_payload = cq_report.get("payload") if isinstance(cq_report, Mapping) else None
    raw_cqs = (
        cq_payload.get("competency_question_ids")
        if isinstance(cq_payload, Mapping)
        else None
    )
    actual_cqs = tuple(
        sorted(
            {
                item
                for item in (raw_cqs if isinstance(raw_cqs, list) else [])
                if isinstance(item, str) and item
            }
        )
    )
    if actual_cqs != run.cq_ids:
        violations.append("{} actual CQ IDs differ from suite".format(prefix))
    for _, asset_id, digest in run.case_assets:
        if loaded_assets.get(asset_id) != digest:
            violations.append(
                "{} case asset {} was not actually loaded".format(prefix, asset_id)
            )

    verdict = result.get("release_verdict")
    if not _release_verdict_mapping_integral(verdict):
        violations.append("{} release verdict is not integral".format(prefix))
    elif isinstance(verdict, Mapping):
        if verdict.get("status") != run.release_status:
            violations.append("{} release status differs from suite".format(prefix))
        if verdict.get("receipt_sha256") != run.receipt_sha256:
            violations.append("{} release verdict receipt differs".format(prefix))
    return violations


def _capabilities_from_result(value: Mapping[str, Any]) -> Tuple[str, ...]:
    report = value.get("capability_report")
    payload = report.get("payload") if isinstance(report, Mapping) else None
    profile = payload.get("profile") if isinstance(payload, Mapping) else None
    raw = profile.get("capabilities") if isinstance(profile, Mapping) else None
    return tuple(
        sorted(
            {
                item
                for item in (raw if isinstance(raw, list) else [])
                if isinstance(item, str) and item
            }
        )
    )


def _loaded_assets_from_result(value: Mapping[str, Any]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    operations = value.get("operations")
    for operation in operations if isinstance(operations, list) else []:
        if not isinstance(operation, Mapping) or operation.get("operation") not in {
            "load",
            "load_asset",
        }:
            continue
        payload = operation.get("payload")
        if not isinstance(payload, Mapping):
            continue
        asset_id = payload.get("asset_id")
        digest = payload.get("asset_sha256")
        if isinstance(asset_id, str) and is_sha256(digest):
            result[asset_id] = str(digest)
    return result


def _execution_report_mapping_integral(value: Any, *, expected_kind: str) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "kind",
        "status",
        "payload",
        "sha256",
    }:
        return False
    if value.get("kind") != expected_kind or value.get("status") not in _PHASE_STATUSES:
        return False
    return value.get("sha256") == sha256_text(
        canonical_json(
            {
                "kind": value.get("kind"),
                "status": value.get("status"),
                "payload": value.get("payload"),
            }
        )
    )


def _native_receipt_mapping_violations(
    value: Mapping[str, Any],
    *,
    expected_asset_hashes: Mapping[str, str],
    expected_output_hashes: Mapping[str, str],
    expected_report_hashes: Mapping[str, str],
    expected_contract_sha256: str,
    expected_runtime: RuntimeSourceIdentityDTO,
    expected_package_id: str,
    expected_package_version: str,
    expected_package_digest: str,
    prefix: str,
) -> List[str]:
    fields = {
        "schema_version",
        "created_at",
        "runtime_version",
        "runtime_commit",
        "runtime_artifact_sha256",
        "package_id",
        "package_version",
        "package_digest",
        "asset_hashes",
        "chapter_contract_sha256",
        "dataset_sha256",
        "dataset_quad_count",
        "dataset_revision",
        "capability_report",
        "cq_report",
        "shacl_report",
        "oracle_report",
        "output_hashes",
        "provenance_bundle",
        "receipt_sha256",
    }
    violations = []
    if set(value) != fields:
        return ["{} receipt schema is not exact".format(prefix)]
    content = dict(value)
    declared = content.pop("receipt_sha256", None)
    if not is_sha256(declared) or declared != sha256_text(canonical_json(content)):
        violations.append("{} receipt content hash mismatch".format(prefix))
    expected_identity = {
        "runtime_version": expected_runtime.runtime_version,
        "runtime_commit": expected_runtime.runtime_commit,
        "runtime_artifact_sha256": expected_runtime.runtime_artifact_sha256,
        "package_id": expected_package_id,
        "package_version": expected_package_version,
        "package_digest": expected_package_digest,
        "chapter_contract_sha256": expected_contract_sha256,
    }
    for field, expected in expected_identity.items():
        if value.get(field) != expected:
            violations.append("{} receipt {} mismatch".format(prefix, field))
    if value.get("asset_hashes") != dict(expected_asset_hashes):
        violations.append("{} receipt asset hashes differ".format(prefix))
    if value.get("output_hashes") != dict(expected_output_hashes):
        violations.append("{} receipt output hashes differ".format(prefix))
    for field, kind in (
        ("capability_report", "capability"),
        ("cq_report", "cq"),
        ("shacl_report", "shacl"),
        ("oracle_report", "oracle"),
    ):
        report = value.get(field)
        if not _execution_report_mapping_integral(report, expected_kind=kind):
            violations.append("{} receipt {} is invalid".format(prefix, field))
        elif report.get("sha256") != expected_report_hashes.get(kind):
            violations.append("{} result and receipt reports differ".format(prefix))
    bindings = {
        "runtime_version": value.get("runtime_version"),
        "runtime_commit": value.get("runtime_commit"),
        "runtime_artifact_sha256": value.get("runtime_artifact_sha256"),
        "package_id": value.get("package_id"),
        "package_version": value.get("package_version"),
        "package_digest": value.get("package_digest"),
        "asset_hashes": value.get("asset_hashes"),
        "chapter_contract_sha256": value.get("chapter_contract_sha256"),
        "dataset_sha256": value.get("dataset_sha256"),
        "report_hashes": {
            kind: value[field].get("sha256")
            for field, kind in (
                ("capability_report", "capability"),
                ("cq_report", "cq"),
                ("shacl_report", "shacl"),
                ("oracle_report", "oracle"),
            )
            if isinstance(value.get(field), Mapping)
        },
        "output_hashes": value.get("output_hashes"),
    }
    if not _provenance_bundle_mapping_integral(
        value.get("provenance_bundle"), expected_bindings=bindings
    ):
        violations.append("{} native provenance bundle is invalid".format(prefix))
    return violations


def _provenance_bundle_mapping_integral(
    value: Any, *, expected_bindings: Mapping[str, Any]
) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "bundle_id",
        "generated_at",
        "bindings",
        "records",
        "bundle_sha256",
    }:
        return False
    content = dict(value)
    declared = content.pop("bundle_sha256", None)
    if not is_sha256(declared) or declared != sha256_text(canonical_json(content)):
        return False
    if value.get("bindings") != dict(expected_bindings):
        return False
    records = value.get("records")
    if not isinstance(records, list) or not records:
        return False
    try:
        from semantica.provenance.integrity import verify_checksum
    except ImportError:
        return False
    previous = None
    for sequence, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            return False
        checksum = record.get("checksum")
        if (
            not is_sha256(checksum)
            or record.get("sequence_id") != sequence
            or record.get("previous_checksum") != previous
            or not verify_checksum(dict(record), checksum)
        ):
            return False
        previous = checksum
    return True


def _release_verdict_mapping_integral(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "status",
        "receipt_sha256",
        "checked_at",
        "checks",
        "reasons",
    }:
        return False
    checks = value.get("checks")
    if not isinstance(checks, list) or not checks:
        return False
    failed = []
    for check in checks:
        if not isinstance(check, Mapping) or set(check) != {
            "check_id",
            "passed",
            "message",
        }:
            return False
        if (
            not isinstance(check.get("check_id"), str)
            or not isinstance(check.get("passed"), bool)
            or not isinstance(check.get("message"), str)
        ):
            return False
        if not check["passed"]:
            failed.append(check["check_id"])
    expected_status = "complete" if not failed else "blocked"
    return bool(
        value.get("status") == expected_status
        and value.get("reasons") == failed
        and is_sha256(value.get("receipt_sha256"))
    )


def _asset_manifest_record(change: PackageAssetDeltaDTO) -> Dict[str, Any]:
    return {
        "category": change.category,
        "asset_id": change.asset_id,
        "media_type": change.media_type,
        "sha256": change.sha256,
        "role": change.role,
        "case_kind": change.case_kind,
    }


def _descriptor_from_record(value: Mapping[str, Any]) -> IndustryPackageDescriptorDTO:
    _validate_promotion_record(value)
    return IndustryPackageDescriptorDTO(
        package_id=_strict_text(value.get("package_id"), "package_id"),
        version=_strict_text(value.get("version"), "package version"),
        package_sha256=_required_sha256(value.get("package_sha256"), "package_sha256"),
        manifest_sha256=_required_sha256(
            value.get("manifest_sha256"), "manifest_sha256"
        ),
        promotion_record_sha256=_required_sha256(
            value.get("promotion_record_sha256"), "promotion_record_sha256"
        ),
        delta_sha256=_required_sha256(value.get("delta_sha256"), "delta_sha256"),
        engagement_receipt_sha256=_required_sha256(
            value.get("engagement_receipt_sha256"), "engagement_receipt_sha256"
        ),
        regression_evidence_sha256=_required_sha256(
            value.get("regression_evidence_sha256"), "regression_evidence_sha256"
        ),
        release_evidence_sha256=_required_sha256(
            value.get("release_evidence_sha256"), "release_evidence_sha256"
        ),
        subject_execution_suite_sha256=_required_sha256(
            value.get("subject_execution_suite_sha256"),
            "subject_execution_suite_sha256",
        ),
        transition_context_sha256=_required_sha256(
            value.get("transition_context_sha256"),
            "transition_context_sha256",
        ),
        transition_context_object_sha256=_required_sha256(
            value.get("transition_context_object_sha256"),
            "transition_context_object_sha256",
        ),
        provenance_closure_sha256=_required_sha256(
            value.get("provenance_closure_sha256"),
            "provenance_closure_sha256",
        ),
        provenance_closure_object_sha256=_required_sha256(
            value.get("provenance_closure_object_sha256"),
            "provenance_closure_object_sha256",
        ),
        authorization_sha256=_required_sha256(
            value.get("authorization_sha256"), "authorization_sha256"
        ),
        authorization_object_sha256=_required_sha256(
            value.get("authorization_object_sha256"),
            "authorization_object_sha256",
        ),
        book_impact=_strict_text(value.get("book_impact"), "book_impact"),
        promoted_at=_strict_text(value.get("promoted_at"), "promoted_at"),
    )


def _validate_promotion_record(value: Mapping[str, Any]) -> None:
    fields = {
        "schema_version",
        "package_id",
        "version",
        "package_sha256",
        "manifest_sha256",
        "delta_sha256",
        "engagement_receipt_sha256",
        "regression_evidence_sha256",
        "release_evidence_sha256",
        "subject_execution_suite_sha256",
        "transition_context_sha256",
        "transition_context_object_sha256",
        "provenance_closure_sha256",
        "provenance_closure_object_sha256",
        "authorization_sha256",
        "authorization_object_sha256",
        "book_impact",
        "runtime_source",
        "promoted_at",
        "status",
        "promotion_record_sha256",
    }
    _reject_unknown(value, fields, "promotion record")
    if set(value) != fields:
        raise RefineryInputError("promotion record schema is incomplete")
    _require_schema(
        _strict_text(value.get("schema_version"), "promotion record schema_version")
    )
    if value.get("status") != "promoted":
        raise RefineryInputError("promotion record status must be promoted")
    runtime = RuntimeSourceIdentityDTO.from_dict(
        _mapping(value.get("runtime_source"), "promotion runtime_source")
    )
    if not runtime.complete:
        raise RefineryInputError("promotion runtime_source is incomplete")
    content = dict(value)
    declared = content.pop("promotion_record_sha256", None)
    if declared != sha256_text(canonical_json(content)):
        raise RefineryInputError("promotion record digest does not match content")


def _state_from_pointer(value: Mapping[str, Any]) -> RefineryStateDTO:
    _reject_unknown(
        value,
        {
            "schema_version",
            "delta_sha256",
            "package_id",
            "state",
            "sequence",
            "event_sha256",
            "previous_event_sha256",
            "package_sha256",
            "recorded_at",
        },
        "refinery current pointer",
    )
    if value.get("schema_version") != REFINERY_SCHEMA_VERSION:
        raise RefineryWorkspaceError("unsupported refinery pointer schema")
    return RefineryStateDTO(
        delta_sha256=_strict_text(value.get("delta_sha256"), "delta_sha256"),
        package_id=_strict_text(value.get("package_id"), "package_id"),
        state=_strict_text(value.get("state"), "state"),
        sequence=value.get("sequence"),
        event_sha256=_strict_text(value.get("event_sha256"), "event_sha256"),
        previous_event_sha256=(
            _strict_text(value["previous_event_sha256"], "previous_event_sha256")
            if value.get("previous_event_sha256") is not None
            else None
        ),
        package_sha256=(
            _strict_text(value["package_sha256"], "package_sha256")
            if value.get("package_sha256") is not None
            else None
        ),
        recorded_at=_strict_text(value.get("recorded_at"), "recorded_at"),
    )


def _validate_refinery_event(value: Mapping[str, Any]) -> None:
    """Strictly validate a complete immutable lifecycle event."""

    _reject_unknown(
        value,
        {
            "schema_version",
            "sequence",
            "state",
            "delta_sha256",
            "package_id",
            "previous_event_sha256",
            "package_sha256",
            "recorded_at",
            "payload",
            "event_sha256",
        },
        "refinery event",
    )
    _require_schema(_strict_text(value.get("schema_version"), "event schema_version"))
    sequence = value.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise RefineryInputError("event sequence must be an integer")
    state = _strict_text(value.get("state"), "event state")
    if state not in REFINERY_STATES or sequence != REFINERY_STATES.index(state) + 1:
        raise RefineryInputError("event state/sequence is invalid")
    _required_sha256(value.get("delta_sha256"), "event delta_sha256")
    _validate_package_id(value.get("package_id"))
    previous = value.get("previous_event_sha256")
    if sequence == 1:
        if previous is not None:
            raise RefineryInputError("candidate event cannot have a predecessor")
    else:
        _required_sha256(previous, "event previous_event_sha256")
    package_sha = value.get("package_sha256")
    if sequence <= 2:
        if package_sha is not None:
            raise RefineryInputError("pre-commit event cannot bind a package digest")
    else:
        _required_sha256(package_sha, "event package_sha256")
    _validate_timestamp(value.get("recorded_at"), "event recorded_at")
    payload = _mapping(value.get("payload"), "event payload")
    _validate_event_payload(state, payload)
    declared = _required_sha256(value.get("event_sha256"), "event_sha256")
    content = dict(value)
    content.pop("event_sha256", None)
    if sha256_text(canonical_json(content)) != declared:
        raise RefineryInputError("event_sha256 does not match event content")


def _validate_event_payload(state: str, payload: Mapping[str, Any]) -> None:
    expected = {
        "candidate": {
            "envelope_sha256",
            "binding_sha256",
            "engagement_receipt_sha256",
            "engagement_status",
            "transition_context_sha256",
            "transition_context_object_sha256",
        },
        "proposed": {
            "proposal",
            "transition_context_sha256",
            "transition_context_object_sha256",
        },
        "committed": {
            "manifest_sha256",
            "authorization_sha256",
            "authorization_object_sha256",
            "engagement_receipt_sha256",
            "transition_context_sha256",
            "transition_context_object_sha256",
        },
        "regression_passed": {
            "regression_evidence_sha256",
            "regression_evidence_object_sha256",
            "execution_suite_sha256",
            "execution_suite_object_sha256",
            "transition_context_sha256",
            "transition_context_object_sha256",
            "provenance_closure_sha256",
            "provenance_closure_object_sha256",
        },
        "release_complete": {
            "release_evidence_sha256",
            "release_evidence_object_sha256",
            "execution_suite_sha256",
            "execution_suite_object_sha256",
            "transition_context_sha256",
            "transition_context_object_sha256",
            "provenance_closure_sha256",
            "provenance_closure_object_sha256",
        },
        "promoted": {
            "promotion_record_sha256",
            "authorization_sha256",
            "authorization_object_sha256",
            "promotion_target",
            "transition_context_sha256",
            "transition_context_object_sha256",
            "provenance_closure_sha256",
            "provenance_closure_object_sha256",
        },
    }[state]
    _reject_unknown(payload, expected, "{} event payload".format(state))
    if set(payload) != expected:
        missing = sorted(expected - set(payload))
        raise RefineryInputError(
            "{} event payload is missing: {}".format(state, ", ".join(missing))
        )
    if state == "proposed":
        _required_text(payload.get("proposal"), "proposal")
        for field in (
            "transition_context_sha256",
            "transition_context_object_sha256",
        ):
            _required_sha256(payload.get(field), field)
        return
    if state == "candidate":
        for field in (
            "envelope_sha256",
            "binding_sha256",
            "engagement_receipt_sha256",
            "transition_context_sha256",
            "transition_context_object_sha256",
        ):
            _required_sha256(payload.get(field), field)
        if payload.get("engagement_status") not in {"complete", "blocked"}:
            raise RefineryInputError("candidate engagement_status is invalid")
        return
    for field, item in payload.items():
        if field == "promotion_target":
            _required_text(item, field)
        else:
            _required_sha256(item, field)


def _validate_registry_event_document(value: Mapping[str, Any]) -> None:
    _reject_unknown(
        value,
        {
            "schema_version",
            "sequence",
            "previous_event_sha256",
            "operation",
            "package_id",
            "version",
            "package_sha256",
            "promotion_record_sha256",
            "packages_sha256",
            "recorded_at",
            "event_sha256",
        },
        "registry event",
    )
    _require_schema(_strict_text(value.get("schema_version"), "registry schema"))
    sequence = value.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise RefineryInputError("registry event sequence is invalid")
    previous = value.get("previous_event_sha256")
    if sequence == 1:
        if previous is not None:
            raise RefineryInputError("first registry event has a predecessor")
    else:
        _required_sha256(previous, "registry previous_event_sha256")
    if value.get("operation") != "promote":
        raise RefineryInputError("registry operation must be promote")
    _validate_package_id(value.get("package_id"))
    _required_text(value.get("version"), "registry event version")
    for field in (
        "package_sha256",
        "promotion_record_sha256",
        "packages_sha256",
    ):
        _required_sha256(value.get(field), "registry event {}".format(field))
    _validate_timestamp(value.get("recorded_at"), "registry event recorded_at")
    declared = _required_sha256(value.get("event_sha256"), "registry event_sha256")
    content = dict(value)
    content.pop("event_sha256", None)
    if sha256_text(canonical_json(content)) != declared:
        raise RefineryInputError("registry event hash mismatch")


def _validate_package_id(value: Any) -> str:
    result = _validate_opaque_id(value, "package_id")
    if result in {".", ".."} or "/" in result or "\\" in result:
        raise RefineryInputError("package_id is an opaque registry ID, not a path")
    return result


def _validate_opaque_id(value: Any, field: str) -> str:
    result = _required_text(value, field)
    if not _SAFE_OPAQUE_ID.fullmatch(result):
        raise RefineryInputError(
            "{} must be a safe opaque identifier, never a path".format(field)
        )
    return result


def _validate_logical_uri(value: Any, field: str) -> str:
    text = _required_text(value, field)
    if "\\" in text:
        raise RefineryInputError("{} must not contain backslashes".format(field))
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in _LOGICAL_URI_SCHEMES:
        raise RefineryInputError(
            "{} must use a non-resolving logical URI scheme ({})".format(
                field, ", ".join(sorted(_LOGICAL_URI_SCHEMES))
            )
        )
    decoded = unquote(text)
    segments = re.split(r"[/:?#]", decoded)
    if any(segment in {".", ".."} for segment in segments):
        raise RefineryInputError("{} must not contain dot segments".format(field))
    return text


def _uri_within_root(uri: str, root: str) -> bool:
    """Return true only for the root itself or a delimiter-bounded child URI."""

    _validate_logical_uri(uri, "evidence URI")
    _validate_logical_uri(root, "evidence_root")
    if uri == root:
        return True
    normalized = root.rstrip("/#:?")
    return any(
        uri.startswith(normalized + delimiter) for delimiter in ("/", "#", ":", "?")
    )


def _validate_timestamp(value: Any, field: str) -> str:
    text = _required_text(value, field)
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise RefineryInputError("{} must be ISO 8601".format(field)) from exc
    if parsed.tzinfo is None:
        raise RefineryInputError("{} must include a timezone".format(field))
    return text


def _validate_unique_text_tuple(
    value: Tuple[str, ...], field: str, *, allow_empty: bool = False
) -> None:
    if not isinstance(value, tuple):
        raise RefineryInputError("{} must be a tuple".format(field))
    if not value and not allow_empty:
        raise RefineryInputError("{} must not be empty".format(field))
    for item in value:
        _required_text(item, field)
    if len(set(value)) != len(value):
        raise RefineryInputError("{} must be unique".format(field))


def _validate_unique_by(
    values: Sequence[Any],
    key: Any,
    field: str,
    *,
    allow_empty: bool = False,
) -> None:
    if not values and not allow_empty:
        raise RefineryInputError("{} must not be empty".format(field))
    keys = [key(item) for item in values]
    if len(keys) != len(set(keys)):
        raise RefineryInputError("{} must be unique".format(field))


def _text_tuple(
    value: Any, field: str, *, allow_empty: bool = False
) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise RefineryInputError("{} must be a list".format(field))
    if any(not isinstance(item, str) for item in value):
        raise RefineryInputError("{} entries must be text".format(field))
    result = tuple(value)
    if not result and not allow_empty:
        raise RefineryInputError("{} must not be empty".format(field))
    return result


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RefineryInputError("{} must be a mapping".format(field))
    return value


def _mapping_list(value: Any, field: str) -> Tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        raise RefineryInputError("{} must be a list".format(field))
    result = []
    for item in value:
        if not isinstance(item, Mapping):
            raise RefineryInputError("{} entries must be mappings".format(field))
        result.append(item)
    return tuple(result)


def _validate_canonical_json(value: str, field: str) -> None:
    try:
        parsed = json.loads(value)
    except Exception as exc:
        raise RefineryInputError("{} must be JSON".format(field)) from exc
    if canonical_json(parsed) != value:
        raise RefineryInputError("{} must be canonical JSON".format(field))


def _required_text(value: Any, field: str) -> str:
    text = _exact_string(value, field)
    if not text:
        raise RefineryInputError("{} must be non-empty text".format(field))
    return text


def _exact_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise RefineryInputError("{} must be text".format(field))
    if value != value.strip():
        raise RefineryInputError(
            "{} must not contain surrounding whitespace".format(field)
        )
    return value


def _strict_text(value: Any, field: str) -> str:
    """Alias used at persisted/public parsing boundaries for clarity."""

    return _required_text(value, field)


def _required_sha256(value: Any, field: str) -> str:
    if not is_sha256(value):
        raise RefineryInputError("{} must be a lowercase SHA-256 digest".format(field))
    return str(value)


def _require_schema(value: str) -> None:
    if value != REFINERY_SCHEMA_VERSION:
        raise RefineryInputError("unsupported refinery schema_version")


def _check_declared_digest(value: Mapping[str, Any], field: str, actual: str) -> None:
    if field in value and value.get(field) != actual:
        raise RefineryInputError("{} does not match content".format(field))


def _reject_unknown(
    value: Mapping[str, Any], allowed: Iterable[str], field: str
) -> None:
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise RefineryInputError(
            "{} contains unknown fields: {}".format(field, ", ".join(unknown))
        )


def _storage_key(value: str) -> str:
    return sha256_text(value)


def _lexical_absolute_path(value: Union[str, os.PathLike, Path]) -> Path:
    """Return an absolute lexical path without following symlinks."""

    return Path(os.path.abspath(os.fspath(Path(value).expanduser())))


def _require_regular_directory(path: Path, field: str) -> None:
    try:
        metadata = os.lstat(str(path))
    except FileNotFoundError as exc:
        raise RefineryWorkspaceError("{} is missing: {}".format(field, path)) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RefineryWorkspaceError(
            "{} must be a non-symlink directory: {}".format(field, path)
        )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _json_mapping_from_bytes(payload: bytes, source: str) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise RefineryWorkspaceError("invalid JSON: {}".format(source)) from exc
    if not isinstance(value, Mapping):
        raise RefineryWorkspaceError("JSON root is not a mapping: {}".format(source))
    return value


def _read_json(path: Path) -> Mapping[str, Any]:
    return _json_mapping_from_bytes(_read_bytes(path), str(path))


def _read_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RefineryWorkspaceError(
            "required regular file is missing: {}".format(path)
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RefineryWorkspaceError("failed to read {}".format(path)) from exc


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise RefineryWorkspaceError(
            "refusing to overwrite immutable file: {}".format(path)
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
        raise RefineryWorkspaceError(
            "refinery workspace is busy or has a stale lock"
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
        pass


# ---------------------------------------------------------------------------
# Standalone CLI


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("init")
    command.add_argument("--workspace", required=True)
    command.add_argument("--registry-id", required=True)

    command = commands.add_parser("engage")
    command.add_argument("--workspace", required=True)
    command.add_argument("--envelope", required=True)
    command.add_argument("--binding", required=True)
    command.add_argument("--receipt", required=True)

    command = commands.add_parser("candidate")
    command.add_argument("--workspace", required=True)
    command.add_argument("--envelope", required=True)
    command.add_argument("--binding", required=True)
    command.add_argument("--engagement", required=True)
    command.add_argument("--delta", required=True)

    command = commands.add_parser("propose")
    command.add_argument("--workspace", required=True)
    command.add_argument("--delta-sha256", required=True)
    command.add_argument("--context", required=True)

    command = commands.add_parser("commit")
    command.add_argument("--workspace", required=True)
    command.add_argument("--delta-sha256", required=True)
    command.add_argument("--authorization", required=True)
    command.add_argument("--context", required=True)

    for name in ("regress", "release"):
        command = commands.add_parser(name)
        command.add_argument("--workspace", required=True)
        command.add_argument("--delta-sha256", required=True)
        command.add_argument("--evidence", required=True)
        command.add_argument("--context", required=True)

    command = commands.add_parser("promote")
    command.add_argument("--workspace", required=True)
    command.add_argument("--delta-sha256", required=True)
    command.add_argument("--authorization", required=True)
    command.add_argument("--context", required=True)

    command = commands.add_parser("status")
    command.add_argument("--workspace", required=True)
    command.add_argument("--delta-sha256", required=True)

    command = commands.add_parser("history")
    command.add_argument("--workspace", required=True)
    command.add_argument("--delta-sha256", required=True)

    command = commands.add_parser("list")
    command.add_argument("--workspace", required=True)

    command = commands.add_parser("resolve")
    command.add_argument("--workspace", required=True)
    command.add_argument("--package-id", required=True)
    command.add_argument("--version")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run ``python -m semantica.ontology.refinery`` fail closed."""

    args = build_argument_parser().parse_args(argv)
    try:
        if args.command == "init":
            registry = IndustryOntologyRegistry.create(
                args.workspace, registry_id=args.registry_id
            )
            result: Any = {
                "status": "created",
                "registry_id": registry.registry_id,
            }
        else:
            registry = IndustryOntologyRegistry(args.workspace)
            if args.command == "engage":
                envelope = SemanticTaskEnvelope.from_dict(
                    _read_json(Path(args.envelope))
                )
                binding = ProjectOntologyBinding.from_dict(
                    _read_json(Path(args.binding))
                )
                receipt = SemanticEngagementReceipt.from_dict(
                    _read_json(Path(args.receipt))
                )
                result = {
                    "engagement_record_sha256": registry.record_engagement(
                        envelope, binding, receipt
                    ),
                    "status": receipt.status,
                }
            elif args.command == "candidate":
                result = registry.register_candidate(
                    PackageDelta.from_dict(_read_json(Path(args.delta))),
                    SemanticTaskEnvelope.from_dict(_read_json(Path(args.envelope))),
                    ProjectOntologyBinding.from_dict(_read_json(Path(args.binding))),
                    SemanticEngagementReceipt.from_dict(
                        _read_json(Path(args.engagement))
                    ),
                ).as_dict()
            elif args.command == "propose":
                result = registry.propose(
                    args.delta_sha256,
                    context=TransitionContextDTO.from_dict(
                        _read_json(Path(args.context))
                    ),
                ).as_dict()
            elif args.command == "commit":
                result = registry.commit(
                    args.delta_sha256,
                    RefineryAuthorizationDTO.from_dict(
                        _read_json(Path(args.authorization))
                    ),
                    context=TransitionContextDTO.from_dict(
                        _read_json(Path(args.context))
                    ),
                ).as_dict()
            elif args.command == "regress":
                result = registry.record_regression(
                    args.delta_sha256,
                    RefineryGateEvidenceDTO.from_dict(_read_json(Path(args.evidence))),
                    context=TransitionContextDTO.from_dict(
                        _read_json(Path(args.context))
                    ),
                ).as_dict()
            elif args.command == "release":
                result = registry.record_release(
                    args.delta_sha256,
                    RefineryGateEvidenceDTO.from_dict(_read_json(Path(args.evidence))),
                    context=TransitionContextDTO.from_dict(
                        _read_json(Path(args.context))
                    ),
                ).as_dict()
            elif args.command == "promote":
                result = registry.promote(
                    args.delta_sha256,
                    RefineryAuthorizationDTO.from_dict(
                        _read_json(Path(args.authorization))
                    ),
                    context=TransitionContextDTO.from_dict(
                        _read_json(Path(args.context))
                    ),
                ).as_dict()
            elif args.command == "status":
                result = registry.status(args.delta_sha256).as_dict()
            elif args.command == "history":
                result = list(registry.history(args.delta_sha256))
            elif args.command == "list":
                result = [item.as_dict() for item in registry.list_packages()]
            else:
                result = registry.resolve_package(
                    args.package_id, version=args.version
                ).as_dict()
        print(canonical_json({"ok": True, "result": result}))
        return 0
    except RefineryGateError as exc:
        print(
            canonical_json(
                {"ok": False, "status": "blocked", "violations": exc.violations}
            )
        )
        return 2
    except OntologyRefineryError as exc:
        print(
            canonical_json({"ok": False, "status": "blocked", "error": str(exc)}),
            file=sys.stderr,
        )
        return 1


__all__ = [
    "AssetDecisionDTO",
    "BOOK_IMPACTS",
    "CASE_KINDS",
    "CandidateVerificationDTO",
    "EMPTY_PACKAGE_SHA256",
    "EngagementPhaseDTO",
    "ExecutionReceiptReferenceDTO",
    "GateCheckDTO",
    "IndustryOntologyRegistry",
    "IndustryPackageDescriptorDTO",
    "IndustryPackageNotFoundError",
    "IndustryPackageVersionExistsError",
    "LearningResultDTO",
    "OntologyRefineryError",
    "PACKAGE_ASSET_CATEGORIES",
    "PACKAGE_DELTA_CATEGORIES",
    "REGRESSION_REQUIRED_CHECK_IDS",
    "RELEASE_REQUIRED_CHECK_IDS",
    "INDUSTRY_REGISTRY_TARGET",
    "SEMANTIC_PACKAGE_RUNNER_CONTRACT",
    "PackageAssetDeltaDTO",
    "PackageDelta",
    "ProjectOntologyBinding",
    "ProvenanceClosureDTO",
    "ProvenanceScenarioBindingDTO",
    "REFINERY_CONTRACT",
    "REFINERY_SCHEMA_VERSION",
    "REFINERY_STATES",
    "TRANSITION_CONTEXT_ACTIONS",
    "RefineryAuthorizationDTO",
    "RefineryGateError",
    "RefineryGateEvidenceDTO",
    "RefineryInputError",
    "RefineryStateDTO",
    "RefineryStateError",
    "RefineryWorkspaceError",
    "RefineryWorkspaceExistsError",
    "RuntimeSourceIdentityDTO",
    "SubjectExecutionSuiteDTO",
    "SubjectScenarioRunDTO",
    "SemanticEngagementReceipt",
    "SemanticTaskEnvelope",
    "SourceEvidenceDTO",
    "TransitionContextDTO",
    "build_argument_parser",
    "build_refinery_acceptance_delta",
    "commit_candidate",
    "derive_gate_evidence",
    "execute_candidate",
    "history",
    "main",
    "open_engagement",
    "promote_candidate",
    "propose_candidate",
    "refinery_capabilities",
    "verify_candidate",
]


if __name__ == "__main__":
    raise SystemExit(main())
