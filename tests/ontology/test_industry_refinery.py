import json
import base64
from dataclasses import replace

import pytest
import semantica.ontology.refinery as refinery_module

from semantica.ontology.lifecycle import canonical_json, sha256_text
from semantica.ontology.refinery import (
    AssetDecisionDTO,
    BOOK_IMPACTS,
    CASE_KINDS,
    EMPTY_PACKAGE_SHA256,
    PACKAGE_ASSET_CATEGORIES,
    PACKAGE_DELTA_CATEGORIES,
    REFINERY_CONTRACT,
    REFINERY_STATES,
    REGRESSION_REQUIRED_CHECK_IDS,
    RELEASE_REQUIRED_CHECK_IDS,
    EngagementPhaseDTO,
    ExecutionReceiptReferenceDTO,
    GateCheckDTO,
    IndustryOntologyRegistry,
    IndustryPackageNotFoundError,
    LearningResultDTO,
    PackageAssetDeltaDTO,
    PackageDelta,
    ProjectOntologyBinding,
    ProvenanceClosureDTO,
    RefineryAuthorizationDTO,
    RefineryGateError,
    RefineryGateEvidenceDTO,
    RefineryInputError,
    RefineryStateError,
    RefineryWorkspaceError,
    RuntimeSourceIdentityDTO,
    SemanticEngagementReceipt,
    SemanticTaskEnvelope,
    SourceEvidenceDTO,
    TransitionContextDTO,
    commit_candidate,
    build_refinery_acceptance_delta,
    history,
    main,
    open_engagement,
    promote_candidate,
    propose_candidate,
    refinery_capabilities,
    verify_candidate,
)
from semantica.chapter_packages.runner import SemanticPackageRunner

T0 = "2026-08-19T00:00:00Z"
SOURCE = SourceEvidenceDTO(
    source_id="engineering-record",
    uri="urn:example:evidence-root:engineering-record",
    sha256="a" * 64,
    media_type="application/json",
    captured_at=T0,
)
RUNTIME = RuntimeSourceIdentityDTO(
    runtime_commit="1" * 40,
    runtime_artifact_sha256="b" * 64,
    runtime_version="0.6.5+oe.2",
)
CAPABILITY = "semantic.package.load"


def _asset(
    category,
    asset_id,
    *,
    content=None,
    media_type="text/plain",
    role=None,
    case_kind=None,
):
    return PackageAssetDeltaDTO.add_text(
        category=category,
        asset_id=asset_id,
        content=content if content is not None else "{}:{}".format(category, asset_id),
        media_type=media_type,
        role=role,
        case_kind=case_kind,
    )


def _delta(*, omit=(), package_id="industry.example"):
    assets = {category: [] for category in PACKAGE_ASSET_CATEGORIES}
    assets["ontology"].append(
        _asset(
            "ontology",
            "ontology-core",
            content=(
                "@prefix owl: <http://www.w3.org/2002/07/owl#> .\n"
                "<urn:industry:example> a owl:Ontology .\n"
            ),
            media_type="text/turtle",
        )
    )
    cq_registry = {
        "schema_version": "1.0",
        "package_id": package_id,
        "competency_questions": [
            {
                "id": "cq-current",
                "question": "Can the current reusable case be retrieved?",
                "scenario_ids": ["scenario-current"],
            },
            {
                "id": "cq-prior",
                "question": "Does the prior-release case still execute?",
                "scenario_ids": ["scenario-prior"],
            },
        ],
    }
    assets["competency_questions"].append(
        _asset(
            "competency_questions",
            "cq-registry",
            content=canonical_json(cq_registry),
            media_type="application/json",
        )
    )
    assets["shapes"].append(
        _asset(
            "shapes",
            "quality-shapes",
            content=(
                "@prefix sh: <http://www.w3.org/ns/shacl#> .\n"
                "@prefix ex: <urn:example:> .\n"
                "ex:NamedShape a sh:NodeShape ; sh:targetSubjectsOf ex:name .\n"
            ),
            media_type="text/turtle",
        )
    )
    assets["queries"].append(
        _asset(
            "queries",
            "cq-primary",
            content="SELECT ?name WHERE { ?s <urn:example:name> ?name . } ORDER BY ?name\n",
            media_type="application/sparql-query",
        )
    )
    assets["rules"].append(
        _asset(
            "rules",
            "engineering-rules",
            content="IF observed(?x) THEN reusable(?x)\n",
        )
    )
    case_values = {
        "positive": "positive",
        "negative": None,
        "ambiguity": "ambiguity",
        "prior_release": "prior",
    }
    for case_kind, value in case_values.items():
        case_content = (
            '<urn:case:{}> <urn:example:name> "{}" .\n'.format(case_kind, value)
            if value is not None
            else "# deliberately empty negative graph\n"
        )
        assets["cases"].append(
            _asset(
                "cases",
                "case-{}".format(case_kind),
                content=case_content,
                media_type="text/turtle",
                case_kind=case_kind,
            )
        )
    scenario_rows = {
        "scenario-current": ("case-positive", "positive", 1),
        "scenario-negative": ("case-negative", None, 0),
        "scenario-ambiguity": ("case-ambiguity", "ambiguity", 1),
        "scenario-prior": ("case-prior_release", "prior", 1),
    }
    scenarios = []
    for scenario_id, (primary_asset, value, row_count) in scenario_rows.items():
        positive_oracle = {"row_count": row_count}
        if value is not None:
            positive_oracle["bindings"] = {"name": [value]}
        scenarios.append(
            {
                "id": scenario_id,
                "status": "native",
                "execution": {
                    "provider": "SemanticRuntime",
                    "operation": "select_exact_multiset",
                    "query_asset_id": "cq-primary",
                },
                "inputs": [primary_asset, "case-negative"],
                "oracle": {
                    "id": "oracle-{}".format(scenario_id),
                    "status": "ready",
                    "positive": positive_oracle,
                    "single_fault_negative": {"row_count": 0},
                },
            }
        )
    scenario_registry = {
        "schema_version": "1.0",
        "package_id": package_id,
        "runner_contract": "semantica.chapter_packages.SemanticPackageRunner/v1",
        "scenarios": scenarios,
    }
    assets["provenance"].extend(
        (
            _asset(
                "provenance",
                "scenario-registry",
                content=canonical_json(scenario_registry),
                media_type="application/json",
            ),
            _asset(
                "provenance",
                "rights-evidence",
                content=canonical_json(
                    {
                        "schema_version": "1.0",
                        "source_id": SOURCE.source_id,
                        "source_sha256": SOURCE.sha256,
                        "statement": "Rights evidence retained; no legal conclusion.",
                    }
                ),
                media_type="application/json",
            ),
            _asset(
                "provenance",
                "source-evidence-binding",
                content=canonical_json(
                    {
                        "schema_version": "1.0",
                        "kind": "semantica.source-evidence-binding",
                        "source_evidence": [SOURCE.as_dict()],
                    }
                ),
                media_type="application/json",
            ),
        )
    )
    for category in omit:
        assets[category] = []
    runtime_metadata = {}
    for category, items in assets.items():
        for item in items:
            if category == "ontology":
                metadata = {
                    "role": "ontology",
                    "format": "turtle",
                    "kind": "rdf",
                    "load_into_dataset": True,
                }
            elif category == "competency_questions":
                metadata = {
                    "role": "competency_questions",
                    "format": "json",
                    "kind": "structured",
                    "load_into_dataset": False,
                }
            elif category == "shapes":
                metadata = {
                    "role": "shapes",
                    "format": "turtle",
                    "kind": "rdf",
                    "load_into_dataset": False,
                }
            elif category == "queries":
                metadata = {
                    "role": "sparql",
                    "format": "sparql",
                    "kind": "text",
                    "load_into_dataset": False,
                }
            elif category == "rules":
                metadata = {
                    "role": "engineering_rules",
                    "format": "text",
                    "kind": "text",
                    "load_into_dataset": False,
                }
            elif category == "cases":
                metadata = {
                    "role": "case",
                    "format": "turtle",
                    "kind": "rdf",
                    "load_into_dataset": False,
                }
            elif item.asset_id == "scenario-registry":
                metadata = {
                    "role": "scenario_registry",
                    "format": "json",
                    "kind": "structured",
                    "load_into_dataset": False,
                }
            else:
                metadata = {
                    "role": "provenance",
                    "format": "json",
                    "kind": "structured",
                    "load_into_dataset": False,
                }
            runtime_metadata[item.asset_id] = metadata
    runtime_metadata["package-contract"] = {
        "role": "contract",
        "format": "json",
        "kind": "structured",
        "load_into_dataset": False,
    }
    projection = {
        "schema_version": "1.0",
        "runner_contract": "semantica.chapter_packages.SemanticPackageRunner/v1",
        "namespace": "urn:industry:example:",
        "release_status": "complete",
        "execution": {
            "scenario_registry_asset_id": "scenario-registry",
            "cq_registry_asset_id": "cq-registry",
        },
        "assets": runtime_metadata,
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
    assets["contract"].append(
        _asset(
            "contract",
            "package-contract",
            content=canonical_json(projection),
            media_type="application/json",
        )
    )
    return PackageDelta(
        package_id=package_id,
        base_version="0",
        base_package_sha256=EMPTY_PACKAGE_SHA256,
        target_version="1.0.0",
        rationale="Repeated engineering practice merits a governed candidate.",
        created_by="fact.authority",
        created_at=T0,
        required_capabilities=(CAPABILITY,),
        source_evidence=(SOURCE,),
        book_impact="none",
        **{key: tuple(value) for key, value in assets.items()},
    )


def _replace_text_asset(original, content):
    payload = content.encode("utf-8")
    return PackageAssetDeltaDTO(
        category=original.category,
        asset_id=original.asset_id,
        operation="replace",
        media_type=original.media_type,
        sha256=refinery_module._sha256_bytes(payload),
        content_base64=base64.b64encode(payload).decode("ascii"),
        replaces_sha256=original.sha256,
        role=original.role,
        case_kind=original.case_kind,
    )


def _v2_fake_prior_delta(base_delta, base_package_sha256):
    by_id = {item.asset_id: item for item in base_delta.assets}
    fake_case = _asset(
        "cases",
        "case-fake-prior",
        content='<urn:case:fake-prior> <urn:example:name> "fake-prior" .\n',
        media_type="text/turtle",
        case_kind="prior_release",
    )
    cq_registry = {
        "schema_version": "1.0",
        "package_id": base_delta.package_id,
        "competency_questions": [
            {
                "id": "cq-fake-prior",
                "question": "Can a target-labelled fake stand in for prior truth?",
                "scenario_ids": ["scenario-current", "scenario-prior"],
            }
        ],
    }
    cq_change = _replace_text_asset(by_id["cq-registry"], canonical_json(cq_registry))
    scenario_registry = json.loads(
        by_id["scenario-registry"].content_bytes.decode("utf-8")
    )
    for scenario in scenario_registry["scenarios"]:
        if scenario["id"] == "scenario-prior":
            scenario["inputs"] = ["case-fake-prior", "case-negative"]
            scenario["oracle"]["positive"] = {
                "row_count": 1,
                "bindings": {"name": ["fake-prior"]},
            }
    scenario_change = _replace_text_asset(
        by_id["scenario-registry"], canonical_json(scenario_registry)
    )
    projection = json.loads(by_id["package-contract"].content_bytes.decode("utf-8"))
    projection["assets"]["case-fake-prior"] = {
        "role": "case",
        "format": "turtle",
        "kind": "rdf",
        "load_into_dataset": False,
    }
    projection["gate_suite"]["cq.prior"]["cq_ids"] = ["cq-fake-prior"]
    projection["gate_suite"]["cq.current"]["cq_ids"] = ["cq-fake-prior"]
    projection["gate_suite"]["case.prior_release"]["case_asset_ids"] = [
        "case-fake-prior"
    ]
    contract_change = _replace_text_asset(
        by_id["package-contract"], canonical_json(projection)
    )
    return PackageDelta(
        package_id=base_delta.package_id,
        base_version=base_delta.target_version,
        base_package_sha256=base_package_sha256,
        target_version="2.0.0",
        rationale="Attempted target-labelled prior replacement.",
        created_by="fact.authority",
        created_at=T0,
        required_capabilities=(CAPABILITY,),
        source_evidence=(SOURCE,),
        book_impact="none",
        ontology=(),
        competency_questions=(cq_change,),
        shapes=(),
        queries=(),
        rules=(),
        cases=(fake_case,),
        contract=(contract_change,),
        provenance=(scenario_change,),
    )


def _envelope(action="candidate", **changes):
    values = {
        "task_id": "task-{}".format(action),
        "task_kind": "engineering-refinement",
        "project_id": "project-1",
        "domain": "example-industry",
        "intent": "Refine repeated engineering knowledge.",
        "requested_decision": "Determine whether the lesson is reusable.",
        "actor_id": "fact.authority",
        "requested_actions": (action,),
        "required_capabilities": (CAPABILITY,),
        "evidence": (SOURCE,),
        "created_at": T0,
    }
    values.update(changes)
    return SemanticTaskEnvelope(
        **values,
    )


def _binding():
    return ProjectOntologyBinding(
        binding_id="binding-1",
        project_id="project-1",
        domain="example-industry",
        package_id="industry.example",
        workspace_id="registry-1",
        baseline_version="0",
        baseline_package_sha256=EMPTY_PACKAGE_SHA256,
        evidence_root="urn:example:evidence-root",
        fact_authorities=("fact.authority",),
        decision_authorities=("decision.authority",),
        allowed_actions=REFINERY_STATES,
        semantic_api_contract=REFINERY_CONTRACT,
        promotion_target="industry-registry",
        created_at=T0,
    )


def _context(action, delta, *, envelope=None, binding=None):
    return TransitionContextDTO.create(
        action=action,
        delta_sha256=delta.delta_sha256,
        envelope=envelope or _envelope(action),
        binding=binding or _binding(),
    )


def _phase(name, *, observed=(CAPABILITY,), evidence_sha256="c" * 64):
    return EngagementPhaseDTO.evaluate(
        name,
        required_capabilities=(CAPABILITY,),
        observed_capabilities=observed,
        evidence_sha256=evidence_sha256,
        details={"executed": True},
    )


def _engagement(
    delta,
    *,
    runtime=RUNTIME,
    execution=None,
    execution_receipt_sha256="f" * 64,
    envelope=None,
    binding=None,
):
    envelope = envelope or _envelope("candidate")
    binding = binding or _binding()
    return SemanticEngagementReceipt.create(
        engagement_id="engagement-1",
        envelope=envelope,
        binding=binding,
        runtime_source=runtime,
        execution=execution or _phase("execution"),
        regression=_phase("regression"),
        receipt=_phase("receipt"),
        release=_phase("release"),
        learning=LearningResultDTO(
            status="candidate",
            rationale="The lesson is reusable outside this project.",
            delta_sha256=delta.delta_sha256,
        ),
        execution_receipts=(
            ExecutionReceiptReferenceDTO(
                receipt_sha256=execution_receipt_sha256,
                package_id="semantica.chapter.reference",
                package_version="1",
                package_digest="e" * 64,
            ),
        ),
        created_at=T0,
    )


def _authorization(delta, action, *, actor="decision.authority"):
    decisions = (
        tuple(
            AssetDecisionDTO(
                category=item.category,
                asset_id=item.asset_id,
                operation=item.operation,
                replaces_sha256=item.replaces_sha256,
                verdict="approve",
                reason="Exact retained asset mutation reviewed.",
            )
            for item in delta.assets
            if item.operation in {"replace", "remove"}
        )
        if action == "commit"
        else ()
    )
    return RefineryAuthorizationDTO(
        authorization_id="authorization-{}".format(action),
        action=action,
        actor_id=actor,
        authority=actor,
        package_id=delta.package_id,
        delta_sha256=delta.delta_sha256,
        promotion_target="industry-registry",
        reason="Reviewed against the bound evidence and project authority.",
        source=SOURCE,
        issued_at=T0,
        decisions=decisions,
    )


def _gate(
    gate,
    package_sha256,
    *,
    checks=None,
    observed=(CAPABILITY,),
    runtime=RUNTIME,
    execution_suite_sha256="f" * 64,
    execution_suite_object_sha256="e" * 64,
    transition_context_sha256="c" * 64,
    transition_context_object_sha256="b" * 64,
    provenance_closure_sha256="a" * 64,
    provenance_closure_object_sha256="9" * 64,
):
    check_ids = (
        REGRESSION_REQUIRED_CHECK_IDS
        if gate == "regression"
        else RELEASE_REQUIRED_CHECK_IDS
    )
    return RefineryGateEvidenceDTO.create(
        gate=gate,
        package_sha256=package_sha256,
        execution_suite_sha256=execution_suite_sha256,
        execution_suite_object_sha256=execution_suite_object_sha256,
        transition_context_sha256=transition_context_sha256,
        transition_context_object_sha256=transition_context_object_sha256,
        provenance_closure_sha256=provenance_closure_sha256,
        provenance_closure_object_sha256=provenance_closure_object_sha256,
        runtime_source=runtime,
        required_capabilities=(CAPABILITY,),
        observed_capabilities=observed,
        checks=checks
        or tuple(
            GateCheckDTO(check_id, True, "Derived check passed.", "d" * 64)
            for check_id in check_ids
        ),
        recorded_at=T0,
    )


def _register(tmp_path, delta=None, engagement=None):
    delta = delta or _delta()
    registry = IndustryOntologyRegistry.create(
        tmp_path / "registry", registry_id="registry-1", created_at=T0
    )
    registry.register_candidate(
        delta,
        _envelope("candidate"),
        _binding(),
        engagement or _engagement(delta),
        recorded_at=T0,
    )
    return registry, delta


def _advance_to_release(registry, delta):
    registry.propose(
        delta.delta_sha256,
        context=_context("proposed", delta),
        recorded_at=T0,
    )
    committed = registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
        recorded_at=T0,
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    regression = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    registry.record_regression(
        delta.delta_sha256,
        regression,
        context=_context("regression_passed", delta),
        recorded_at=T0,
    )
    release = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_release_gate", delta),
        gate="release",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    registry.record_release(
        delta.delta_sha256,
        release,
        context=_context("release_complete", delta),
        recorded_at=T0,
    )
    return committed, suite, regression, release


def test_contract_exposes_exact_six_state_and_complete_package_surface():
    capabilities = refinery_capabilities()
    assert capabilities["contract"] == "semantica.ontology.refinery/v1"
    assert REFINERY_CONTRACT == capabilities["contract"]
    assert tuple(capabilities["states"]) == REFINERY_STATES
    assert tuple(capabilities["asset_categories"]) == PACKAGE_ASSET_CATEGORIES
    assert tuple(capabilities["delta_categories"]) == PACKAGE_DELTA_CATEGORIES
    assert tuple(capabilities["book_impacts"]) == BOOK_IMPACTS
    assert tuple(capabilities["case_kinds"]) == CASE_KINDS
    assert capabilities["publication_owned_externally"] is True
    assert "published" not in capabilities["states"]
    assert tuple(capabilities["transition_context_actions"]) == (
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


def test_public_acceptance_factory_owns_complete_executable_payload():
    delta = build_refinery_acceptance_delta(
        package_id="industry.acceptance",
        source_evidence=SOURCE,
        created_by="fact.authority",
        created_at=T0,
    )
    assert delta.package_id == "industry.acceptance"
    assert {item.category for item in delta.assets} == set(PACKAGE_ASSET_CATEGORIES)
    projection = json.loads(delta.contract[0].content_bytes.decode("utf-8"))
    assert projection["provenance_evidence_asset_ids"] == ["source-evidence-binding"]


def test_package_delta_serializes_every_asset_family_and_case_kind():
    delta = _delta()
    payload = delta.as_dict()
    for category in PACKAGE_ASSET_CATEGORIES:
        assert category in payload
        assert payload[category]
    assert {item["case_kind"] for item in payload["cases"]} == set(CASE_KINDS)
    assert payload["book_impact"] == "none"
    assert PackageDelta.from_dict(payload).delta_sha256 == delta.delta_sha256


def test_task_envelope_keeps_kind_intent_and_requested_decision_auditable():
    envelope = _envelope()
    payload = envelope.as_dict()
    assert payload["task_kind"] == "engineering-refinement"
    assert payload["intent"] == "Refine repeated engineering knowledge."
    assert payload["requested_decision"] == (
        "Determine whether the lesson is reusable."
    )
    assert "objective" not in payload
    assert SemanticTaskEnvelope.from_dict(payload).envelope_sha256 == (
        envelope.envelope_sha256
    )


@pytest.mark.parametrize(
    "book_impact", ("none", "vol1-method", "vol2-iso-exemplar", "both")
)
def test_book_impact_is_top_level_validated_and_content_addressed(book_impact):
    first = replace(_delta(), book_impact=book_impact)
    round_trip = PackageDelta.from_dict(first.as_dict())
    assert round_trip.book_impact == book_impact
    assert round_trip.delta_sha256 == first.delta_sha256


def test_invalid_book_impact_is_rejected():
    with pytest.raises(RefineryInputError, match="book_impact"):
        replace(_delta(), book_impact="hidden-in-provenance")


def test_engagement_always_has_five_outputs_and_missing_capability_blocks():
    delta = _delta()
    blocked = _engagement(
        delta,
        execution=_phase("execution", observed=(), evidence_sha256=None),
    )
    payload = blocked.as_dict()
    for output in ("execution", "regression", "receipt", "release", "learning"):
        assert output in payload
    assert blocked.status == "blocked"
    assert "capability.execution.{}".format(CAPABILITY) in blocked.blocked_reasons
    assert "evidence.execution" in blocked.blocked_reasons


def test_engagement_phase_fields_have_lossless_round_trip():
    phase = _phase("execution")
    assert tuple(phase.__dataclass_fields__) == (
        "name",
        "status",
        "required_capabilities",
        "observed_capabilities",
        "evidence_sha256",
        "details_json",
    )
    assert EngagementPhaseDTO.from_dict(phase.as_dict()) == phase


def test_blocked_engagement_is_recordable_but_cannot_become_candidate(tmp_path):
    delta = _delta()
    blocked = _engagement(
        delta,
        runtime=RuntimeSourceIdentityDTO("", "", ""),
    )
    registry = IndustryOntologyRegistry.create(
        tmp_path / "registry", registry_id="registry-1", created_at=T0
    )
    assert registry.record_engagement(_envelope(), _binding(), blocked)
    with pytest.raises(RefineryGateError, match="complete semantic engagement"):
        registry.register_candidate(
            delta, _envelope(), _binding(), blocked, recorded_at=T0
        )


def test_full_lifecycle_is_content_addressed_authorized_and_resolvable(tmp_path):
    registry, delta = _register(tmp_path)
    committed, suite, regression, release = _advance_to_release(registry, delta)
    assert committed.state == "committed"
    assert len(committed.package_sha256) == 64
    assert suite.status == "complete"
    assert tuple(item.check_id for item in regression.checks) == (
        REGRESSION_REQUIRED_CHECK_IDS
    )
    assert tuple(item.check_id for item in release.checks) == RELEASE_REQUIRED_CHECK_IDS
    promoted = registry.promote(
        delta.delta_sha256,
        _authorization(delta, "promote"),
        context=_context("promoted", delta),
        recorded_at=T0,
    )
    assert promoted.package_sha256 == committed.package_sha256
    assert registry.status(delta.delta_sha256).state == "promoted"
    assert tuple(item["state"] for item in registry.history(delta.delta_sha256)) == (
        REFINERY_STATES
    )
    assert registry.resolve_package("industry.example") == promoted
    assert registry.read_asset("industry.example", "ontology-core") == (
        b"@prefix owl: <http://www.w3.org/2002/07/owl#> .\n"
        b"<urn:industry:example> a owl:Ontology .\n"
    )
    assert list((tmp_path / "registry" / "packages").iterdir())[0].name != (
        "industry.example"
    )


def test_transition_context_is_exact_delta_task_binding_and_required(tmp_path):
    registry, delta = _register(tmp_path)
    with pytest.raises(TypeError, match="context"):
        registry.propose(delta.delta_sha256)
    with pytest.raises(RefineryGateError, match="action must be exactly proposed"):
        registry.propose(
            delta.delta_sha256,
            context=_context("committed", delta),
        )
    wrong_delta = replace(delta, target_version="1.0.1")
    with pytest.raises(RefineryGateError, match="exact delta"):
        registry.propose(
            delta.delta_sha256,
            context=TransitionContextDTO.create(
                action="proposed",
                delta_sha256=wrong_delta.delta_sha256,
                envelope=_envelope("proposed"),
                binding=_binding(),
            ),
        )
    wrong_workspace = replace(_binding(), workspace_id="registry-2")
    with pytest.raises(RefineryGateError, match="retained current binding|workspace"):
        registry.propose(
            delta.delta_sha256,
            context=_context("proposed", delta, binding=wrong_workspace),
        )
    wrong_package = replace(_binding(), package_id="industry.other")
    with pytest.raises(RefineryGateError, match="retained current binding|package"):
        registry.propose(
            delta.delta_sha256,
            context=_context("proposed", delta, binding=wrong_package),
        )
    wrong_binding = replace(_binding(), binding_id="binding-2")
    with pytest.raises(RefineryGateError, match="retained current binding"):
        registry.propose(
            delta.delta_sha256,
            context=_context("proposed", delta, binding=wrong_binding),
        )
    with pytest.raises(RefineryInputError, match="project/domain"):
        TransitionContextDTO.create(
            action="proposed",
            delta_sha256=delta.delta_sha256,
            envelope=_envelope("proposed", project_id="wrong-project"),
            binding=_binding(),
        )
    with pytest.raises(RefineryInputError, match="outside.*evidence_root"):
        TransitionContextDTO.create(
            action="proposed",
            delta_sha256=delta.delta_sha256,
            envelope=_envelope(
                "proposed",
                evidence=(replace(SOURCE, uri="urn:outside:evidence"),),
            ),
            binding=_binding(),
        )
    payload = _context("proposed", delta).as_dict()
    payload["shadow"] = True
    with pytest.raises(RefineryInputError, match="unknown fields"):
        TransitionContextDTO.from_dict(payload)


def test_release_derivation_requires_recorded_regression_and_closure_order(tmp_path):
    registry, delta = _register(tmp_path)
    registry.propose(delta.delta_sha256, context=_context("proposed", delta))
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    with pytest.raises(RefineryStateError, match="regression_passed"):
        registry.gate_evidence(
            delta.delta_sha256,
            context=_context("derive_release_gate", delta),
            gate="release",
            execution_suite_sha256=suite.suite_sha256,
            recorded_at=T0,
        )
    regression = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    registry.record_regression(
        delta.delta_sha256,
        regression,
        context=_context("regression_passed", delta),
        recorded_at=T0,
    )
    release = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_release_gate", delta),
        gate="release",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    closure = ProvenanceClosureDTO.from_dict(
        registry._get_json_object(release.provenance_closure_object_sha256)
    )
    assert tuple(item[0] for item in closure.transition_contexts) == (
        "candidate",
        "proposed",
        "committed",
        "execute_candidate",
        "derive_regression_gate",
        "regression_passed",
        "derive_release_gate",
    )
    for action, context_sha, object_sha in closure.transition_contexts:
        replayed = registry._load_transition_context(context_sha, object_sha)
        assert replayed.action == action
        assert replayed.delta_sha256 == delta.delta_sha256


def test_context_cas_tamper_is_detected_after_restart(tmp_path):
    registry, delta = _register(tmp_path)
    registry.propose(
        delta.delta_sha256,
        context=_context("proposed", delta),
        recorded_at=T0,
    )
    event = registry.history(delta.delta_sha256)[-1]
    object_sha = event["payload"]["transition_context_object_sha256"]
    path = registry._object_path(object_sha)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["action"] = "committed"
    path.write_text(json.dumps(value), encoding="utf-8")
    reopened = IndustryOntologyRegistry(tmp_path / "registry")
    with pytest.raises(RefineryWorkspaceError, match="hash mismatch"):
        reopened.status(delta.delta_sha256)


def test_unrelated_provenance_asset_cannot_satisfy_source_binding(tmp_path):
    delta = _delta()
    provenance = []
    for item in delta.provenance:
        if item.asset_id == "source-evidence-binding":
            provenance.append(
                _asset(
                    "provenance",
                    "source-evidence-binding",
                    content=canonical_json(
                        {
                            "schema_version": "1.0",
                            "kind": "semantica.source-evidence-binding",
                            "source_evidence": [
                                {**SOURCE.as_dict(), "sha256": "8" * 64}
                            ],
                        }
                    ),
                    media_type="application/json",
                )
            )
        else:
            provenance.append(item)
    delta = replace(delta, provenance=tuple(provenance))
    registry, delta = _register(tmp_path, delta=delta)
    registry.propose(delta.delta_sha256, context=_context("proposed", delta))
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
    )
    with pytest.raises(RefineryGateError, match="exactly bind delta source_evidence"):
        registry.execute_candidate(
            delta.delta_sha256,
            context=_context("execute_candidate", delta),
            runtime_source=RUNTIME,
            created_at=T0,
        )


def test_immutable_base_prior_cqs_and_cases_cannot_be_faked_by_target_labels(
    tmp_path,
):
    registry, v1 = _register(tmp_path)
    _advance_to_release(registry, v1)
    promoted = registry.promote(
        v1.delta_sha256,
        _authorization(v1, "promote"),
        context=_context("promoted", v1),
        recorded_at=T0,
    )
    v2 = _v2_fake_prior_delta(v1, promoted.package_sha256)
    binding = replace(
        _binding(),
        baseline_version=v1.target_version,
        baseline_package_sha256=promoted.package_sha256,
    )
    candidate_envelope = _envelope("candidate")
    engagement = _engagement(
        v2,
        envelope=candidate_envelope,
        binding=binding,
    )
    registry.register_candidate(
        v2,
        candidate_envelope,
        binding,
        engagement,
        recorded_at=T0,
    )
    registry.propose(
        v2.delta_sha256,
        context=_context("proposed", v2, binding=binding),
        recorded_at=T0,
    )
    registry.commit(
        v2.delta_sha256,
        _authorization(v2, "commit"),
        context=_context("committed", v2, binding=binding),
        recorded_at=T0,
    )
    suite = registry.execute_candidate(
        v2.delta_sha256,
        context=_context("execute_candidate", v2, binding=binding),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    assert dict(suite.required_prior_cq_bindings) == {
        "cq-current": sha256_text(
            canonical_json(
                {
                    "id": "cq-current",
                    "question": "Can the current reusable case be retrieved?",
                    "scenario_ids": ["scenario-current"],
                }
            )
        ),
        "cq-prior": sha256_text(
            canonical_json(
                {
                    "id": "cq-prior",
                    "question": "Does the prior-release case still execute?",
                    "scenario_ids": ["scenario-prior"],
                }
            )
        ),
    }
    regression = registry.gate_evidence(
        v2.delta_sha256,
        context=_context("derive_regression_gate", v2, binding=binding),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    checks = {item.check_id: item for item in regression.checks}
    assert checks["cq.prior"].passed is False
    assert checks["case.prior_release"].passed is False


def test_explicit_authority_and_exact_transition_are_fail_closed(tmp_path):
    registry, delta = _register(tmp_path)
    with pytest.raises(RefineryStateError):
        registry.commit(
            delta.delta_sha256,
            _authorization(delta, "commit"),
            context=_context("committed", delta),
        )
    registry.propose(delta.delta_sha256, context=_context("proposed", delta))
    with pytest.raises(RefineryGateError, match="decision authority"):
        registry.commit(
            delta.delta_sha256,
            _authorization(delta, "commit", actor="unbound.actor"),
            context=_context("committed", delta),
        )
    assert registry.status(delta.delta_sha256).state == "proposed"


def test_binding_allowed_actions_are_a_nonempty_ordered_lifecycle_prefix():
    assert replace(_binding(), allowed_actions=("candidate", "proposed"))
    for actions in (
        (),
        ("proposed",),
        ("candidate", "committed"),
        ("candidate", "proposed", "candidate"),
    ):
        with pytest.raises(RefineryInputError, match="allowed_actions"):
            replace(_binding(), allowed_actions=actions)


def test_asset_decisions_belong_only_to_exact_commit_mutations(tmp_path):
    registry, delta = _register(tmp_path)
    registry.propose(
        delta.delta_sha256,
        context=_context("proposed", delta),
        recorded_at=T0,
    )
    unmatched = AssetDecisionDTO(
        category="ontology",
        asset_id="ontology-core",
        operation="replace",
        replaces_sha256="1" * 64,
        verdict="approve",
        reason="This does not match the add-only delta.",
    )
    with pytest.raises(RefineryGateError, match="unmatched asset decision"):
        registry.commit(
            delta.delta_sha256,
            replace(_authorization(delta, "commit"), decisions=(unmatched,)),
            context=_context("committed", delta),
            recorded_at=T0,
        )
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
        recorded_at=T0,
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    regression = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    registry.record_regression(
        delta.delta_sha256,
        regression,
        context=_context("regression_passed", delta),
        recorded_at=T0,
    )
    release = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_release_gate", delta),
        gate="release",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    registry.record_release(
        delta.delta_sha256,
        release,
        context=_context("release_complete", delta),
        recorded_at=T0,
    )
    with pytest.raises(RefineryGateError, match="must not contain"):
        registry.promote(
            delta.delta_sha256,
            replace(_authorization(delta, "promote"), decisions=(unmatched,)),
            context=_context("promoted", delta),
            recorded_at=T0,
        )


def test_industry_package_id_cannot_collide_with_builtin_registry(tmp_path):
    package_id = "semantica.chapter_packages.vol1.ch03"
    delta = _delta(package_id=package_id)
    binding = replace(_binding(), package_id=package_id)
    engagement = _engagement(delta, binding=binding)
    registry = IndustryOntologyRegistry.create(
        tmp_path / "registry", registry_id="registry-1", created_at=T0
    )
    with pytest.raises(RefineryGateError, match="collides with a built-in"):
        registry.register_candidate(
            delta, _envelope(), binding, engagement, recorded_at=T0
        )


def test_failed_or_capability_incomplete_gate_does_not_advance(tmp_path):
    registry, delta = _register(tmp_path)
    registry.propose(delta.delta_sha256, context=_context("proposed", delta))
    committed = registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    derived = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    failed = _gate(
        "regression",
        committed.package_sha256,
        execution_suite_sha256=suite.suite_sha256,
        execution_suite_object_sha256=derived.execution_suite_object_sha256,
        transition_context_sha256=derived.transition_context_sha256,
        transition_context_object_sha256=(derived.transition_context_object_sha256),
        provenance_closure_sha256=derived.provenance_closure_sha256,
        provenance_closure_object_sha256=(derived.provenance_closure_object_sha256),
        checks=tuple(
            GateCheckDTO(
                check_id,
                check_id != "cq.prior",
                "Prior CQ regressed." if check_id == "cq.prior" else "passed",
                "d" * 64,
            )
            for check_id in REGRESSION_REQUIRED_CHECK_IDS
        ),
    )
    assert failed.status == "blocked"
    with pytest.raises(RefineryGateError, match="evidence is blocked"):
        registry.record_regression(
            delta.delta_sha256,
            failed,
            context=_context("regression_passed", delta),
        )
    missing = _gate(
        "regression",
        committed.package_sha256,
        observed=(),
        execution_suite_sha256=suite.suite_sha256,
        execution_suite_object_sha256=derived.execution_suite_object_sha256,
        transition_context_sha256=derived.transition_context_sha256,
        transition_context_object_sha256=(derived.transition_context_object_sha256),
        provenance_closure_sha256=derived.provenance_closure_sha256,
        provenance_closure_object_sha256=(derived.provenance_closure_object_sha256),
    )
    assert missing.status == "blocked"
    with pytest.raises(RefineryGateError, match="evidence is blocked"):
        registry.record_regression(
            delta.delta_sha256,
            missing,
            context=_context("regression_passed", delta),
        )
    assert registry.status(delta.delta_sha256).state == "committed"


def test_execution_projection_requires_all_named_registry_and_rights_assets(tmp_path):
    delta = _delta(omit=("provenance",))
    registry, delta = _register(tmp_path, delta=delta)
    registry.propose(delta.delta_sha256, context=_context("proposed", delta))
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
    )
    with pytest.raises(RefineryGateError, match="projection|registries"):
        registry.execute_candidate(
            delta.delta_sha256,
            context=_context("execute_candidate", delta),
            runtime_source=RUNTIME,
            created_at=T0,
        )
    assert registry.status(delta.delta_sha256).state == "committed"


def test_package_id_never_becomes_a_path_and_unknown_ids_do_not_read(tmp_path):
    registry = IndustryOntologyRegistry.create(
        tmp_path / "registry", registry_id="registry-1", created_at=T0
    )
    with pytest.raises(IndustryPackageNotFoundError):
        registry.resolve_package("unknown.package")
    with pytest.raises(RefineryInputError, match="opaque"):
        replace(_binding(), package_id="../../outside")
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    assert outside.read_text(encoding="utf-8") == "secret"


def test_adapter_inputs_require_hashed_evidence_and_exact_semantic_api():
    payload = _envelope().as_dict()
    payload["evidence"] = ["urn:example:unhashed-reference"]
    payload.pop("envelope_sha256")
    with pytest.raises(RefineryInputError, match="entries must be mappings"):
        SemanticTaskEnvelope.from_dict(payload)
    with pytest.raises(RefineryInputError, match="semantic_api_contract"):
        replace(_binding(), semantic_api_contract="semantica.ontology.refinery/v0")


def test_runtime_source_requires_exact_lowercase_git_commit():
    delta = _delta()
    for commit in ("runtime-commit-1", "A" * 40, "1" * 39, "1" * 41):
        engagement = _engagement(
            delta,
            runtime=RuntimeSourceIdentityDTO(commit, "b" * 64, "0.6.5+oe.2"),
        )
        assert engagement.status == "blocked"
        assert "runtime_source_identity" in engagement.blocked_reasons


def test_native_boundary_enforces_evidence_root_for_task_delta_and_authority(
    tmp_path,
):
    outside = replace(SOURCE, uri="urn:outside:evidence")
    delta = _delta()
    envelope = replace(_envelope(), evidence=(outside,))
    engagement = SemanticEngagementReceipt.create(
        engagement_id="engagement-outside",
        envelope=envelope,
        binding=_binding(),
        runtime_source=RUNTIME,
        execution=_phase("execution"),
        regression=_phase("regression"),
        receipt=_phase("receipt"),
        release=_phase("release"),
        learning=LearningResultDTO(
            "candidate", "Candidate from outside evidence.", delta.delta_sha256
        ),
        execution_receipts=(
            ExecutionReceiptReferenceDTO(
                "d" * 64, "semantica.chapter.reference", "1", "e" * 64
            ),
        ),
        created_at=T0,
    )
    registry = IndustryOntologyRegistry.create(
        tmp_path / "registry-task", registry_id="registry-1", created_at=T0
    )
    with pytest.raises(RefineryGateError, match="outside binding evidence_root"):
        registry.register_candidate(delta, envelope, _binding(), engagement)

    outside_delta = replace(delta, source_evidence=(outside,))
    outside_engagement = _engagement(outside_delta)
    registry = IndustryOntologyRegistry.create(
        tmp_path / "registry-delta", registry_id="registry-1", created_at=T0
    )
    with pytest.raises(RefineryGateError, match="outside binding evidence_root"):
        registry.register_candidate(
            outside_delta, _envelope(), _binding(), outside_engagement
        )

    registry, delta = _register(tmp_path / "authority")
    registry.propose(delta.delta_sha256, context=_context("proposed", delta))
    with pytest.raises(RefineryGateError, match="authorization evidence URI"):
        registry.commit(
            delta.delta_sha256,
            replace(_authorization(delta, "commit"), source=outside),
            context=_context("committed", delta),
        )


def test_public_dto_parsers_reject_shadow_fields():
    delta = _delta()
    engagement = _engagement(delta)
    authorization = _authorization(delta, "commit")
    gate = _gate("regression", "9" * 64)
    examples = (
        (SourceEvidenceDTO.from_dict, SOURCE.as_dict()),
        (SemanticTaskEnvelope.from_dict, _envelope().as_dict()),
        (ProjectOntologyBinding.from_dict, _binding().as_dict()),
        (SemanticEngagementReceipt.from_dict, engagement.as_dict()),
        (PackageDelta.from_dict, delta.as_dict()),
        (RefineryAuthorizationDTO.from_dict, authorization.as_dict()),
        (RefineryGateEvidenceDTO.from_dict, gate.as_dict()),
    )
    for parser, original in examples:
        shadowed = dict(original)
        shadowed["shadow_semantics"] = {"allow": True}
        with pytest.raises(RefineryInputError, match="unknown fields"):
            parser(shadowed)


def test_gate_runtime_and_release_suite_must_match_bound_execution(tmp_path):
    delta = _delta()
    registry, delta = _register(
        tmp_path,
        delta=delta,
        engagement=_engagement(delta, execution_receipt_sha256="7" * 64),
    )
    registry.propose(delta.delta_sha256, context=_context("proposed", delta))
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
    )
    other_runtime = RuntimeSourceIdentityDTO("2" * 40, "b" * 64, "0.6.5+oe.2")
    other_suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=other_runtime,
        created_at=T0,
    )
    other_gate = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=other_suite.suite_sha256,
        recorded_at=T0,
    )
    with pytest.raises(RefineryGateError, match="differs from engagement"):
        registry.record_regression(
            delta.delta_sha256,
            other_gate,
            context=_context("regression_passed", delta),
        )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    regression = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    registry.record_regression(
        delta.delta_sha256,
        regression,
        context=_context("regression_passed", delta),
    )
    second_suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at="2026-08-19T00:00:01Z",
    )
    second_release = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_release_gate", delta),
        gate="release",
        execution_suite_sha256=second_suite.suite_sha256,
        recorded_at="2026-08-19T00:00:01Z",
    )
    with pytest.raises(RefineryGateError, match="differs from regression suite"):
        registry.record_release(
            delta.delta_sha256,
            second_release,
            context=_context("release_complete", delta),
        )


def test_current_pointer_tampering_is_detected_by_status(tmp_path):
    registry, delta = _register(tmp_path)
    pointer_path = (
        tmp_path / "registry" / "refinements" / delta.delta_sha256 / "current.json"
    )
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer["state"] = "proposed"
    pointer_path.write_text(json.dumps(pointer), encoding="utf-8")
    with pytest.raises(RefineryWorkspaceError, match="differs from event"):
        registry.status(delta.delta_sha256)


def test_immutable_event_and_object_tampering_is_detected(tmp_path):
    registry, delta = _register(tmp_path)
    event = next(
        (tmp_path / "registry" / "refinements" / delta.delta_sha256 / "events").glob(
            "*.json"
        )
    )
    value = json.loads(event.read_text(encoding="utf-8"))
    value["payload"]["engagement_status"] = "complete-but-tampered"
    event.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RefineryWorkspaceError, match="hash mismatch|integrity"):
        registry.history(delta.delta_sha256)


def test_stable_facade_runs_candidate_commit_verify_and_promotion(tmp_path):
    delta = _delta()
    envelope = _envelope()
    binding = _binding()
    engagement = _engagement(delta)
    registry = IndustryOntologyRegistry.create(
        tmp_path / "registry", registry_id="registry-1", created_at=T0
    )
    assert (
        open_engagement(
            registry, envelope=envelope, binding=binding, receipt=engagement
        )
        == engagement
    )
    assert (
        propose_candidate(
            registry,
            delta=delta,
            envelope=envelope,
            binding=binding,
            engagement=engagement,
            context=_context("proposed", delta),
            recorded_at=T0,
        ).state
        == "proposed"
    )
    commit_candidate(
        registry,
        delta_sha256=delta.delta_sha256,
        authorization=_authorization(delta, "commit"),
        context=_context("committed", delta),
        recorded_at=T0,
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    regression = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    assert (
        verify_candidate(
            registry,
            delta_sha256=delta.delta_sha256,
            execution_suite_sha256=suite.suite_sha256,
            regression_evidence=regression,
            regression_context=_context("regression_passed", delta),
            release_derivation_context=_context("derive_release_gate", delta),
            release_context=_context("release_complete", delta),
            recorded_at=T0,
        ).state.state
        == "release_complete"
    )
    promoted = promote_candidate(
        registry,
        delta_sha256=delta.delta_sha256,
        authorization=_authorization(delta, "promote"),
        context=_context("promoted", delta),
        recorded_at=T0,
    )
    assert promoted.package_id == delta.package_id
    assert len(history(registry, delta_sha256=delta.delta_sha256)) == 6


def test_propose_facade_retry_requires_exact_recorded_context(tmp_path):
    registry, delta = _register(tmp_path)
    candidate_envelope = _envelope("candidate")
    binding = _binding()
    engagement = _engagement(delta)
    proposed_context = _context("proposed", delta)
    proposed = propose_candidate(
        registry,
        delta=delta,
        envelope=candidate_envelope,
        binding=binding,
        engagement=engagement,
        context=proposed_context,
        recorded_at=T0,
    )
    assert (
        propose_candidate(
            registry,
            delta=delta,
            envelope=candidate_envelope,
            binding=binding,
            engagement=engagement,
            context=proposed_context,
            recorded_at=T0,
        )
        == proposed
    )
    with pytest.raises(RefineryGateError, match="differs from proposed event"):
        propose_candidate(
            registry,
            delta=delta,
            envelope=candidate_envelope,
            binding=binding,
            engagement=engagement,
            context=_context(
                "proposed",
                delta,
                envelope=_envelope("proposed", task_id="different-retry-task"),
            ),
            recorded_at=T0,
        )


def test_invalid_event_timestamp_is_rejected_before_any_mutation(tmp_path):
    registry, delta = _register(tmp_path)
    registry.propose(
        delta.delta_sha256,
        context=_context("proposed", delta),
        recorded_at=T0,
    )
    event_dir = tmp_path / "registry" / "refinements" / delta.delta_sha256 / "events"
    pointer_path = event_dir.parent / "current.json"
    before_events = tuple(sorted(path.name for path in event_dir.iterdir()))
    before_pointer = pointer_path.read_bytes()
    before_objects = tuple(
        sorted(
            path.relative_to(tmp_path / "registry" / "objects").as_posix()
            for path in (tmp_path / "registry" / "objects").rglob("*")
            if path.is_file()
        )
    )
    with pytest.raises(RefineryInputError, match="ISO 8601"):
        registry.commit(
            delta.delta_sha256,
            _authorization(delta, "commit"),
            context=_context("committed", delta),
            recorded_at="not-a-time",
        )
    assert tuple(sorted(path.name for path in event_dir.iterdir())) == before_events
    assert pointer_path.read_bytes() == before_pointer
    assert (
        tuple(
            sorted(
                path.relative_to(tmp_path / "registry" / "objects").as_posix()
                for path in (tmp_path / "registry" / "objects").rglob("*")
                if path.is_file()
            )
        )
        == before_objects
    )


def test_refinement_event_torn_write_recovers_from_bound_pending_transaction(
    tmp_path, monkeypatch
):
    registry, delta = _register(tmp_path)
    original = refinery_module._atomic_replace

    def interrupt_current(path, payload):
        if path.name == "current.json":
            raise OSError("simulated pointer interruption")
        return original(path, payload)

    monkeypatch.setattr(refinery_module, "_atomic_replace", interrupt_current)
    with pytest.raises(OSError, match="pointer interruption"):
        registry.propose(
            delta.delta_sha256,
            context=_context("proposed", delta),
            recorded_at=T0,
        )
    refinement = tmp_path / "registry" / "refinements" / delta.delta_sha256
    assert (refinement / "pending-event.json").is_file()
    assert len(tuple((refinement / "events").glob("*.json"))) == 2
    monkeypatch.setattr(refinery_module, "_atomic_replace", original)
    assert registry.status(delta.delta_sha256).state == "proposed"
    assert not (refinement / "pending-event.json").exists()


def test_workspace_and_cas_reject_symlink_escape(tmp_path):
    workspace = tmp_path / "registry"
    registry = IndustryOntologyRegistry.create(
        workspace, registry_id="registry-1", created_at=T0
    )
    alias = tmp_path / "registry-alias"
    alias.symlink_to(workspace, target_is_directory=True)
    with pytest.raises(RefineryWorkspaceError, match="non-symlink"):
        IndustryOntologyRegistry(alias)

    outside = tmp_path / "outside-cas"
    outside.mkdir()
    cas_root = workspace / "objects" / "sha256"
    cas_root.rmdir()
    cas_root.symlink_to(outside, target_is_directory=True)
    delta = _delta()
    with pytest.raises(RefineryWorkspaceError, match="symlink"):
        registry.register_candidate(
            delta, _envelope(), _binding(), _engagement(delta), recorded_at=T0
        )
    assert tuple(outside.iterdir()) == ()


def test_both_verification_stages_require_every_manifest_asset_object(tmp_path):
    registry, delta = _register(tmp_path)
    registry.propose(
        delta.delta_sha256,
        context=_context("proposed", delta),
        recorded_at=T0,
    )
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
        recorded_at=T0,
    )
    digest = delta.ontology[0].sha256
    registry._object_path(digest).unlink()
    with pytest.raises(RefineryWorkspaceError, match="missing"):
        registry.execute_candidate(
            delta.delta_sha256,
            context=_context("execute_candidate", delta),
            runtime_source=RUNTIME,
            created_at=T0,
        )
    assert registry.status(delta.delta_sha256).state == "committed"


def test_suite_retains_actual_cq_and_case_io_from_runner_outputs(tmp_path):
    registry, delta = _register(tmp_path)
    registry.propose(
        delta.delta_sha256,
        context=_context("proposed", delta),
        recorded_at=T0,
    )
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
        recorded_at=T0,
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    runs = {item.scenario_id: item for item in suite.runs}
    assert runs["scenario-current"].cq_ids == ("cq-current",)
    assert runs["scenario-prior"].cq_ids == ("cq-prior",)
    assert runs["scenario-negative"].cq_ids == ()
    assert {
        (kind, asset_id) for kind, asset_id, _ in runs["scenario-current"].case_assets
    } == {("positive", "case-positive"), ("negative", "case-negative")}


def test_suite_replay_rejects_tampered_full_runner_result(tmp_path):
    registry, delta = _register(tmp_path)
    registry.propose(
        delta.delta_sha256,
        context=_context("proposed", delta),
        recorded_at=T0,
    )
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
        recorded_at=T0,
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    result_path = registry._object_path(suite.runs[0].run_result_object_sha256)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["cq_report"]["payload"]["competency_question_ids"] = ["forged-cq"]
    result_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RefineryWorkspaceError, match="hash mismatch"):
        registry.gate_evidence(
            delta.delta_sha256,
            context=_context("derive_regression_gate", delta),
            gate="regression",
            execution_suite_sha256=suite.suite_sha256,
            recorded_at=T0,
        )


def test_verify_facade_retries_release_only_with_exact_recorded_regression(
    tmp_path,
):
    registry, delta = _register(tmp_path)
    registry.propose(
        delta.delta_sha256,
        context=_context("proposed", delta),
        recorded_at=T0,
    )
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
        recorded_at=T0,
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    regression = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    regression_context = _context("regression_passed", delta)
    release_derivation_context = _context("derive_release_gate", delta)
    release_context = _context("release_complete", delta)
    with pytest.raises(RefineryGateError, match="requested execution suite"):
        verify_candidate(
            registry,
            delta_sha256=delta.delta_sha256,
            execution_suite_sha256="8" * 64,
            regression_evidence=regression,
            regression_context=regression_context,
            release_derivation_context=release_derivation_context,
            release_context=release_context,
            recorded_at=T0,
        )
    assert registry.status(delta.delta_sha256).state == "committed"
    verified = verify_candidate(
        registry,
        delta_sha256=delta.delta_sha256,
        execution_suite_sha256=suite.suite_sha256,
        regression_evidence=regression,
        regression_context=regression_context,
        release_derivation_context=release_derivation_context,
        release_context=release_context,
        recorded_at=T0,
    )
    assert verified.state.state == "release_complete"
    assert verified.release_evidence.gate == "release"
    with pytest.raises(RefineryInputError, match="restart must load"):
        verify_candidate(
            registry,
            delta_sha256=delta.delta_sha256,
            execution_suite_sha256=suite.suite_sha256,
            regression_evidence=regression,
            regression_context=_context(
                "regression_passed",
                delta,
                envelope=_envelope("regression_passed", task_id="different-retry-task"),
            ),
            release_derivation_context=release_derivation_context,
            release_context=release_context,
            recorded_at=T0,
        )
    reopened = IndustryOntologyRegistry(tmp_path / "registry")
    replayed = verify_candidate(
        reopened,
        delta_sha256=delta.delta_sha256,
        execution_suite_sha256=suite.suite_sha256,
        regression_evidence=None,
        regression_context=None,
        release_derivation_context=_context("derive_release_gate", delta),
        release_context=_context("release_complete", delta),
        recorded_at=T0,
    )
    assert replayed.verification_sha256 == verified.verification_sha256
    with pytest.raises(RefineryGateError, match="release transition context differs"):
        verify_candidate(
            reopened,
            delta_sha256=delta.delta_sha256,
            execution_suite_sha256=suite.suite_sha256,
            regression_evidence=None,
            regression_context=None,
            release_derivation_context=_context(
                "derive_release_gate",
                delta,
                envelope=_envelope(
                    "derive_release_gate", task_id="different-release-retry-task"
                ),
            ),
            release_context=release_context,
            recorded_at=T0,
        )
    with pytest.raises(RefineryGateError, match="release transition context differs"):
        verify_candidate(
            reopened,
            delta_sha256=delta.delta_sha256,
            execution_suite_sha256=suite.suite_sha256,
            regression_evidence=None,
            regression_context=None,
            release_derivation_context=release_derivation_context,
            release_context=_context(
                "release_complete",
                delta,
                envelope=_envelope(
                    "release_complete", task_id="different-release-event-task"
                ),
            ),
            recorded_at=T0,
        )


def test_verify_facade_recovers_after_crash_between_regression_and_release(
    tmp_path, monkeypatch
):
    registry, delta = _register(tmp_path)
    registry.propose(delta.delta_sha256, context=_context("proposed", delta))
    registry.commit(
        delta.delta_sha256,
        _authorization(delta, "commit"),
        context=_context("committed", delta),
    )
    suite = registry.execute_candidate(
        delta.delta_sha256,
        context=_context("execute_candidate", delta),
        runtime_source=RUNTIME,
        created_at=T0,
    )
    regression = registry.gate_evidence(
        delta.delta_sha256,
        context=_context("derive_regression_gate", delta),
        gate="regression",
        execution_suite_sha256=suite.suite_sha256,
        recorded_at=T0,
    )
    original = registry.gate_evidence

    def crash_before_release(*args, **kwargs):
        if kwargs.get("gate") == "release":
            raise RuntimeError("simulated crash after regression")
        return original(*args, **kwargs)

    monkeypatch.setattr(registry, "gate_evidence", crash_before_release)
    with pytest.raises(RuntimeError, match="after regression"):
        verify_candidate(
            registry,
            delta_sha256=delta.delta_sha256,
            execution_suite_sha256=suite.suite_sha256,
            regression_evidence=regression,
            regression_context=_context("regression_passed", delta),
            release_derivation_context=_context("derive_release_gate", delta),
            release_context=_context("release_complete", delta),
            recorded_at=T0,
        )
    assert registry.status(delta.delta_sha256).state == "regression_passed"

    reopened = IndustryOntologyRegistry(tmp_path / "registry")
    recovered = verify_candidate(
        reopened,
        delta_sha256=delta.delta_sha256,
        execution_suite_sha256=suite.suite_sha256,
        regression_evidence=None,
        regression_context=None,
        release_derivation_context=_context("derive_release_gate", delta),
        release_context=_context("release_complete", delta),
        recorded_at=T0,
    )
    assert recovered.state.state == "release_complete"
    assert recovered.release_evidence.status == "complete"


def test_promotion_recovers_trailing_registry_event_and_remains_no_overwrite(
    tmp_path, monkeypatch
):
    registry, delta = _register(tmp_path)
    _advance_to_release(registry, delta)
    authorization = _authorization(delta, "promote")
    original = refinery_module._atomic_replace

    def interrupt_registry(path, payload):
        if path.name == "registry.json":
            raise OSError("simulated registry pointer interruption")
        return original(path, payload)

    monkeypatch.setattr(refinery_module, "_atomic_replace", interrupt_registry)
    with pytest.raises(RefineryWorkspaceError, match="publication is incomplete"):
        registry.promote(
            delta.delta_sha256,
            authorization,
            context=_context("promoted", delta),
            recorded_at=T0,
        )
    with pytest.raises(RefineryWorkspaceError, match="event count"):
        registry.status(delta.delta_sha256)
    monkeypatch.setattr(refinery_module, "_atomic_replace", original)
    promoted = registry.promote(
        delta.delta_sha256,
        authorization,
        context=_context("promoted", delta),
        recorded_at=T0,
    )
    assert registry.status(delta.delta_sha256).state == "promoted"
    assert registry.resolve_package(delta.package_id) == promoted
    assert len(tuple((tmp_path / "registry" / "registry-events").glob("*.json"))) == 1
    with pytest.raises(RefineryGateError, match="authorization"):
        registry.promote(
            delta.delta_sha256,
            replace(authorization, authorization_id="different-retry"),
            context=_context("promoted", delta),
            recorded_at=T0,
        )


def test_promoted_package_runs_from_registry_after_process_restart(tmp_path):
    registry, delta = _register(tmp_path)
    _, suite, _, _ = _advance_to_release(registry, delta)
    promoted = registry.promote(
        delta.delta_sha256,
        _authorization(delta, "promote"),
        context=_context("promoted", delta),
        recorded_at=T0,
    )
    assert promoted.subject_execution_suite_sha256 == suite.suite_sha256
    assert "execution_receipt_sha256" not in promoted.as_dict()

    reopened = IndustryOntologyRegistry(tmp_path / "registry")
    runner = SemanticPackageRunner()
    result = runner.run_registry(
        reopened,
        delta.package_id,
        "scenario-current",
        runtime_commit=RUNTIME.runtime_commit,
        runtime_artifact_sha256=RUNTIME.runtime_artifact_sha256,
        runtime_version=RUNTIME.runtime_version,
        created_at=T0,
    )
    assert result.status == "passed"
    assert result.package_id == delta.package_id
    assert result.package_version == delta.target_version
    assert runner.verify(result, checked_at=T0).status == "complete"


def test_run_registry_rejects_builtin_id_before_industry_resolution(tmp_path):
    registry = IndustryOntologyRegistry.create(
        tmp_path / "registry", registry_id="registry-1", created_at=T0
    )
    with pytest.raises(ValueError, match="collides with a built-in"):
        SemanticPackageRunner().run_registry(
            registry,
            "semantica.chapter_packages.vol1.ch03",
            "OE-V1-CH03-SCN-CQ-ACCEPTANCE-001",
        )


def test_promotion_reuses_only_exact_orphan_version_record(tmp_path, monkeypatch):
    registry, delta = _register(tmp_path)
    _advance_to_release(registry, delta)
    authorization = _authorization(delta, "promote")
    original = refinery_module._write_new

    def interrupt_registry_event(path, payload):
        if path.parent.name == "registry-events":
            raise OSError("simulated registry event interruption")
        return original(path, payload)

    monkeypatch.setattr(refinery_module, "_write_new", interrupt_registry_event)
    with pytest.raises(RefineryWorkspaceError, match="publication is incomplete"):
        registry.promote(
            delta.delta_sha256,
            authorization,
            context=_context("promoted", delta),
            recorded_at=T0,
        )
    monkeypatch.setattr(refinery_module, "_write_new", original)
    promoted = registry.promote(
        delta.delta_sha256,
        authorization,
        context=_context("promoted", delta),
        recorded_at=T0,
    )
    assert promoted.version == delta.target_version
    assert registry.status(delta.delta_sha256).state == "promoted"


def test_registry_pointer_tamper_cannot_rehash_away_immutable_history(tmp_path):
    registry, delta = _register(tmp_path)
    _advance_to_release(registry, delta)
    registry.promote(
        delta.delta_sha256,
        _authorization(delta, "promote"),
        context=_context("promoted", delta),
        recorded_at=T0,
    )
    registry_path = tmp_path / "registry" / "registry.json"
    value = json.loads(registry_path.read_text(encoding="utf-8"))
    value["packages"][delta.package_id]["current_package_sha256"] = "9" * 64
    value["packages_sha256"] = sha256_text(canonical_json(value["packages"]))
    registry_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RefineryWorkspaceError, match="immutable promotion history"):
        registry.resolve_package(delta.package_id)


def test_public_parsers_reject_type_coercion_and_noncanonical_identity():
    payload = _envelope().as_dict()
    payload.pop("envelope_sha256")
    payload["task_id"] = 123
    with pytest.raises(RefineryInputError, match="task_id must be text"):
        SemanticTaskEnvelope.from_dict(payload)
    payload = _envelope().as_dict()
    payload.pop("envelope_sha256")
    payload["requested_actions"] = [{"backend": "alternate"}]
    with pytest.raises(RefineryInputError, match="entries must be text"):
        SemanticTaskEnvelope.from_dict(payload)
    with pytest.raises(RefineryInputError, match="surrounding whitespace"):
        replace(SOURCE, source_id=" engineering-record ")


def test_evidence_uri_is_logical_normalized_and_root_bounded(tmp_path):
    with pytest.raises(RefineryInputError, match="logical URI scheme"):
        replace(SOURCE, uri="file:///tmp/evidence-root/../../etc/passwd")
    with pytest.raises(RefineryInputError, match="dot segments"):
        replace(SOURCE, uri="urn:example:evidence-root:..:outside")
    with pytest.raises(RefineryInputError, match="backslashes"):
        replace(SOURCE, uri=r"urn:example:evidence-root\outside")

    def engagement_for(envelope, binding, delta):
        return SemanticEngagementReceipt.create(
            engagement_id="engagement-evidence-scheme",
            envelope=envelope,
            binding=binding,
            runtime_source=RUNTIME,
            execution=_phase("execution"),
            regression=_phase("regression"),
            receipt=_phase("receipt"),
            release=_phase("release"),
            learning=LearningResultDTO(
                "candidate", "Evidence scheme candidate.", delta.delta_sha256
            ),
            execution_receipts=(
                ExecutionReceiptReferenceDTO(
                    "f" * 64, "semantica.chapter.reference", "1", "e" * 64
                ),
            ),
            created_at=T0,
        )

    logical = replace(SOURCE, uri="evidence:project-1/root/record")
    binding = replace(_binding(), evidence_root="evidence:project-1/root")
    envelope = replace(_envelope(), evidence=(logical,))
    delta = replace(_delta(), source_evidence=(logical,))
    registry = IndustryOntologyRegistry.create(
        tmp_path / "accepted", registry_id="registry-1", created_at=T0
    )
    assert (
        registry.register_candidate(
            delta,
            envelope,
            binding,
            engagement_for(envelope, binding, delta),
            recorded_at=T0,
        ).state
        == "candidate"
    )

    sibling = replace(SOURCE, uri="evidence:project-1/rooted/record")
    sibling_envelope = replace(_envelope(), evidence=(sibling,))
    sibling_delta = replace(_delta(), source_evidence=(sibling,))
    registry = IndustryOntologyRegistry.create(
        tmp_path / "rejected", registry_id="registry-1", created_at=T0
    )
    with pytest.raises(RefineryGateError, match="outside binding evidence_root"):
        registry.register_candidate(
            sibling_delta,
            sibling_envelope,
            binding,
            engagement_for(sibling_envelope, binding, sibling_delta),
            recorded_at=T0,
        )


def test_asset_ids_are_globally_addressable_across_categories():
    delta = _delta()
    duplicate = replace(
        delta.queries[0],
        asset_id=delta.ontology[0].asset_id,
        content_base64=delta.ontology[0].content_base64,
        sha256=delta.ontology[0].sha256,
    )
    with pytest.raises(RefineryInputError, match="asset_id must be unique"):
        replace(delta, queries=(duplicate,))


def test_cli_init_is_machine_readable_and_refuses_overwrite(tmp_path, capsys):
    workspace = tmp_path / "registry"
    assert (
        main(["init", "--workspace", str(workspace), "--registry-id", "registry-1"])
        == 0
    )
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert (
        main(["init", "--workspace", str(workspace), "--registry-id", "registry-1"])
        == 1
    )
    assert json.loads(capsys.readouterr().err)["status"] == "blocked"
