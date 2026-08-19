from __future__ import annotations

from dataclasses import replace

import pytest

from semantica.ontology import (
    DatasetDiffDTO,
    DatasetSnapshotDTO,
    ExecutionReportDTO,
    PackageExecutionReceiptDTO,
    ReleaseVerdictDTO,
    SemanticRuntime,
)
from semantica.ontology.runtime import (
    CAP_DATASET_DIFF,
    CAP_DATASET_SNAPSHOT,
    CAP_EXECUTION_RECEIPT,
    CAP_PROVENANCE_BUNDLE,
    CAP_RELEASE_VERIFY,
    SemanticInputError,
)


FIXED_TIME = "2026-08-19T12:00:00Z"
COMMIT = "a" * 40
ARTIFACT_SHA256 = "b" * 64


def _runtime_with_package() -> SemanticRuntime:
    runtime = SemanticRuntime()
    runtime.load_package(
        {
            "schema_version": "1.0",
            "package_id": "semantica.chapter.vol1.ch04",
            "version": "1.0.0",
            "namespace": "urn:example:chapter:",
            "assets": [
                {
                    "asset_id": "ontology",
                    "role": "ontology",
                    "data": """
                        @prefix ex: <urn:example:> .
                        ex:data { _:person ex:name "Alice"@en . }
                    """,
                    "format": "trig",
                },
                {
                    "asset_id": "chapter-contract",
                    "role": "chapter_contract",
                    "data": '{"chapter":"vol1/ch04","schema_version":"1.0"}',
                },
                {
                    "asset_id": "cq-01",
                    "role": "sparql",
                    "data": "ASK { GRAPH <urn:example:data> { ?s ?p ?o } }",
                },
            ],
        }
    )
    return runtime


def _passing_report() -> dict:
    return {"status": "passed", "passed": True, "checks": []}


def _complete_receipt(runtime: SemanticRuntime) -> PackageExecutionReceiptDTO:
    return runtime.create_execution_receipt(
        "semantica.chapter.vol1.ch04",
        "1.0.0",
        runtime_version="0.6.5+ontology-runtime.1",
        runtime_commit=COMMIT,
        runtime_artifact_sha256=ARTIFACT_SHA256,
        required_capabilities=(
            CAP_DATASET_SNAPSHOT,
            CAP_DATASET_DIFF,
            CAP_EXECUTION_RECEIPT,
            CAP_PROVENANCE_BUNDLE,
            CAP_RELEASE_VERIFY,
        ),
        cq_report=_passing_report(),
        shacl_report=_passing_report(),
        oracle_report=_passing_report(),
        output_hashes={"result": "c" * 64},
        created_at=FIXED_TIME,
    )


def test_snapshot_is_dataset_isomorphism_stable_and_deterministic():
    first = SemanticRuntime()
    first.load(
        """
        @prefix ex: <urn:example:> .
        _:a ex:name "Alice"@en .
        ex:named { _:a ex:age "42"^^<http://www.w3.org/2001/XMLSchema#integer> . }
        """,
        format="trig",
    )
    second = SemanticRuntime()
    second.load(
        """
        @prefix ex: <urn:example:> .
        ex:named { _:different ex:age 42 . }
        _:different ex:name "Alice"@en .
        """,
        format="trig",
    )

    left = first.snapshot(created_at=FIXED_TIME)
    right = second.snapshot(created_at=FIXED_TIME)

    assert isinstance(left, DatasetSnapshotDTO)
    assert left.dataset_sha256 == right.dataset_sha256
    assert left.canonical_nquads == right.canonical_nquads
    assert left.quad_count == 2
    assert left.verify_integrity()
    assert left.to_json() == first.snapshot(created_at=FIXED_TIME).to_json()
    assert "@en" in left.canonical_nquads
    assert "urn:example:named" in left.canonical_nquads


def test_snapshot_cache_is_revision_bound_and_rebinds_only_created_at(monkeypatch):
    import semantica.ontology.runtime as runtime_module

    calls = []
    original = runtime_module.snapshot_dataset

    def counted_snapshot(*args, **kwargs):
        calls.append(kwargs["revision"])
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_module, "snapshot_dataset", counted_snapshot)
    runtime = SemanticRuntime()
    runtime.load('<urn:a> <urn:p> "one" .', format="nt")

    first = runtime.snapshot(created_at="2026-08-19T12:00:00Z")
    second = runtime.snapshot(created_at="2026-08-19T12:00:01Z")

    assert calls == [1]
    assert first.created_at != second.created_at
    assert first.dataset_sha256 == second.dataset_sha256
    assert first.canonical_nquads == second.canonical_nquads
    assert first.revision == second.revision == 1
    assert first.verify_integrity() and second.verify_integrity()

    runtime.update('INSERT DATA { <urn:b> <urn:p> "two" }')
    third = runtime.snapshot(created_at="2026-08-19T12:00:02Z")

    assert calls == [1, 2]
    assert third.revision == 2
    assert third.dataset_sha256 != first.dataset_sha256

    runtime.load('<urn:c> <urn:p> "three" .', format="nt")
    fourth = runtime.snapshot(created_at="2026-08-19T12:00:03Z")
    assert calls == [1, 2, 3]
    assert fourth.revision == 3
    assert fourth.dataset_sha256 != third.dataset_sha256


def test_failed_update_cannot_reuse_snapshot_of_partially_mutated_backend(monkeypatch):
    import semantica.ontology.runtime as runtime_module

    calls = []
    original_snapshot = runtime_module.snapshot_dataset

    def counted_snapshot(*args, **kwargs):
        calls.append(kwargs["revision"])
        return original_snapshot(*args, **kwargs)

    monkeypatch.setattr(runtime_module, "snapshot_dataset", counted_snapshot)
    runtime = SemanticRuntime()
    runtime.load('<urn:a> <urn:p> "one" .', format="nt")
    before = runtime.snapshot(created_at=FIXED_TIME)
    original_update = runtime_module.ConjunctiveGraph.update

    def partial_update_then_fail(graph, *args, **kwargs):
        original_update(graph, 'INSERT DATA { <urn:partial> <urn:p> "dirty" }')
        raise RuntimeError("simulated backend failure after partial mutation")

    monkeypatch.setattr(
        runtime_module.ConjunctiveGraph, "update", partial_update_then_fail
    )

    with pytest.raises(SemanticInputError, match="SPARQL update failed"):
        runtime.update('INSERT DATA { <urn:requested> <urn:p> "value" }')

    after = runtime.snapshot(created_at=FIXED_TIME)
    assert runtime.revision == 1
    assert calls == [1, 1]
    assert after.dataset_sha256 != before.dataset_sha256
    assert "urn:partial" in after.canonical_nquads


def test_snapshot_diff_reports_sorted_added_removed_and_live_default():
    runtime = SemanticRuntime()
    runtime.load('<urn:a> <urn:p> "one" .', format="nt")
    before = runtime.snapshot(created_at=FIXED_TIME)
    runtime.update(
        'DELETE DATA { <urn:a> <urn:p> "one" }; INSERT DATA { <urn:b> <urn:p> "two" }'
    )

    diff = runtime.diff(before, created_at=FIXED_TIME)

    assert isinstance(diff, DatasetDiffDTO)
    assert diff.changed is True
    assert diff.added_quads == ('<urn:b> <urn:p> "two" .',)
    assert diff.removed_quads == ('<urn:a> <urn:p> "one" .',)
    assert diff.unchanged_count == 0
    assert (
        diff.to_json()
        == runtime.diff(
            before, runtime.snapshot(created_at=FIXED_TIME), created_at=FIXED_TIME
        ).to_json()
    )


def test_complete_receipt_is_deterministic_provenance_bound_and_releasable():
    runtime = _runtime_with_package()

    first = _complete_receipt(runtime)
    second = _complete_receipt(runtime)

    assert isinstance(first, PackageExecutionReceiptDTO)
    assert first.receipt_sha256 == second.receipt_sha256
    assert first.to_json() == second.to_json()
    assert first.verify_integrity()
    assert first.provenance_bundle.verify_integrity()
    assert first.provenance_bundle.bindings["runtime_commit"] == COMMIT
    assert first.provenance_bundle.bindings["dataset_sha256"] == first.dataset_sha256
    assert dict(first.asset_hashes)["chapter-contract"] == first.chapter_contract_sha256
    assert all(isinstance(report, ExecutionReportDTO) for report in first.reports)

    verdict = runtime.verify_release(first, checked_at=FIXED_TIME)
    assert isinstance(verdict, ReleaseVerdictDTO)
    assert verdict.status == "complete"
    assert verdict.complete is True
    assert verdict.reasons == ()
    assert all(item.passed for item in verdict.checks)


def test_missing_evidence_and_failed_report_are_retained_and_block_release():
    runtime = _runtime_with_package()
    receipt = runtime.create_execution_receipt(
        "semantica.chapter.vol1.ch04",
        "1.0.0",
        runtime_version="0.6.5+ontology-runtime.1",
        # commit, artifact, SHACL, and oracle intentionally absent
        cq_report={"status": "failed", "passed": False, "failed_cq": ["CQ-01"]},
        created_at=FIXED_TIME,
    )

    assert receipt.cq_report.status == "failed"
    assert receipt.shacl_report.status == "blocked"
    assert receipt.oracle_report.status == "blocked"
    assert receipt.verify_integrity()

    verdict = runtime.verify_release(receipt, checked_at=FIXED_TIME)
    assert verdict.status == "blocked"
    assert "runtime.commit" in verdict.reasons
    assert "runtime.artifact_sha256" in verdict.reasons
    assert "report.cq" in verdict.reasons
    assert "report.shacl" in verdict.reasons
    assert "report.oracle" in verdict.reasons


def test_receipt_tampering_and_dataset_drift_block_release():
    runtime = _runtime_with_package()
    receipt = _complete_receipt(runtime)

    tampered = replace(receipt, runtime_commit="d" * 40)
    tampered_verdict = runtime.verify_release(tampered, checked_at=FIXED_TIME)
    assert tampered_verdict.status == "blocked"
    assert "receipt.integrity" in tampered_verdict.reasons
    assert "provenance.bundle" in tampered_verdict.reasons

    runtime.update('INSERT DATA { <urn:new> <urn:p> "drift" }')
    drift_verdict = runtime.verify_release(receipt, checked_at=FIXED_TIME)
    assert drift_verdict.status == "blocked"
    assert "dataset.integrity" in drift_verdict.reasons


def test_public_lifecycle_capabilities_are_explicit():
    runtime = SemanticRuntime()
    for capability in (
        CAP_DATASET_SNAPSHOT,
        CAP_DATASET_DIFF,
        CAP_EXECUTION_RECEIPT,
        CAP_PROVENANCE_BUNDLE,
        CAP_RELEASE_VERIFY,
    ):
        assert runtime.supports(capability)

    bundle = runtime.record_provenance(
        {
            "runtime_version": "test",
            "package_id": "example",
            "package_version": "1",
            "package_digest": "d" * 64,
            "dataset_sha256": "e" * 64,
            "asset_hashes": {},
            "report_hashes": {},
        },
        generated_at=FIXED_TIME,
    )
    assert bundle.verify_integrity()
    assert (
        bundle.to_json()
        == runtime.record_provenance(bundle.bindings, generated_at=FIXED_TIME).to_json()
    )
