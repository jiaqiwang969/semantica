import json
from dataclasses import FrozenInstanceError

import pytest

from semantica.chapter_packages import RUNNER_CONTRACT, SemanticPackageRunner

SOURCE_KWARGS = {
    "runtime_commit": "a" * 40,
    "runtime_artifact_sha256": "b" * 64,
    "created_at": "2026-08-19T00:00:00Z",
}


def test_vol1_runner_executes_exact_positive_and_negative_cq_oracles():
    runner = SemanticPackageRunner()

    result = runner.run_scenario("vol1", "ch03", **SOURCE_KWARGS)

    assert result.status == "passed"
    assert result.package_id == "semantica.chapter_packages.vol1.ch03"
    assert {item.status for item in result.operations} == {"passed"}
    assert {item.status for item in result.oracle_checks} == {"passed"}
    assert result.receipt is not None
    assert result.receipt.verify_integrity()
    # The scenario passes, while the package's honest migration release gate
    # remains blocked until its manifest declares the package complete.
    assert result.release_verdict.status == "blocked"
    assert "package.declared_release_status" in result.release_verdict.reasons
    assert (
        runner.verify(result, checked_at=SOURCE_KWARGS["created_at"]).as_dict()
        == result.release_verdict.as_dict()
    )
    assert json.loads(result.to_json()) == result.as_dict()


@pytest.mark.parametrize("chapter", ("ch01", "ch17"))
def test_vol2_json_registry_runs_query_and_two_shacl_paths(chapter):
    result = SemanticPackageRunner().run_scenario("vol2", chapter, **SOURCE_KWARGS)

    assert result.status == "passed"
    assert [item.check_id for item in result.oracle_checks] == [
        "oracle.cq_exact",
        "oracle.positive_path",
        "oracle.single_fault_negative",
    ]
    assert all(item.status == "passed" for item in result.oracle_checks)
    assert any(item.operation == "select" for item in result.operations)
    assert sum(item.operation == "validate" for item in result.operations) == 2
    assert result.oracle_report.status == "passed"
    assert result.shacl_report.status == "passed"
    assert result.receipt is not None
    assert result.receipt.provenance_bundle.verify_integrity()


def test_reference_only_operation_and_absent_oracle_fail_closed():
    result = SemanticPackageRunner().run_scenario("vol1", "ch01", **SOURCE_KWARGS)

    assert result.status == "blocked"
    assert result.oracle_report.status == "blocked"
    assert result.release_verdict.status == "blocked"
    assert result.receipt is not None
    assert result.receipt.verify_integrity()
    assert "oracle.contract" in {item.check_id for item in result.oracle_checks}


@pytest.mark.parametrize(
    ("operation", "inputs", "oracle"),
    (
        (
            "unknown_backend_operation",
            ["data"],
            {"id": "ORC-1", "status": "ready", "expected": True},
        ),
        (
            "select_exact_multiset",
            ["missing-data", "data"],
            {
                "id": "ORC-1",
                "status": "ready",
                "positive": {"row_count": 0},
                "single_fault_negative": {"row_count": 0},
            },
        ),
        ("select_exact_multiset", ["data", "data"], None),
    ),
)
def test_unknown_operation_missing_asset_and_missing_oracle_are_blocked(
    tmp_path, operation, inputs, oracle
):
    contract = tmp_path / "contract.yaml"
    data = tmp_path / "data.ttl"
    query = tmp_path / "query.rq"
    cqs = tmp_path / "cqs.yaml"
    scenarios = tmp_path / "scenarios.yaml"
    contract.write_text("contract: test\n", encoding="utf-8")
    data.write_text(
        "@prefix ex: <https://example.test/> . ex:s ex:p ex:o .\n",
        encoding="utf-8",
    )
    query.write_text("SELECT ?s WHERE { ?s ?p ?o }\n", encoding="utf-8")
    cqs.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "competency_questions": [{"id": "CQ-1", "scenario_ids": ["SCN-1"]}],
            }
        ),
        encoding="utf-8",
    )
    scenario = {
        "id": "SCN-1",
        "status": "native",
        "execution": {"operation": operation, "query_asset_id": "query"},
        "inputs": inputs,
    }
    if oracle is not None:
        scenario["oracle"] = oracle
    scenarios.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "runner_contract": RUNNER_CONTRACT,
                "scenarios": [scenario],
            }
        ),
        encoding="utf-8",
    )
    assets = []
    for asset_id, role, path, format_name in (
        ("contract", "chapter_contract", contract, "yaml"),
        ("data", "positive_fixture", data, "turtle"),
        ("query", "sparql", query, "sparql"),
        ("cqs", "competency_questions", cqs, "yaml"),
        ("scenarios", "scenario_registry", scenarios, "yaml"),
    ):
        assets.append(
            {
                "asset_id": asset_id,
                "role": role,
                "path": path.name,
                "format": format_name,
            }
        )
    manifest = {
        "schema_version": "1.0",
        "package_id": "semantica.test.fail-closed",
        "version": "1.0.0",
        "namespace": "https://example.test/",
        "release_status": "complete",
        "execution": {
            "scenario_registry_asset_id": "scenarios",
            "cq_registry_asset_id": "cqs",
        },
        "assets": assets,
    }

    result = SemanticPackageRunner().run_manifest(
        manifest, base_path=tmp_path, **SOURCE_KWARGS
    )

    assert result.status == "blocked"
    assert result.oracle_report.status == "blocked"
    assert result.release_verdict.status == "blocked"
    assert result.receipt is not None
    assert result.receipt.verify_integrity()
    json.dumps(result.as_dict(), ensure_ascii=False)


def test_public_run_dtos_are_frozen_and_do_not_expose_backend_objects():
    result = SemanticPackageRunner().run_scenario("vol1", "ch03", **SOURCE_KWARGS)

    with pytest.raises(FrozenInstanceError):
        result.status = "blocked"
    with pytest.raises(FrozenInstanceError):
        result.operations[0].status = "blocked"
    assert isinstance(result.as_dict(), dict)
    assert "rdflib" not in repr(result.operations)
