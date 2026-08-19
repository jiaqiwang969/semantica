from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

from semantica.ontology.runtime import SemanticRuntime


VOL2 = Path(__file__).resolve().parents[2] / "semantica/chapter_packages/vol2"
CHAPTERS = tuple(f"ch{number:02d}" for number in range(1, 21))
PAYLOAD_KINDS = {
    "ontology",
    "competency_questions",
    "shapes",
    "sparql",
    "cases",
    "engineering_rules",
    "chapter_contract",
}
LIFECYCLE_STAGES = {
    "load",
    "query_validate_reason",
    "version",
    "provenance",
    "release",
}
RECEIPT_FIELDS = {
    "runtime_commit",
    "runtime_artifact_sha256",
    "chapter_contract_sha256",
    "dataset_sha256",
    "capability_report",
    "cq_report",
    "oracle_report",
    "provenance_bundle",
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def runtime() -> SemanticRuntime:
    return SemanticRuntime(profile="ontology-runtime", backend="rdflib")


def asset(result, asset_id: str):
    return next(item for item in result.assets if item.asset_id == asset_id)


def normalized_rows(rows, variables):
    rendered = []
    for row in rows:
        rendered.append(
            json.dumps(
                {name: row[name].as_dict() for name in variables},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    return Counter(rendered)


@pytest.mark.parametrize("chapter", CHAPTERS)
def test_chapter_manifest_is_native_loadable_and_fail_closed(chapter: str) -> None:
    manifest_path = VOL2 / chapter / "manifest.yaml"
    manifest = read_json(manifest_path)
    loaded = runtime().load_package(manifest_path)

    assert loaded.identity.package_id == f"semantica.chapter_packages.vol2.{chapter}"
    assert loaded.identity.version == "0.1.0"
    assert loaded.rdf_added > 0
    assert manifest["status"] == "partial"
    assert manifest["release_status"] == "blocked"
    assert len(manifest["scenarios"]) == 1
    assert manifest["scenarios"][0]["scenario_id"] == (
        f"semantica.vol2.{chapter}.scenario.primary"
    )

    contract = read_json(VOL2 / chapter / "contract.yaml")
    assert set(contract["payload_status"]) == PAYLOAD_KINDS
    assert set(contract["lifecycle"]) == LIFECYCLE_STAGES
    assert set(contract["receipt"]["required_fields"]) == RECEIPT_FIELDS
    assert set(contract["receipt"]["fields"]) == RECEIPT_FIELDS
    assert contract["receipt"]["status"] == "absent"
    assert contract["release"]["status"] == "blocked"


@pytest.mark.parametrize("chapter", CHAPTERS)
def test_primary_scenario_query_and_shacl_oracles(chapter: str) -> None:
    manifest_path = VOL2 / chapter / "manifest.yaml"
    package_runtime = runtime()
    loaded = package_runtime.load_package(manifest_path)
    registry = json.loads(asset(loaded, "cq-registry").text())
    cq = registry["competency_questions"][0]
    assert cq["scenario_id"] == f"semantica.vol2.{chapter}.scenario.primary"
    assert registry["runner_contract"]["fail_closed"] is True

    steps = cq["execution"]["steps"]
    dataset_id = next(step["asset_id"] for step in steps if step["operation"] == "load_asset")
    query_id = next(step["asset_id"] for step in steps if step["operation"] == "select")
    package_runtime.load(asset(loaded, dataset_id).content, format="turtle")
    result = package_runtime.select(asset(loaded, query_id).text())
    exact = cq["oracles"]["cq_exact"]
    expected = Counter(
        json.dumps(row, ensure_ascii=False, sort_keys=True) for row in exact["rows"]
    )
    assert tuple(result.variables) == tuple(exact["variables"])
    assert normalized_rows(result.rows, exact["variables"]) == expected

    positive_runtime = runtime()
    positive_loaded = positive_runtime.load_package(manifest_path)
    positive_runtime.load(asset(positive_loaded, "positive-case").content, format="turtle")
    shapes_id = next(
        step["asset_id"]
        for step in cq["oracles"]["positive_path"]["execution"]
        if step["operation"] == "validate"
    )
    assert positive_runtime.validate(asset(positive_loaded, shapes_id).content).conforms

    negative_runtime = runtime()
    negative_loaded = negative_runtime.load_package(manifest_path)
    negative_runtime.load(asset(negative_loaded, "negative-case").content, format="turtle")
    negative_oracle = cq["oracles"]["single_fault_negative"]
    negative_report = negative_runtime.validate(asset(negative_loaded, shapes_id).content)
    assert not negative_report.conforms
    assert any(
        negative_oracle["message_contains"] in violation.message
        for violation in negative_report.violations
    )
    assert negative_oracle["fault_count"] == 1


def test_normative_package_loads_complete_derived_layer_and_oracles() -> None:
    manifest_path = VOL2 / "normative/manifest.yaml"
    rt = runtime()
    loaded = rt.load_package(manifest_path)
    assert loaded.identity.package_id == "semantica.chapter_packages.vol2.normative"
    assert loaded.rdf_added > 0
    ids = {item.asset_id for item in loaded.assets}
    assert {
        "normative-tbox",
        "part1-vocabulary",
        "part3-concept-phase",
        "teaching-cases",
        "part1-cards",
        "part3-cards",
        "gloss-part3-glosses",
        "gloss-teaching-cases",
    } <= ids

    cq = json.loads(asset(loaded, "cq-registry").text())["competency_questions"][0]
    query_id = next(
        step["asset_id"] for step in cq["execution"]["steps"] if step["operation"] == "select"
    )
    result = rt.select(asset(loaded, query_id).text())
    expected = Counter(
        json.dumps(row, ensure_ascii=False, sort_keys=True)
        for row in cq["oracles"]["cq_exact"]["rows"]
    )
    assert normalized_rows(result.rows, result.variables) == expected

    shapes_id = cq["oracles"]["positive_path"]["shapes_asset"]
    assert rt.validate(asset(loaded, shapes_id).content).conforms
    bad = runtime()
    bad_loaded = bad.load_package(manifest_path)
    bad.load(asset(bad_loaded, "single-fault-negative").content, format="turtle")
    report = bad.validate(asset(bad_loaded, shapes_id).content)
    assert not report.conforms
    assert any("模态" in violation.message for violation in report.violations)


def test_migration_map_covers_all_legacy_fixtures_iso_layer_and_examples() -> None:
    migration = read_json(VOL2 / "migration-map.json")
    mappings = migration["mappings"]
    exact = {item["old_path"]: item for item in mappings if item["relation"] == "byte_identical"}
    required_fixtures = {
        f"demos/fixtures/{name}.ttl"
        for name in (
            "ch12_bridge_bad",
            "ch12_bridge_good",
            "ch13_activation_bad",
            "ch13_governance",
            "ch15_traceability",
            "ch17_change",
            "ch17_verdicts_bad",
            "ch17_verdicts_good",
            "ch18_dependency",
            "ch19_ledger",
            "ch19_substitution_bad",
            "ch19_substitution_good",
        )
    }
    required_iso = {
        "references/iso-normative-ontology/normative-tbox.ttl",
        "references/iso-normative-ontology/part1-vocabulary.ttl",
        "references/iso-normative-ontology/part3-concept-phase.ttl",
        "references/iso-normative-ontology/teaching-cases.ttl",
        "references/iso-normative-ontology/part1-cards.md",
        "references/iso-normative-ontology/part3-cards.md",
        "references/iso-normative-ontology/glosses/part3-glosses.yaml",
        "references/iso-normative-ontology/glosses/teaching-cases.yaml",
        "references/iso-normative-ontology/README.md",
    }
    assert required_fixtures | required_iso <= set(exact)
    assert all(exact[path]["old_sha256"] == exact[path]["new_sha256"] for path in required_fixtures | required_iso)

    example_mappings = [
        item for item in mappings
        if "/examples/" in item["old_path"] and item["relation"] == "byte_identical"
    ]
    assert len(example_mappings) == 29
    assert all(item["old_sha256"] == item["new_sha256"] for item in example_mappings)


def test_legacy_capstone_is_preserved_without_fabricating_missing_inputs() -> None:
    manifest_path = VOL2 / "ch20/manifest.yaml"
    loaded = runtime().load_package(manifest_path)
    old_manifest = asset(loaded, "legacy-capstone-bundle-manifest")
    missing = json.loads(asset(loaded, "legacy-capstone-missing-inputs").text())
    queries = json.loads(asset(loaded, "legacy-capstone-queries").text())
    boundaries = json.loads(asset(loaded, "legacy-capstone-boundary-rules").text())

    assert hashlib.sha256(old_manifest.content).hexdigest() == old_manifest.sha256
    assert missing["status"] == "blocked"
    assert missing["declared_input_count"] == len(missing["inputs"])
    assert missing["available_input_count"] == 0
    assert {item["availability"] for item in missing["inputs"]} == {"missing_from_oe_snapshot"}
    assert set(queries["queries"]) == {
        "TRACE_CLOSURE_QUERY",
        "ITEM_SUMMARY_QUERY",
        "ASIL_D_CROSS_VIEW_QUERY",
        "CLAUSE8_BOUNDARY_QUERY",
        "LABEL_QUERY",
    }
    assert queries["execution_status"] == "blocked_missing_declared_inputs"
    assert any("release authorization" in rule.lower() for rule in boundaries["rules"])
    contract = read_json(VOL2 / "ch20/contract.yaml")
    assert contract["legacy_capstone"]["status"] == "blocked_missing_inputs"
    assert contract["release"]["status"] == "blocked"
