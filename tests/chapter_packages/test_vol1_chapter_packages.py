import hashlib
from pathlib import Path

import pytest
import yaml

from semantica.chapter_packages import (
    ChapterPackageAssetError,
    execute_chapter_query,
    get_chapter_package,
    list_chapter_packages,
    load_chapter_package,
    read_chapter_manifest,
    validate_chapter_contract,
    validate_chapter_registry,
)
from semantica.ontology.runtime import SemanticRuntime
from semantica.reasoning import Reasoner


VOL1_CHAPTERS = tuple("ch{:02d}".format(index) for index in range(1, 10))


def _runtime():
    return SemanticRuntime(profile="ontology-runtime", backend="rdflib")


def _asset(result, asset_id):
    return next(asset for asset in result.assets if asset.asset_id == asset_id)


def test_vol1_registry_is_complete_and_contracts_follow_common_policy():
    packages = list_chapter_packages("vol1")

    assert tuple(package.chapter for package in packages) == VOL1_CHAPTERS
    assert not validate_chapter_registry(require_complete=False)
    for chapter in VOL1_CHAPTERS:
        assert not validate_chapter_contract("vol1", chapter)


def test_two_book_registry_has_all_29_policy_conformant_contracts():
    packages = list_chapter_packages()

    assert len(packages) == 29
    assert not validate_chapter_registry(require_complete=True)


@pytest.mark.parametrize("chapter", VOL1_CHAPTERS)
def test_every_vol1_package_loads_natively_and_retains_contract(chapter):
    runtime = _runtime()

    result = load_chapter_package(runtime, "vol1", chapter)

    assert result.identity.package_id == (
        "semantica.chapter_packages.vol1.{}".format(chapter)
    )
    assert result.identity.version == "1.0.0"
    assert _asset(result, "contract").role == "chapter_contract"
    assert _asset(result, "cqs").role == "competency_questions"
    assert _asset(result, "scenarios").role == "scenario_registry"


def test_vol1_ch03_cq_scenario_has_exact_positive_and_negative_oracles():
    positive = _runtime()
    package = load_chapter_package(positive, "vol1", "ch03")
    positive.load(
        _asset(package, "cq01-positive").content,
        format="turtle",
    )
    rows = execute_chapter_query(
        positive, "vol1", "ch03", "cq01"
    ).rows
    assert sorted(row["name"].value for row in rows) == [
        "数控车床一号",
        "立式铣床二号",
    ]

    negative = _runtime()
    package = load_chapter_package(negative, "vol1", "ch03")
    negative.load(
        _asset(package, "cq01-single-fault-negative").content,
        format="turtle",
    )
    assert not execute_chapter_query(
        negative, "vol1", "ch03", "cq01"
    ).rows


@pytest.mark.parametrize(
    ("chapter", "expected"),
    (
        (
            "ch02",
            {
                "CNCMachine(Lathe_001)",
                "ProcessingEquipment(Lathe_001)",
                "Available(Lathe_001)",
                "Unavailable(Lathe_001)",
            },
        ),
        (
            "ch05",
            {
                "HighPowerEquipment(Lathe_003)",
                "RequiresCooling(Lathe_003)",
            },
        ),
    ),
)
def test_source_grounded_forward_chain_scenarios_match_oracles(
    chapter, expected
):
    runtime = _runtime()
    package = load_chapter_package(runtime, "vol1", chapter)
    reasoner = Reasoner()
    for line in _asset(package, "forward-chain-facts").text().splitlines():
        if line.strip():
            reasoner.add_fact(line.strip())
    for line in _asset(package, "forward-chain-rules").text().splitlines():
        if line.strip():
            reasoner.add_rule(line.strip())

    conclusions = {
        str(inference.conclusion) for inference in reasoner.forward_chain()
    }

    assert expected <= conclusions


def test_vol1_ch04_rdf_assets_load_and_demo_query_is_registered():
    runtime = _runtime()
    package = load_chapter_package(runtime, "vol1", "ch04")

    assert package.rdf_added > 0
    runtime.load(
        _asset(package, "open-world-data").content,
        format="turtle",
    )
    rows = execute_chapter_query(
        runtime, "vol1", "ch04", "cq-missing-serial"
    ).rows
    assert [row["equipment"].value for row in rows] == [
        "http://example.org/manufacturing#Lathe_BAD"
    ]


def test_vol1_ch07_shape_has_positive_and_single_fault_oracles():
    positive = _runtime()
    package = load_chapter_package(positive, "vol1", "ch07")
    positive.load(_asset(package, "positive").content, format="turtle")
    report = positive.validate(
        _asset(package, "kg-quality-shacl").content,
        inference="none",
        advanced=True,
    )
    assert report.conforms
    assert report.violation_count == 0

    negative = _runtime()
    package = load_chapter_package(negative, "vol1", "ch07")
    negative.load(
        _asset(package, "single-fault-missing-serial").content,
        format="turtle",
    )
    report = negative.validate(
        _asset(package, "kg-quality-shacl").content,
        inference="none",
        advanced=True,
    )
    assert not report.conforms
    assert report.violation_count == 1
    assert "序列号" in report.violations[0].message


def test_vol1_ch09_queries_replace_book_local_jena_query_service():
    runtime = _runtime()
    package = load_chapter_package(runtime, "vol1", "ch09")
    runtime.load(_asset(package, "cq01-positive").content, format="turtle")

    rows = execute_chapter_query(runtime, "vol1", "ch09", "cq01").rows

    assert sorted(row["name"].value for row in rows) == [
        "数控车床一号",
        "立式铣床二号",
    ]
    with pytest.raises(ChapterPackageAssetError):
        execute_chapter_query(runtime, "vol1", "ch09", "manufacturing")


def test_vol1_migration_map_covers_all_strict_gate_assets_with_exact_hashes():
    root = get_chapter_package("vol1", "ch01").manifest_path.parents[1]
    migration = yaml.safe_load(
        (root / "migration-map.yaml").read_text(encoding="utf-8")
    )
    strict = [
        item for item in migration["assets"] if item["strict_gate_asset"]
    ]

    assert len(strict) == 9
    for item in migration["assets"]:
        target = root.parents[2] / item["semantica_path"]
        assert target.is_file()
        assert hashlib.sha256(target.read_bytes()).hexdigest() == item["sha256"]
        manifest = read_chapter_manifest(
            item["package_id"].split(".")[-2],
            item["package_id"].split(".")[-1],
        )
        declared = {
            asset["asset_id"]: asset for asset in manifest["assets"]
        }
        assert item["asset_id"] in declared
        assert declared[item["asset_id"]]["sha256"] == item["sha256"]
