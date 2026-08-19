import hashlib

import pytest

from semantica.chapter_packages import (
    ChapterPackageAssetError,
    ChapterPackageNotFoundError,
    get_domain_package,
    list_domain_packages,
    load_domain_package,
    package_asset_text,
    read_migration_map,
    resolve_migration_successor,
    validate_domain_package,
)
from semantica.ontology.runtime import SemanticRuntime

NORMATIVE_PACKAGE = "semantica.chapter_packages.vol2.normative"


def test_normative_layer_is_a_registry_closed_domain_package():
    packages = list_domain_packages()

    assert tuple(item.package_id for item in packages) == (NORMATIVE_PACKAGE,)
    descriptor = get_domain_package(NORMATIVE_PACKAGE)
    assert descriptor.version == "0.1.0"
    assert descriptor.manifest_path.is_file()
    assert not validate_domain_package(NORMATIVE_PACKAGE)


def test_domain_package_load_uses_hash_verified_semantic_runtime_boundary():
    runtime = SemanticRuntime(profile="ontology-runtime", backend="rdflib")

    loaded = load_domain_package(runtime, NORMATIVE_PACKAGE)

    assert loaded.identity.package_id == NORMATIVE_PACKAGE
    assert loaded.identity.version == "0.1.0"
    assert loaded.rdf_added > 0
    assert all(
        hashlib.sha256(asset.content).hexdigest() == asset.sha256
        for asset in loaded.assets
    )


def test_two_migration_encodings_normalize_to_frozen_successor_dtos():
    vol1 = read_migration_map("vol1")
    vol2 = read_migration_map("vol2")

    assert vol1.entry_count == 37
    assert vol2.entry_count == 103
    assert {item.volume for item in vol1.entries} == {"vol1"}
    assert {item.volume for item in vol2.entries} == {"vol2"}
    assert all(len(item.successor_sha256) == 64 for item in vol1.entries + vol2.entries)
    assert read_migration_map("vol1") is vol1
    assert vol1.retired_runtime_entry_count == 3
    assert all(not item.copied_as_runtime for item in vol1.retired_runtime_entries)
    assert vol2.retired_runtime_entries == ()


def test_duplicate_legacy_path_preserves_every_successor_candidate():
    resolution = resolve_migration_successor("demos/vol2_ch17_change_verdict_gate.py")

    assert resolution.resolved
    assert resolution.ambiguous
    assert [(item.package_id, item.asset_id) for item in resolution.candidates] == [
        (
            "semantica.chapter_packages.vol2.ch17",
            "demo_vol2_ch17_change_verdict_gate_query",
        ),
        (
            "semantica.chapter_packages.vol2.ch17",
            "demo_vol2_ch17_change_verdict_gate_shapes",
        ),
    ]


def test_unknown_legacy_path_returns_explicit_unresolved_dto():
    resolution = resolve_migration_successor("not/a/registered/legacy/path")

    assert not resolution.resolved
    assert not resolution.ambiguous
    assert resolution.candidates == ()


def test_retired_runtime_entries_are_audited_but_not_asset_successors():
    ledger = read_migration_map("vol1")
    paths = {item.legacy_path for item in ledger.retired_runtime_entries}

    java_path = (
        "references/ontology-engineering-book/"
        "ch09-capstone-manufacturing/src/OntologyManager.java"
    )
    assert java_path in paths
    assert not resolve_migration_successor(java_path).resolved
    assert all(
        item.replacement_entry and item.reason
        for item in ledger.retired_runtime_entries
    )


def test_package_asset_text_reads_hash_verified_chapter_and_domain_text():
    cq_text = package_asset_text(
        "semantica.chapter_packages.vol1.ch03", "competency-questions"
    )
    normative_text = package_asset_text(NORMATIVE_PACKAGE, "part1-cards")

    assert "能力问题" in cq_text or "Competency" in cq_text
    assert "Part 1" in normative_text or "ISO" in normative_text


def test_package_asset_text_unknown_package_or_asset_fails_closed():
    with pytest.raises(ChapterPackageNotFoundError):
        package_asset_text("semantica.chapter_packages.unknown", "asset")
    with pytest.raises(ChapterPackageAssetError):
        package_asset_text("semantica.chapter_packages.vol1.ch03", "missing")
