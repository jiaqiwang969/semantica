import hashlib
import json

import yaml

import semantica.chapter_packages as packages
from semantica.chapter_packages import ChapterPackageDescriptor
from semantica import mcp_server


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path, monkeypatch):
    chapter = tmp_path / "references" / "book" / "chapter.md"
    guide = tmp_path / "references" / "book" / "README.md"
    tex = tmp_path / "references" / "book" / "handbook" / "fragments" / "ch01.tex"
    package_root = tmp_path / "package"
    chapter.parent.mkdir(parents=True)
    tex.parent.mkdir(parents=True)
    package_root.mkdir()
    chapter.write_text("authoritative chapter\n", encoding="utf-8")
    guide.write_text("maintainer guide\n", encoding="utf-8")
    tex.write_text("generated TeX snapshot\n", encoding="utf-8")

    source_anchor = "references/book/chapter.md"
    guide_anchor = "references/book/README.md"
    tex_anchor = "references/book/handbook/fragments/ch01.tex"
    source_sha256 = _sha(chapter)
    guide_sha256 = _sha(guide)
    tex_sha256 = _sha(tex)
    contract = {
        "external_specification": {
            "source_anchor": source_anchor,
            "source_sha256": source_sha256,
            "guide_anchor": guide_anchor,
            "guide_sha256": guide_sha256,
            "tex_anchor": tex_anchor,
            "tex_sha256": tex_sha256,
        }
    }
    contract_path = package_root / "contract.yaml"
    contract_path.write_text(
        yaml.safe_dump(contract, allow_unicode=True), encoding="utf-8"
    )
    manifest = {
        "book_source": {
            "logical_anchor": source_anchor,
            "sha256": source_sha256,
            "guide_anchor": guide_anchor,
            "guide_sha256": guide_sha256,
            "tex_anchor": tex_anchor,
            "tex_sha256": tex_sha256,
        },
        "assets": [
            {
                "asset_id": "chapter-contract",
                "role": "chapter_contract",
                "path": "contract.yaml",
                "source_anchor": "historical/contracts/ch01.yaml",
                "source_sha256": "a" * 64,
            },
            {
                "asset_id": "ontology",
                "role": "ontology",
                "path": "ontology.ttl",
                "source_anchor": source_anchor,
                "source_sha256": source_sha256,
            },
        ],
    }
    manifest_path = package_root / "manifest.yaml"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (package_root / "ontology.ttl").write_text("@prefix : <urn:test:> .\n")
    descriptor = ChapterPackageDescriptor(
        volume="vol2",
        chapter="ch01",
        package_id="semantica.chapter_packages.vol2.ch01",
        version="0.1.0",
        title="test",
        status="partial",
        release_status="blocked",
        manifest_path=manifest_path,
    )
    monkeypatch.setattr(packages, "_descriptors", lambda: (descriptor,))
    return chapter, manifest_path, contract_path


def test_book_markdown_tex_contract_and_derived_asset_are_bound(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)

    result = packages.verify_book_source_bindings(tmp_path)

    assert result.passed
    assert result.status == "passed"
    assert result.as_dict()["check_count"] == 7
    assert {item.status for item in result.checks} == {"passed"}


def test_mcp_exposes_the_same_fail_closed_book_binding_gate(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)

    payload = mcp_server.call_mcp_tool(
        "verify_book_sources", {"book_root": str(tmp_path), "volume": "vol2"}
    )

    assert payload["ok"] is True
    assert payload["result"]["passed"] is True
    assert payload["result"]["check_count"] == 7


def test_book_content_drift_blocks_verification(tmp_path, monkeypatch):
    chapter, _, _ = _fixture(tmp_path, monkeypatch)
    chapter.write_text("changed without rebinding\n", encoding="utf-8")

    result = packages.verify_book_source_bindings(tmp_path)

    assert not result.passed
    failed = [item for item in result.checks if item.status == "blocked"]
    assert [item.check_id for item in failed] == ["book.primary.digest"]
    assert failed[0].actual_sha256 == _sha(chapter)


def test_derived_asset_source_hash_cannot_drift_from_book_binding(
    tmp_path, monkeypatch
):
    _, manifest_path, _ = _fixture(tmp_path, monkeypatch)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["assets"][1]["source_sha256"] = "b" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = packages.verify_book_source_bindings(tmp_path)

    failed = [item for item in result.checks if item.status == "blocked"]
    assert [item.check_id for item in failed] == ["book.asset-source.ontology"]


def test_book_anchor_cannot_escape_repository_root(tmp_path, monkeypatch):
    _, manifest_path, contract_path = _fixture(tmp_path, monkeypatch)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["book_source"]["logical_anchor"] = "../outside.md"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    contract["external_specification"]["source_anchor"] = "../outside.md"
    contract_path.write_text(yaml.safe_dump(contract), encoding="utf-8")

    result = packages.verify_book_source_bindings(tmp_path)

    failed = [item for item in result.checks if item.status == "blocked"]
    assert failed[0].check_id == "book.primary.digest"
    assert "escapes" in failed[0].reason
