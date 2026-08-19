import hashlib
import json
from pathlib import Path

import pytest

from semantica.chapter_packages.normative import (
    NormativeInputError,
    NormativeOutputError,
    engrave_normative_package,
    main,
)
from semantica.ontology.runtime import SemanticRuntime


PART_PATHS = {
    1: Path(
        "part-01-vocabulary/native-full/ISO 26262-1-2018/auto/"
        "ISO 26262-1-2018_content_list_v2.json"
    ),
    3: Path(
        "part-03-concept-phase/native-full/ISO 26262-3-2018/auto/"
        "ISO 26262-3-2018_content_list_v2.json"
    ),
}
SECRET = "RESTRICTED-STANDARD-WORDING-MUST-NOT-LEAVE-SOURCE"


def _block(text):
    return {"content": {"text": [{"content": text}]}}


def _write_extract(root: Path, part: int, texts) -> None:
    path = root / PART_PATHS[part]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([[_block(text) for text in texts]]), encoding="utf-8")


def _write_book(root: Path) -> None:
    path = root / "appendices" / "appendix-c-glossary.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "- **测试术语（test term）**（1-3.1；ch04）——这是作者自己的公开转述。\n",
        encoding="utf-8",
    )


def _inputs(tmp_path):
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    _write_extract(controlled, 1, ["3.1 test term {}".format(SECRET)])
    _write_extract(
        controlled,
        3,
        [
            "5.4.1 {} the item definition shall be available".format(SECRET),
            "8.1 {} structural heading".format(SECRET),
        ],
    )
    book = tmp_path / "book"
    book.mkdir()
    _write_book(book)
    return controlled, book


def test_engraver_uses_builtin_seeds_and_never_exports_standard_text(tmp_path):
    controlled, book = _inputs(tmp_path)
    output = tmp_path / "engraved"
    result = engrave_normative_package(
        controlled_source_root=controlled,
        book_root=book,
        output_directory=output,
        parts=(1, 3),
    )

    assert result.package_id == "semantica.chapter_packages.vol2.normative"
    assert result.package_digest
    assert result.restricted_standard_text_included is False
    assert tuple(item.part for item in result.parts) == (1, 3)
    assert result.parts[0].unit_count == 1
    assert result.parts[1].unit_count == 2
    assert result.parts[1].glossed_count == 1
    assert result.parts[1].pending_count == 1

    combined = b"\n".join(path.read_bytes() for path in sorted(output.iterdir()))
    assert SECRET.encode("utf-8") not in combined
    assert b"the item definition shall be available" not in combined
    assert "isoN:modality isoN:Shall" in (output / "part3-concept-phase.ttl").read_text(
        encoding="utf-8"
    )
    assert "这是作者自己的公开转述" in (output / "part1-vocabulary.ttl").read_text(
        encoding="utf-8"
    )

    for artifact in result.artifacts:
        payload = (output / artifact.relative_path).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == artifact.sha256
        assert len(payload) == artifact.size_bytes
    report = json.loads((output / "engraving-report.json").read_text())
    assert report["bundle_sha256"] == result.bundle_sha256
    assert report["semantic_dataset_sha256"] == result.semantic_dataset_sha256
    assert report["restricted_standard_text_included"] is False
    assert not any("/" in logical_id for logical_id in report["source_hashes"])

    runtime = SemanticRuntime(profile="rdf")
    runtime.load(output / "normative-tbox.ttl", format="turtle")
    runtime.load(output / "teaching-cases.ttl", format="turtle")
    runtime.load(output / "part1-vocabulary.ttl", format="turtle")
    runtime.load(output / "part3-concept-phase.ttl", format="turtle")
    assert runtime.quad_count > 0


def test_all_requested_inputs_preflight_before_output_creation(tmp_path):
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    _write_extract(controlled, 1, ["3.1 test term {}".format(SECRET)])
    book = tmp_path / "book"
    book.mkdir()
    _write_book(book)
    output = tmp_path / "engraved"

    with pytest.raises(NormativeInputError, match="Part 3"):
        engrave_normative_package(
            controlled_source_root=controlled,
            book_root=book,
            output_directory=output,
            parts=(1, 3),
        )
    assert not output.exists()


def test_existing_output_requires_explicit_overwrite_and_preserves_unrelated(tmp_path):
    controlled, book = _inputs(tmp_path)
    output = tmp_path / "engraved"
    output.mkdir()
    unrelated = output / "keep.txt"
    unrelated.write_text("keep", encoding="utf-8")
    with pytest.raises(NormativeOutputError, match="overwrite=True"):
        engrave_normative_package(
            controlled_source_root=controlled,
            book_root=book,
            output_directory=output,
            parts=(3,),
        )
    assert unrelated.read_text() == "keep"

    first = engrave_normative_package(
        controlled_source_root=controlled,
        book_root=book,
        output_directory=output,
        parts=(3,),
        overwrite=True,
    )
    assert first.parts[0].part == 3
    assert unrelated.read_text() == "keep"


def test_failed_overwrite_preflight_does_not_touch_existing_output(tmp_path):
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    _write_extract(controlled, 1, ["3.1 test term {}".format(SECRET)])
    book = tmp_path / "book"
    book.mkdir()
    _write_book(book)
    output = tmp_path / "engraved"
    output.mkdir()
    sentinel = output / "part1-cards.md"
    sentinel.write_text("old", encoding="utf-8")

    with pytest.raises(NormativeInputError, match="Part 3"):
        engrave_normative_package(
            controlled_source_root=controlled,
            book_root=book,
            output_directory=output,
            parts=(1, 3),
            overwrite=True,
        )
    assert sentinel.read_text() == "old"
    assert tuple(output.iterdir()) == (sentinel,)


def test_output_cannot_overlap_private_or_book_roots(tmp_path):
    controlled, book = _inputs(tmp_path)
    with pytest.raises(NormativeOutputError, match="controlled source root"):
        engrave_normative_package(
            controlled_source_root=controlled,
            book_root=book,
            output_directory=controlled / "derived",
            parts=(3,),
        )
    with pytest.raises(NormativeOutputError, match="book root"):
        engrave_normative_package(
            controlled_source_root=controlled,
            book_root=book,
            output_directory=book / "derived",
            parts=(3,),
        )


def test_standalone_main_requires_explicit_roots_and_output(tmp_path, capsys):
    controlled, book = _inputs(tmp_path)
    output = tmp_path / "engraved"
    assert (
        main(
            [
                "--source-root",
                str(controlled),
                "--book-root",
                str(book),
                "--output",
                str(output),
                "--part",
                "1",
            ]
        )
        == 0
    )
    stdout = capsys.readouterr().out
    assert '"restricted_standard_text_included":false' in stdout
