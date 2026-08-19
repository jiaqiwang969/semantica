"""Source-bounded normative engraver backed by Semantica package seeds.

The built-in ``vol2/normative`` semantic package supplies only the released
TBox, author-created glosses, and synthetic teaching-case seeds.  A book root
and a lawfully controlled standard-extract root are explicit external inputs;
neither is inferred from environment variables and standard text is never
copied to the output.

All inputs and the complete prospective output are validated in memory before
the first output byte is written.  A new output directory is then published as
one atomic directory rename.  Re-engraving an existing directory requires the
caller's explicit ``overwrite=True`` decision and uses atomic file replacement
without deleting unrelated files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import yaml

from semantica.ontology.lifecycle import canonical_json
from semantica.ontology.runtime import SemanticRuntime, SemanticRuntimeError


NORMATIVE_ENGRAVER_SCHEMA_VERSION = "1.0"
NORMATIVE_NAMESPACE = "https://ontology-engineering.local/iso26262/normative#"
_PACKAGE_ROOT = Path(__file__).resolve().parent
_BUILTIN_MANIFEST = _PACKAGE_ROOT / "vol2" / "normative" / "manifest.yaml"
_PART_EXTRACTS = {
    1: Path(
        "part-01-vocabulary/native-full/ISO 26262-1-2018/auto/"
        "ISO 26262-1-2018_content_list_v2.json"
    ),
    3: Path(
        "part-03-concept-phase/native-full/ISO 26262-3-2018/auto/"
        "ISO 26262-3-2018_content_list_v2.json"
    ),
}
_BOOK_GLOSSARY = Path("appendices/appendix-c-glossary.md")
_PREFIX = (
    "@prefix isoN: <{}> .\n@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\n"
).format(NORMATIVE_NAMESPACE)


class NormativeEngravingError(RuntimeError):
    """Base error for preflight, seed, and publication failures."""


class NormativeInputError(NormativeEngravingError):
    """Raised when an external controlled/book input is missing or ambiguous."""


class NormativeOutputError(NormativeEngravingError):
    """Raised when the explicit output target is unsafe or would be overwritten."""


@dataclass(frozen=True)
class NormativeArtifactDTO:
    """Hash-bound public/derived output artifact."""

    relative_path: str
    media_type: str
    sha256: str
    size_bytes: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "media_type": self.media_type,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class NormativePartResultDTO:
    """Coverage counts for one engraved standard Part."""

    part: int
    unit_count: int
    glossed_count: int
    pending_count: int

    def as_dict(self) -> Dict[str, int]:
        return {
            "part": self.part,
            "unit_count": self.unit_count,
            "glossed_count": self.glossed_count,
            "pending_count": self.pending_count,
        }


@dataclass(frozen=True)
class NormativeEngravingResultDTO:
    """Stable content receipt returned by one engraving run."""

    package_id: str
    package_version: str
    package_digest: str
    parts: Tuple[NormativePartResultDTO, ...]
    source_hashes: Tuple[Tuple[str, str], ...]
    artifacts: Tuple[NormativeArtifactDTO, ...]
    bundle_sha256: str
    semantic_dataset_sha256: str
    output_directory: str
    restricted_standard_text_included: bool = False
    schema_version: str = NORMATIVE_ENGRAVER_SCHEMA_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "package_digest": self.package_digest,
            "parts": [item.as_dict() for item in self.parts],
            "source_hashes": dict(self.source_hashes),
            "artifacts": [item.as_dict() for item in self.artifacts],
            "bundle_sha256": self.bundle_sha256,
            "semantic_dataset_sha256": self.semantic_dataset_sha256,
            "output_directory": self.output_directory,
            "restricted_standard_text_included": self.restricted_standard_text_included,
        }


@dataclass(frozen=True)
class _BuiltinSeeds:
    package_id: str
    package_version: str
    package_digest: str
    tbox: bytes
    glosses: Mapping[str, Any]
    cases: Mapping[str, Any]
    source_hashes: Tuple[Tuple[str, str], ...]


def engrave_normative_package(
    *,
    controlled_source_root: Union[str, os.PathLike],
    book_root: Union[str, os.PathLike],
    output_directory: Union[str, os.PathLike],
    parts: Iterable[int] = (1, 3),
    overwrite: bool = False,
) -> NormativeEngravingResultDTO:
    """Engrave source coordinates, modalities, and released glosses.

    Args:
        controlled_source_root: Explicit private root containing the authorized
            structured extracts.  Only hashes, clause coordinates, and inferred
            modality categories leave this boundary.
        book_root: Explicit external two-volume book root.  Part 1 author-created
            glossary entries are read from ``appendices/appendix-c-glossary.md``.
        output_directory: Explicit candidate release directory.
        parts: Supported values are 1 and 3.
        overwrite: Required to atomically replace generated files in an
            existing output directory.  No unrelated file is deleted.
    """

    selected_parts = _normalize_parts(parts)
    controlled_root = _regular_directory(
        controlled_source_root, "controlled_source_root"
    )
    external_book_root = _regular_directory(book_root, "book_root")
    output = Path(output_directory).expanduser().resolve()
    _preflight_output_location(output, controlled_root, external_book_root, overwrite)

    seeds = _load_builtin_seeds()
    extracts: Dict[int, Tuple[Path, bytes, Tuple[Tuple[int, int, str], ...]]] = {}
    source_hashes: Dict[str, str] = dict(seeds.source_hashes)
    for part in selected_parts:
        path = _contained_regular_file(
            controlled_root,
            _PART_EXTRACTS[part],
            "controlled Part {} extract".format(part),
        )
        payload = path.read_bytes()
        blocks = _extract_blocks(payload, logical_id="controlled.part{}".format(part))
        if not blocks:
            raise NormativeInputError(
                "controlled Part {} extract contains no readable text blocks".format(
                    part
                )
            )
        extracts[part] = (path, payload, blocks)
        source_hashes["controlled.part{}.extract".format(part)] = _sha256(payload)

    book_glossary: Optional[str] = None
    if 1 in selected_parts:
        glossary_path = _contained_regular_file(
            external_book_root, _BOOK_GLOSSARY, "book Part 1 glossary"
        )
        glossary_payload = glossary_path.read_bytes()
        try:
            book_glossary = glossary_payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NormativeInputError("book Part 1 glossary must be UTF-8") from exc
        source_hashes["book.appendix-c-glossary"] = _sha256(glossary_payload)

    # Everything below is still in-memory preflight.  No output exists yet.
    artifacts: Dict[str, bytes] = {"normative-tbox.ttl": seeds.tbox}
    artifacts["teaching-cases.ttl"] = _emit_cases_ttl(seeds.cases).encode("utf-8")
    part_results: List[NormativePartResultDTO] = []
    if 1 in selected_parts:
        if book_glossary is None:
            raise NormativeInputError("Part 1 requires the external book glossary")
        part1_artifacts, part1_result = _engrave_part1(
            book_glossary, extracts[1][2], seeds.cases
        )
        artifacts.update(part1_artifacts)
        part_results.append(part1_result)
    if 3 in selected_parts:
        part3_artifacts, part3_result = _engrave_part3(extracts[3][2], seeds.glosses)
        artifacts.update(part3_artifacts)
        part_results.append(part3_result)

    semantic_dataset_sha256 = _validate_generated_rdf(artifacts)

    artifact_dtos = tuple(
        NormativeArtifactDTO(
            relative_path=name,
            media_type=_media_type(name),
            sha256=_sha256(payload),
            size_bytes=len(payload),
        )
        for name, payload in sorted(artifacts.items())
    )
    bundle_content = {
        "schema_version": NORMATIVE_ENGRAVER_SCHEMA_VERSION,
        "package_id": seeds.package_id,
        "package_version": seeds.package_version,
        "package_digest": seeds.package_digest,
        "parts": [
            item.as_dict() for item in sorted(part_results, key=lambda item: item.part)
        ],
        "source_hashes": dict(sorted(source_hashes.items())),
        "artifacts": [item.as_dict() for item in artifact_dtos],
        "semantic_dataset_sha256": semantic_dataset_sha256,
        "restricted_standard_text_included": False,
    }
    bundle_sha256 = _sha256(canonical_json(bundle_content).encode("utf-8"))
    report = {**bundle_content, "bundle_sha256": bundle_sha256}
    report_payload = (canonical_json(report) + "\n").encode("utf-8")
    artifacts["engraving-report.json"] = report_payload

    # Recheck the target at the final side-effect boundary, then publish.
    _preflight_target_files(
        output,
        artifacts,
        overwrite,
        controlled_root=controlled_root,
        book_root=external_book_root,
    )
    _publish_artifacts(output, artifacts, overwrite=overwrite)
    return NormativeEngravingResultDTO(
        package_id=seeds.package_id,
        package_version=seeds.package_version,
        package_digest=seeds.package_digest,
        parts=tuple(sorted(part_results, key=lambda item: item.part)),
        source_hashes=tuple(sorted(source_hashes.items())),
        artifacts=tuple(
            sorted(
                artifact_dtos
                + (
                    NormativeArtifactDTO(
                        relative_path="engraving-report.json",
                        media_type="application/json",
                        sha256=_sha256(report_payload),
                        size_bytes=len(report_payload),
                    ),
                ),
                key=lambda item: item.relative_path,
            )
        ),
        bundle_sha256=bundle_sha256,
        semantic_dataset_sha256=semantic_dataset_sha256,
        output_directory=str(output),
    )


def _load_builtin_seeds() -> _BuiltinSeeds:
    try:
        runtime = SemanticRuntime(profile="rdf")
        loaded = runtime.load_package(_BUILTIN_MANIFEST)
    except (SemanticRuntimeError, OSError) as exc:
        raise NormativeInputError(
            "built-in normative semantic package failed content verification"
        ) from exc
    by_id = {asset.asset_id: asset for asset in loaded.assets}
    required = (
        "normative-tbox",
        "gloss-part3-glosses",
        "gloss-teaching-cases",
    )
    missing = [asset_id for asset_id in required if asset_id not in by_id]
    if missing:
        raise NormativeInputError(
            "built-in normative package is missing seed assets: {}".format(
                ", ".join(missing)
            )
        )
    try:
        glosses = yaml.safe_load(by_id["gloss-part3-glosses"].text())
    except Exception as exc:
        raise NormativeInputError(
            "built-in normative gloss seed YAML is invalid"
        ) from exc
    # The teaching-case seed is a byte-preserved migration artifact from the
    # book package.  One historical plain scalar starts with a quoted phrase
    # followed by unquoted text, which strict YAML rejects.  Parse only its
    # explicitly bounded ``id/ch/teaches/summary`` contract instead of
    # rewriting the source-derived bytes or accepting general unsafe YAML.
    cases = _parse_teaching_case_seed(by_id["gloss-teaching-cases"].text())
    if not isinstance(glosses, Mapping) or not isinstance(cases, Mapping):
        raise NormativeInputError("built-in normative seeds must be YAML mappings")
    _validate_glosses(glosses)
    _validate_cases(cases)
    return _BuiltinSeeds(
        package_id=loaded.identity.package_id,
        package_version=loaded.identity.version,
        package_digest=loaded.identity.digest,
        tbox=by_id["normative-tbox"].content,
        glosses=glosses,
        cases=cases,
        source_hashes=tuple(
            sorted(
                (
                    ("seed.normative-tbox", by_id["normative-tbox"].sha256),
                    (
                        "seed.part3-glosses",
                        by_id["gloss-part3-glosses"].sha256,
                    ),
                    (
                        "seed.teaching-cases",
                        by_id["gloss-teaching-cases"].sha256,
                    ),
                )
            )
        ),
    )


def _parse_teaching_case_seed(text: str) -> Mapping[str, Any]:
    cases: Dict[str, Dict[str, Any]] = {}
    current_id: Optional[str] = None
    current: Optional[Dict[str, Any]] = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        identifier = re.match(r"^([a-z0-9-]+):\s*$", line)
        if identifier:
            current_id = identifier.group(1)
            if current_id in cases:
                raise NormativeInputError("teaching-case seed contains duplicate id")
            current = {}
            cases[current_id] = current
            continue
        field = re.match(r"^\s{2}(ch|teaches|summary):\s*(.*)$", line)
        if field and current is not None:
            key, raw_value = field.group(1), field.group(2).strip()
            if key in current:
                raise NormativeInputError(
                    "teaching-case seed duplicates {} at line {}".format(
                        key, line_number
                    )
                )
            if key == "teaches":
                if not raw_value.startswith("[") or not raw_value.endswith("]"):
                    raise NormativeInputError("teaching-case teaches must use a list")
                current[key] = [
                    item.strip() for item in raw_value[1:-1].split(",") if item.strip()
                ]
            else:
                current[key] = raw_value
            continue
        raise NormativeInputError(
            "teaching-case seed has unsupported syntax at line {}".format(line_number)
        )
    return cases


def _extract_blocks(
    payload: bytes, *, logical_id: str
) -> Tuple[Tuple[int, int, str], ...]:
    try:
        data = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise NormativeInputError(
            "{} is not valid UTF-8 JSON".format(logical_id)
        ) from exc
    if not isinstance(data, list):
        raise NormativeInputError("{} extract root must be a list".format(logical_id))
    result = []
    for page_index, page in enumerate(data):
        if not isinstance(page, list):
            raise NormativeInputError(
                "{} page {} must be a list".format(logical_id, page_index)
            )
        for block_index, block in enumerate(page):
            if not isinstance(block, Mapping):
                raise NormativeInputError(
                    "{} block {}/{} must be a mapping".format(
                        logical_id, page_index, block_index
                    )
                )
            content = block.get("content") or {}
            if not isinstance(content, Mapping):
                raise NormativeInputError(
                    "{} block content must be a mapping".format(logical_id)
                )
            pieces = []
            for values in content.values():
                if not isinstance(values, list):
                    continue
                for item in values:
                    if isinstance(item, Mapping) and item.get("content") is not None:
                        pieces.append(str(item["content"]))
            text = " ".join(pieces).strip()
            if text:
                result.append((page_index, block_index, text))
    return tuple(result)


def _validate_generated_rdf(artifacts: Mapping[str, bytes]) -> str:
    """Parse every prospective Turtle artifact before any output is written."""

    runtime = SemanticRuntime(profile="rdf")
    try:
        for name, payload in sorted(artifacts.items()):
            if name.endswith(".ttl"):
                runtime.load(payload, format="turtle", base_uri=NORMATIVE_NAMESPACE)
        snapshot = runtime.snapshot(created_at="1970-01-01T00:00:00Z")
    except SemanticRuntimeError as exc:
        raise NormativeInputError(
            "generated normative RDF failed Semantica preflight"
        ) from exc
    return snapshot.dataset_sha256


def _engrave_part1(
    glossary_text: str,
    blocks: Sequence[Tuple[int, int, str]],
    cases: Mapping[str, Any],
) -> Tuple[Dict[str, bytes], NormativePartResultDTO]:
    units = _mine_part1_glossary(glossary_text)
    if not units:
        raise NormativeInputError(
            "book Part 1 glossary contains no recognized term cards"
        )
    index: Dict[int, Tuple[int, int]] = {}
    for page_index, block_index, text in blocks:
        match = re.match(r"^3\.(\d+)(?:\s|$)", text)
        if match:
            number = int(match.group(1))
            if number in index and index[number] != (page_index, block_index):
                raise NormativeInputError(
                    "controlled Part 1 extract has ambiguous anchor for 3.{}".format(
                        number
                    )
                )
            index[number] = (page_index, block_index)
    missing = [unit["num"] for unit in units if unit["num"] not in index]
    if missing:
        raise NormativeInputError(
            "controlled Part 1 extract lacks anchors for terms: {}".format(
                ", ".join("3.{}".format(item) for item in missing)
            )
        )
    for unit in units:
        unit["anchor"] = index[unit["num"]]
        case_id = _link_case(
            "{} {}".format(unit["zh"], unit["en"]), unit["gloss"], cases
        )
        if case_id is not None:
            unit["case_id"] = case_id
            case = cases[case_id]
            unit["taught"] = "[{}] {}".format(
                case.get("ch", ""), case.get("summary", "")
            )

    ttl = [
        _PREFIX,
        "# Part 1 terms: author glosses plus controlled-source coordinates; no standard text.\n",
    ]
    cards = [
        "# ISO 26262 Part 1 术语卡（本体化刻录 · 卡片视图）\n",
        "> 自动生成；转述来自外部书侧作者内容，非标准原文。\n",
    ]
    for unit in sorted(units, key=lambda item: item["num"]):
        iri = "isoN:P1_T{}".format(unit["num"])
        page_index, block_index = unit["anchor"]
        ttl.append("{} a isoN:TermDefinition ;".format(iri))
        ttl.append(
            "    isoN:clauseId {} ; isoN:partNumber 1 ;".format(
                _literal("1-3.{}".format(unit["num"]))
            )
        )
        ttl.append(
            "    rdfs:label {}@zh ; isoN:enLabel {} ;".format(
                _literal(unit["zh"]), _literal(unit["en"])
            )
        )
        ttl.append('    isoN:modality isoN:Definition ; isoN:glossStatus "glossed" ;')
        if unit.get("serves"):
            ttl.append("    isoN:servesChapter {} ;".format(_literal(unit["serves"])))
        ttl.append(
            "    isoN:pageIndex {} ; isoN:blockIndex {} ;".format(
                page_index, block_index
            )
        )
        if unit.get("case_id"):
            ttl.append(
                "    isoN:taughtBy isoN:Case_{} ;".format(
                    str(unit["case_id"]).replace("-", "_")
                )
            )
        ttl.append("    isoN:zhGloss {} .\n".format(_literal(unit["gloss"])))
        cards.append(
            "### 1-3.{} {}（{}）｜术语".format(unit["num"], unit["zh"], unit["en"])
        )
        cards.append("转述：{}".format(unit["gloss"]))
        if unit.get("taught"):
            cards.append("书中讲法：{}".format(unit["taught"]))
        cards.append(
            "映射：{} ｜ 提取件锚点：p{}/b{}\n".format(
                unit.get("serves") or "—", page_index, block_index
            )
        )
    numbers = sorted(unit["num"] for unit in units)
    ttl.extend(
        [
            "isoN:Coverage_P1 a isoN:CoverageDeclaration ; isoN:partNumber 1 ;",
            "    isoN:coversRange {} ; isoN:unitCount {} ;".format(
                _literal("1-3.{} 至 1-3.{}".format(numbers[0], numbers[-1])),
                len(units),
            ),
            "    rdfs:comment {}@zh .".format(
                _literal("本层只声明已刻录范围；范围外须回受控标准来源核对。")
            ),
        ]
    )
    cards.insert(
        2,
        "> **覆盖声明**：本层收录词条 1-3.{} 至 1-3.{} 共 {} 条；范围外须回受控标准来源核对。\n".format(
            numbers[0], numbers[-1], len(units)
        ),
    )
    return (
        {
            "part1-vocabulary.ttl": ("\n".join(ttl) + "\n").encode("utf-8"),
            "part1-cards.md": ("\n".join(cards) + "\n").encode("utf-8"),
        },
        NormativePartResultDTO(
            part=1,
            unit_count=len(units),
            glossed_count=len(units),
            pending_count=0,
        ),
    )


def _engrave_part3(
    blocks: Sequence[Tuple[int, int, str]], glosses: Mapping[str, Any]
) -> Tuple[Dict[str, bytes], NormativePartResultDTO]:
    units: Dict[str, Dict[str, Any]] = {}
    for page_index, block_index, text in blocks:
        match = re.match(r"^(\d+(?:\.\d+)+)[\s\t]+(\S.*)$", text)
        if not match:
            continue
        clause_id = match.group(1)
        if len(clause_id.split(".")) < 2:
            continue
        candidate = {
            "clause_id": clause_id,
            "page_index": page_index,
            "block_index": block_index,
            "modality": _modality_of(text),
        }
        if clause_id in units and units[clause_id] != candidate:
            raise NormativeInputError(
                "controlled Part 3 extract has ambiguous heading for {}".format(
                    clause_id
                )
            )
        units[clause_id] = candidate
    if not units:
        raise NormativeInputError(
            "controlled Part 3 extract contains no clause headings"
        )
    ttl = [
        _PREFIX,
        "# Part 3 skeleton: controlled-source coordinates/modalities plus released gloss seeds; no standard text.\n",
    ]
    cards = [
        "# ISO 26262 Part 3 条款卡（本体化刻录 · 卡片视图）\n",
        "> 骨架来自受控提取件坐标；转述来自内建公开 seed；不含标准原文。\n",
    ]
    glossed = 0
    for clause_id in sorted(units, key=_clause_sort_key):
        unit = units[clause_id]
        gloss = glosses.get(clause_id)
        iri = "isoN:P3_{}".format(clause_id.replace(".", "_"))
        ttl.append("{} a isoN:NormativeUnit ;".format(iri))
        ttl.append(
            "    isoN:clauseId {} ; isoN:partNumber 3 ;".format(
                _literal("3-{}".format(clause_id))
            )
        )
        ttl.append("    isoN:modality isoN:{} ;".format(unit["modality"]))
        ttl.append(
            "    isoN:pageIndex {} ; isoN:blockIndex {} ;".format(
                unit["page_index"], unit["block_index"]
            )
        )
        if gloss is None:
            ttl.append('    isoN:glossStatus "pending" .\n')
            continue
        glossed += 1
        keywords = "、".join(gloss.get("keywords", ()))
        book = "、".join(gloss.get("book", ()))
        ttl.append("    isoN:zhGloss {} ;".format(_literal(gloss["zh"])))
        if keywords:
            ttl.append("    isoN:keywords {} ;".format(_literal(keywords)))
        if book:
            ttl.append("    isoN:servesChapter {} ;".format(_literal(book)))
        ttl.append('    isoN:glossStatus "glossed" .\n')
        cards.append("### 3-{}｜{}｜glossed".format(clause_id, unit["modality"]))
        cards.append("转述：{}".format(gloss["zh"]))
        cards.append(
            "关键词：{} ｜ 映射：{} ｜ 锚点：p{}/b{}\n".format(
                keywords or "—",
                book or "—",
                unit["page_index"],
                unit["block_index"],
            )
        )
    pending = len(units) - glossed
    cards.append(
        "---\n骨架总数：{} ｜ 已刻转述：{} ｜ 待刻：{}".format(
            len(units), glossed, pending
        )
    )
    return (
        {
            "part3-concept-phase.ttl": ("\n".join(ttl) + "\n").encode("utf-8"),
            "part3-cards.md": ("\n".join(cards) + "\n").encode("utf-8"),
        },
        NormativePartResultDTO(
            part=3,
            unit_count=len(units),
            glossed_count=glossed,
            pending_count=pending,
        ),
    )


def _mine_part1_glossary(text: str) -> List[Dict[str, Any]]:
    pattern = re.compile(
        r"^- \*\*(?P<zh>[^（*]+)（(?P<en>[^）]+)）\*\*"
        r"（1-3\.(?P<num>\d+)(?P<meta>[^）]*)）——(?P<gloss>.+)$",
        re.MULTILINE,
    )
    units = []
    seen = set()
    for match in pattern.finditer(text):
        number = int(match.group("num"))
        if number in seen:
            raise NormativeInputError(
                "book Part 1 glossary duplicates term 1-3.{}".format(number)
            )
        seen.add(number)
        units.append(
            {
                "num": number,
                "zh": match.group("zh").strip(),
                "en": match.group("en").strip(),
                "gloss": re.sub(r"\*\*", "", match.group("gloss")).strip(),
                "serves": ",".join(re.findall(r"ch\d+", match.group("meta"))),
            }
        )
    return units


def _emit_cases_ttl(cases: Mapping[str, Any]) -> str:
    lines = [_PREFIX, "# Released synthetic teaching-case layer.\n"]
    for case_id in sorted(cases):
        case = cases[case_id]
        iri = "isoN:Case_{}".format(case_id.replace("-", "_"))
        lines.append("{} a isoN:TeachingCase ;".format(iri))
        lines.append("    isoN:inChapter {} ;".format(_literal(case.get("ch", ""))))
        lines.append(
            "    isoN:teachesConcepts {} ;".format(
                _literal("、".join(case.get("teaches", ())))
            )
        )
        lines.append(
            "    isoN:caseSummary {} .\n".format(_literal(case.get("summary", "")))
        )
    return "\n".join(lines) + "\n"


def _link_case(
    name: str, gloss: str, cases: Mapping[str, Any], *, threshold: int = 4
) -> Optional[str]:
    best: Optional[str] = None
    score = 0
    for case_id in sorted(cases):
        candidate_score = 0
        for keyword in cases[case_id].get("teaches", ()):
            if keyword in name:
                candidate_score += 3 * len(keyword)
            elif keyword in gloss:
                candidate_score += len(keyword)
        if candidate_score > score:
            best, score = case_id, candidate_score
    return best if score >= threshold else None


def _validate_glosses(glosses: Mapping[str, Any]) -> None:
    for clause_id, raw in glosses.items():
        if not isinstance(clause_id, str) or not re.match(
            r"^\d+(?:\.\d+)+$", clause_id
        ):
            raise NormativeInputError("invalid Part 3 gloss clause id")
        if (
            not isinstance(raw, Mapping)
            or not isinstance(raw.get("zh"), str)
            or not raw["zh"].strip()
        ):
            raise NormativeInputError("Part 3 gloss requires non-empty zh text")
        for field in ("keywords", "book"):
            value = raw.get(field, [])
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise NormativeInputError(
                    "Part 3 gloss {} must be a text list".format(field)
                )


def _validate_cases(cases: Mapping[str, Any]) -> None:
    for case_id, raw in cases.items():
        if not isinstance(case_id, str) or not re.match(r"^[a-z0-9-]+$", case_id):
            raise NormativeInputError("teaching case id must use lowercase kebab-case")
        if not isinstance(raw, Mapping):
            raise NormativeInputError("teaching case seed must be a mapping")
        if (
            not isinstance(raw.get("ch"), str)
            or not raw["ch"].strip()
            or not isinstance(raw.get("summary"), str)
            or not raw["summary"].strip()
        ):
            raise NormativeInputError("teaching case requires ch and summary text")
        teaches = raw.get("teaches")
        if (
            not isinstance(teaches, list)
            or not teaches
            or not all(isinstance(item, str) and item for item in teaches)
        ):
            raise NormativeInputError("teaching case requires non-empty teaches list")


def _modality_of(text: str) -> str:
    stripped = text.strip()
    upper = stripped.upper()
    if upper.startswith("NOTE"):
        return "Note"
    if upper.startswith("EXAMPLE"):
        return "Example"
    lowered = " {} ".format(stripped.lower())
    if re.search(r"\bshall\b", lowered):
        return "Shall"
    if re.search(r"\bshould\b", lowered):
        return "Should"
    if re.search(r"\bmay\b", lowered) or " can be " in lowered:
        return "May"
    return "Structural"


def _normalize_parts(parts: Iterable[int]) -> Tuple[int, ...]:
    try:
        values = tuple(parts)
    except TypeError as exc:
        raise NormativeInputError("parts must be an iterable of integers") from exc
    if not values:
        raise NormativeInputError("at least one Part must be selected")
    if any(not isinstance(item, int) or isinstance(item, bool) for item in values):
        raise NormativeInputError("Part identifiers must be integers")
    if len(set(values)) != len(values):
        raise NormativeInputError("duplicate Part identifiers are not allowed")
    unsupported = sorted(set(values) - set(_PART_EXTRACTS))
    if unsupported:
        raise NormativeInputError(
            "unsupported Parts: {}".format(", ".join(str(item) for item in unsupported))
        )
    return tuple(sorted(values))


def _regular_directory(value: Union[str, os.PathLike], field: str) -> Path:
    raw = Path(value).expanduser()
    if raw.is_symlink():
        raise NormativeInputError("{} must not be a symlink".format(field))
    path = raw.resolve()
    if not path.is_dir():
        raise NormativeInputError("{} is not a directory: {}".format(field, path))
    return path


def _contained_regular_file(root: Path, relative: Path, label: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise NormativeInputError("{} escapes its declared root".format(label)) from exc
    if path.is_symlink() or not path.is_file():
        raise NormativeInputError("{} is missing: {}".format(label, relative))
    return path


def _preflight_output_location(
    output: Path, controlled_root: Path, book_root: Path, overwrite: bool
) -> None:
    if output.is_symlink():
        raise NormativeOutputError("output_directory must not be a symlink")
    if output.exists() and not output.is_dir():
        raise NormativeOutputError("output_directory exists and is not a directory")
    for protected, label in (
        (controlled_root, "controlled source root"),
        (book_root, "book root"),
        (_PACKAGE_ROOT, "built-in package root"),
    ):
        if _paths_overlap(output, protected):
            raise NormativeOutputError(
                "output_directory must not overlap {}".format(label)
            )
    if output.exists() and not overwrite:
        raise NormativeOutputError(
            "output_directory already exists; explicit overwrite=True is required"
        )
    if not output.parent.is_dir():
        raise NormativeOutputError("output_directory parent must already exist")


def _preflight_target_files(
    output: Path,
    artifacts: Mapping[str, bytes],
    overwrite: bool,
    *,
    controlled_root: Path,
    book_root: Path,
) -> None:
    _preflight_output_location(output, controlled_root, book_root, overwrite)
    if not output.exists():
        return
    for name in artifacts:
        target = output / name
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise NormativeOutputError(
                "generated target is not a replaceable regular file: {}".format(name)
            )


def _publish_artifacts(
    output: Path, artifacts: Mapping[str, bytes], *, overwrite: bool
) -> None:
    if not output.exists():
        stage = Path(
            tempfile.mkdtemp(
                prefix=".{}.engraving-".format(output.name), dir=str(output.parent)
            )
        )
        try:
            for name, payload in sorted(artifacts.items()):
                _write_new(stage / name, payload)
            if output.exists() or output.is_symlink():
                raise NormativeOutputError(
                    "output_directory appeared during publication"
                )
            os.rename(str(stage), str(output))
            return
        except Exception:
            if stage.exists():
                shutil.rmtree(str(stage))
            raise
    if not overwrite:
        raise NormativeOutputError("existing output requires explicit overwrite=True")
    stage = Path(
        tempfile.mkdtemp(prefix=".semantica-engraving-", dir=str(output.parent))
    )
    try:
        for name, payload in sorted(artifacts.items()):
            _write_new(stage / name, payload)
        for name in sorted(artifacts):
            os.replace(str(stage / name), str(output / name))
    finally:
        if stage.exists():
            shutil.rmtree(str(stage))


def _write_new(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise NormativeOutputError("refusing to overwrite staged artifact") from exc


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        first.relative_to(second)
        return True
    except ValueError:
        pass
    try:
        second.relative_to(first)
        return True
    except ValueError:
        return False


def _literal(value: Any) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _media_type(name: str) -> str:
    if name.endswith(".ttl"):
        return "text/turtle"
    if name.endswith(".md"):
        return "text/markdown"
    if name.endswith(".json"):
        return "application/json"
    return "application/octet-stream"


def _clause_sort_key(value: str) -> Tuple[int, ...]:
    return tuple(int(item) for item in value.split("."))


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the standalone normative engraver CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--book-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--part", type=int, action="append", dest="parts")
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run ``python -m semantica.chapter_packages.normative``."""

    args = build_argument_parser().parse_args(argv)
    try:
        result = engrave_normative_package(
            controlled_source_root=args.source_root,
            book_root=args.book_root,
            output_directory=args.output,
            parts=args.parts or (1, 3),
            overwrite=args.overwrite,
        )
        print(canonical_json(result.as_dict()))
        return 0
    except NormativeEngravingError as exc:
        print(str(exc), file=sys.stderr)
        return 1


__all__ = [
    "NORMATIVE_ENGRAVER_SCHEMA_VERSION",
    "NormativeArtifactDTO",
    "NormativeEngravingError",
    "NormativeEngravingResultDTO",
    "NormativeInputError",
    "NormativeOutputError",
    "NormativePartResultDTO",
    "build_argument_parser",
    "engrave_normative_package",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
