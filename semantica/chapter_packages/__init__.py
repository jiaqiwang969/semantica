"""Built-in, source-grounded semantic chapter packages.

The books remain the external specification.  This module is the Semantica
control surface for discovering and loading their executable chapter assets;
callers do not need to know package-data paths or reach into RDF backends.
"""

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Optional, Tuple

import yaml


class ChapterPackageError(RuntimeError):
    """Base error for the built-in chapter-package registry."""


class ChapterPackageNotFoundError(ChapterPackageError):
    """Raised when a volume/chapter key is not in the built-in registry."""


class ChapterPackageAssetError(ChapterPackageError):
    """Raised when an asset is absent or has the wrong semantic role."""


class ChapterContractValidationError(ChapterPackageError):
    """Raised when a built-in chapter contract violates the common policy."""


@dataclass(frozen=True)
class BookSourceCheckDTO:
    """One fail-closed check against an external book or generated TeX source."""

    check_id: str
    package_id: str
    source_anchor: str
    expected_sha256: str
    actual_sha256: Optional[str]
    status: str
    reason: Optional[str] = None

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "actual_sha256": self.actual_sha256,
            "check_id": self.check_id,
            "expected_sha256": self.expected_sha256,
            "package_id": self.package_id,
            "reason": self.reason,
            "source_anchor": self.source_anchor,
            "status": self.status,
        }


@dataclass(frozen=True)
class BookSourceVerificationDTO:
    """Aggregate result for the 29 chapter-to-book source bindings."""

    checks: Tuple[BookSourceCheckDTO, ...]
    schema_version: str = "1.0"

    @property
    def status(self) -> str:
        return "passed" if self.checks and all(
            item.status == "passed" for item in self.checks
        ) else "blocked"

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "check_count": len(self.checks),
            "checks": [item.as_dict() for item in self.checks],
            "passed": self.passed,
            "schema_version": self.schema_version,
            "status": self.status,
        }


@dataclass(frozen=True)
class ChapterPackageDescriptor:
    """Stable discovery record for one built-in chapter package."""

    volume: str
    chapter: str
    package_id: str
    version: str
    title: str
    status: str
    release_status: str
    manifest_path: Path

    @property
    def key(self) -> str:
        return "{}.{}".format(self.volume, self.chapter)


@dataclass(frozen=True)
class DomainPackageDescriptor:
    """Stable discovery record for a non-chapter semantic package."""

    package_id: str
    version: str
    domain: str
    status: str
    release_status: str
    manifest_path: Path


@dataclass(frozen=True)
class MigrationSuccessorDTO:
    """One audited old-path to Semantica package-asset successor binding."""

    volume: str
    old_path: str
    old_sha256: str
    package_id: str
    asset_id: str
    successor_sha256: str
    relation: str
    successor_path: Optional[str] = None
    source_fragment: Optional[str] = None
    strict_gate_asset: Optional[bool] = None

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "volume": self.volume,
            "old_path": self.old_path,
            "old_sha256": self.old_sha256,
            "package_id": self.package_id,
            "asset_id": self.asset_id,
            "successor_sha256": self.successor_sha256,
            "relation": self.relation,
            "successor_path": self.successor_path,
            "source_fragment": self.source_fragment,
            "strict_gate_asset": self.strict_gate_asset,
        }


@dataclass(frozen=True)
class RetiredRuntimeEntryDTO:
    """Audited legacy runtime entry intentionally not copied as an asset."""

    legacy_path: str
    copied_as_runtime: bool
    replacement_entry: str
    reason: str
    replacement_assets: Tuple[str, ...] = ()

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "legacy_path": self.legacy_path,
            "copied_as_runtime": self.copied_as_runtime,
            "replacement_entry": self.replacement_entry,
            "replacement_assets": list(self.replacement_assets),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class MigrationMapDTO:
    """Normalized, immutable view of one volume's migration ledger."""

    volume: str
    source_sha256: str
    entries: Tuple[MigrationSuccessorDTO, ...]
    retired_runtime_entries: Tuple[RetiredRuntimeEntryDTO, ...] = ()
    schema_version: str = "1.0"

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @property
    def retired_runtime_entry_count(self) -> int:
        return len(self.retired_runtime_entries)

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "schema_version": self.schema_version,
            "volume": self.volume,
            "source_sha256": self.source_sha256,
            "entry_count": self.entry_count,
            "entries": [item.as_dict() for item in self.entries],
            "retired_runtime_entry_count": self.retired_runtime_entry_count,
            "retired_runtime_entries": [
                item.as_dict() for item in self.retired_runtime_entries
            ],
        }


@dataclass(frozen=True)
class MigrationResolutionDTO:
    """All successor candidates for one exact legacy path."""

    old_path: str
    candidates: Tuple[MigrationSuccessorDTO, ...]

    @property
    def resolved(self) -> bool:
        return bool(self.candidates)

    @property
    def ambiguous(self) -> bool:
        return len(self.candidates) > 1

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "old_path": self.old_path,
            "resolved": self.resolved,
            "ambiguous": self.ambiguous,
            "candidates": [item.as_dict() for item in self.candidates],
        }


_ROOT = Path(__file__).resolve().parent
_REGISTRY = _ROOT / "registry.yaml"


def _load_yaml_mapping(path: Path) -> Mapping[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ChapterPackageError(
            "failed to read chapter package metadata: {}".format(path)
        ) from exc
    if not isinstance(value, Mapping):
        raise ChapterPackageError(
            "chapter package metadata must be a mapping: {}".format(path)
        )
    return value


@lru_cache(maxsize=1)
def _descriptors() -> Tuple[ChapterPackageDescriptor, ...]:
    registry = _load_yaml_mapping(_REGISTRY)
    if str(registry.get("schema_version")) != "1.0":
        raise ChapterPackageError("unsupported chapter-package registry schema")
    raw_packages = registry.get("packages")
    if not isinstance(raw_packages, list):
        raise ChapterPackageError("chapter-package registry requires packages")

    descriptors = []
    seen = set()
    for raw in raw_packages:
        if not isinstance(raw, Mapping):
            raise ChapterPackageError("chapter-package entry must be a mapping")
        volume = str(raw.get("volume", ""))
        chapter = str(raw.get("chapter", ""))
        key = (volume, chapter)
        if not volume or not chapter or key in seen:
            raise ChapterPackageError(
                "invalid or duplicate chapter-package key: {!r}".format(key)
            )
        seen.add(key)
        relative = Path(str(raw.get("manifest", "")))
        manifest = (_ROOT / relative).resolve()
        try:
            manifest.relative_to(_ROOT)
        except ValueError as exc:
            raise ChapterPackageError("manifest path escapes registry root") from exc
        if not manifest.is_file():
            raise ChapterPackageError(
                "chapter-package manifest is missing: {}".format(relative)
            )
        descriptors.append(
            ChapterPackageDescriptor(
                volume=volume,
                chapter=chapter,
                package_id=str(raw.get("package_id", "")),
                version=str(raw.get("version", "")),
                title=str(raw.get("title", "")),
                status=str(raw.get("status", "")),
                release_status=str(raw.get("release_status", "")),
                manifest_path=manifest,
            )
        )
    return tuple(sorted(descriptors, key=lambda item: (item.volume, item.chapter)))


def list_chapter_packages(
    volume: Optional[str] = None,
) -> Tuple[ChapterPackageDescriptor, ...]:
    """List built-in packages, optionally restricted to one volume."""

    packages = _descriptors()
    if volume is None:
        return packages
    return tuple(item for item in packages if item.volume == volume)


def get_chapter_package(volume: str, chapter: str) -> ChapterPackageDescriptor:
    """Resolve one exact built-in package; absence fails closed."""

    for descriptor in _descriptors():
        if descriptor.volume == volume and descriptor.chapter == chapter:
            return descriptor
    raise ChapterPackageNotFoundError(
        "chapter package is not registered: {}.{}".format(volume, chapter)
    )


@lru_cache(maxsize=1)
def _domain_descriptors() -> Tuple[DomainPackageDescriptor, ...]:
    registry = _load_yaml_mapping(_REGISTRY)
    raw_packages = registry.get("domain_packages")
    if not isinstance(raw_packages, list):
        raise ChapterPackageError("chapter-package registry requires domain_packages")
    descriptors = []
    seen = set()
    for raw in raw_packages:
        if not isinstance(raw, Mapping):
            raise ChapterPackageError("domain-package entry must be a mapping")
        package_id = str(raw.get("package_id", ""))
        if not package_id or package_id in seen:
            raise ChapterPackageError(
                "invalid or duplicate domain package_id: {!r}".format(package_id)
            )
        seen.add(package_id)
        relative = Path(str(raw.get("manifest", "")))
        manifest_path = (_ROOT / relative).resolve()
        try:
            manifest_path.relative_to(_ROOT)
        except ValueError as exc:
            raise ChapterPackageError(
                "domain manifest path escapes registry root"
            ) from exc
        if not manifest_path.is_file():
            raise ChapterPackageError(
                "domain-package manifest is missing: {}".format(relative)
            )
        manifest = _load_yaml_mapping(manifest_path)
        if manifest.get("package_id") != package_id:
            raise ChapterPackageError(
                "domain registry package_id differs from its manifest"
            )
        version = str(raw.get("version", ""))
        if str(manifest.get("version", "")) != version:
            raise ChapterPackageError(
                "domain registry version differs from its manifest"
            )
        descriptors.append(
            DomainPackageDescriptor(
                package_id=package_id,
                version=version,
                domain=str(manifest.get("domain", "")),
                status=str(raw.get("status", "")),
                release_status=str(raw.get("release_status", "")),
                manifest_path=manifest_path,
            )
        )
    expected = int(registry.get("expected_domain_package_count", len(descriptors)))
    if len(descriptors) != expected:
        raise ChapterPackageError(
            "registry has {} domain packages; expected {}".format(
                len(descriptors), expected
            )
        )
    return tuple(sorted(descriptors, key=lambda item: item.package_id))


def list_domain_packages() -> Tuple[DomainPackageDescriptor, ...]:
    """List the fixed, registry-backed non-chapter packages."""

    return _domain_descriptors()


def get_domain_package(package_id: str) -> DomainPackageDescriptor:
    """Resolve one exact domain package id without path construction."""

    for descriptor in _domain_descriptors():
        if descriptor.package_id == package_id:
            return descriptor
    raise ChapterPackageNotFoundError(
        "domain package is not registered: {}".format(package_id)
    )


def read_domain_manifest(package_id: str) -> Mapping[str, Any]:
    """Read a registry-closed domain package manifest."""

    return _load_yaml_mapping(get_domain_package(package_id).manifest_path)


def validate_domain_package(package_id: str) -> Tuple[str, ...]:
    """Verify every domain asset path and declared SHA-256 digest."""

    descriptor = get_domain_package(package_id)
    manifest = _load_yaml_mapping(descriptor.manifest_path)
    issues = []
    assets = manifest.get("assets")
    if not isinstance(assets, list) or not assets:
        return ("manifest assets are missing",)
    root = descriptor.manifest_path.parent.resolve()
    seen = set()
    for raw in assets:
        if not isinstance(raw, Mapping):
            issues.append("manifest asset is not a mapping")
            continue
        asset_id = str(raw.get("asset_id", ""))
        if not asset_id or asset_id in seen:
            issues.append("invalid or duplicate asset_id: {!r}".format(asset_id))
            continue
        seen.add(asset_id)
        path = (root / Path(str(raw.get("path", "")))).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            issues.append("asset path escapes package: {}".format(asset_id))
            continue
        if not path.is_file():
            issues.append("asset is missing: {}".format(asset_id))
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != raw.get("sha256"):
            issues.append("asset sha256 mismatch: {}".format(asset_id))
    return tuple(issues)


def load_domain_package(runtime: Any, package_id: str) -> Any:
    """Hash-check and load one exact domain package through SemanticRuntime."""

    issues = validate_domain_package(package_id)
    if issues:
        raise ChapterPackageAssetError(
            "domain package failed integrity checks: {}".format("; ".join(issues))
        )
    descriptor = get_domain_package(package_id)
    result = runtime.load_package(descriptor.manifest_path)
    if (
        result.identity.package_id != descriptor.package_id
        or result.identity.version != descriptor.version
    ):
        raise ChapterPackageError(
            "loaded domain package identity differs from the built-in registry"
        )
    return result


def read_chapter_manifest(volume: str, chapter: str) -> Mapping[str, Any]:
    """Read the full source/provenance-aware manifest for one package."""

    return _load_yaml_mapping(get_chapter_package(volume, chapter).manifest_path)


def _binding_value(
    mapping: Mapping[str, Any], *keys: str
) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _book_binding_metadata(
    descriptor: ChapterPackageDescriptor, manifest: Mapping[str, Any]
) -> Mapping[str, Any]:
    if descriptor.volume == "vol1":
        chapter = manifest.get("chapter")
        if isinstance(chapter, Mapping):
            external = chapter.get("external_specification")
            if isinstance(external, Mapping):
                return external
    elif descriptor.volume == "vol2":
        book_source = manifest.get("book_source")
        if isinstance(book_source, Mapping):
            return book_source
    return {}


def _external_book_path(book_root: Path, source_anchor: str) -> Path:
    """Resolve one logical book anchor inside the supplied repository root."""

    relative = Path(source_anchor)
    if relative.is_absolute():
        raise ValueError("source anchor must be relative")
    parts = relative.parts
    if parts and parts[0] == "ontology-engineering":
        relative = Path(*parts[1:])
    root = book_root.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("source anchor escapes book root") from exc
    return candidate


def _digest_check(
    *,
    check_id: str,
    descriptor: ChapterPackageDescriptor,
    book_root: Path,
    source_anchor: str,
    expected_sha256: str,
) -> BookSourceCheckDTO:
    reason = None
    actual_sha256 = None
    if not source_anchor:
        reason = "source anchor is missing"
    elif len(expected_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_sha256
    ):
        reason = "expected source SHA-256 is missing or invalid"
    else:
        try:
            path = _external_book_path(book_root, source_anchor)
        except ValueError as exc:
            reason = str(exc)
        else:
            if not path.is_file():
                reason = "bound book source is missing"
            else:
                actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual_sha256 != expected_sha256:
                    reason = "bound book source SHA-256 differs"
    return BookSourceCheckDTO(
        check_id=check_id,
        package_id=descriptor.package_id,
        source_anchor=source_anchor,
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
        status="passed" if reason is None else "blocked",
        reason=reason,
    )


def _declared_binding_check(
    *,
    check_id: str,
    descriptor: ChapterPackageDescriptor,
    source_anchor: str,
    expected_sha256: str,
    declared_anchor: str,
    declared_sha256: str,
) -> BookSourceCheckDTO:
    reasons = []
    if declared_anchor != source_anchor:
        reasons.append("source anchor differs")
    if declared_sha256 != expected_sha256:
        reasons.append("source SHA-256 differs")
    return BookSourceCheckDTO(
        check_id=check_id,
        package_id=descriptor.package_id,
        source_anchor=declared_anchor,
        expected_sha256=expected_sha256,
        actual_sha256=declared_sha256 or None,
        status="blocked" if reasons else "passed",
        reason="; ".join(reasons) or None,
    )


def verify_book_source_bindings(
    book_root: Path,
    *,
    volume: Optional[str] = None,
    require_tex: bool = True,
    require_guide: bool = True,
) -> BookSourceVerificationDTO:
    """Verify every registered chapter against its book and TeX sources.

    ``book_root`` is the root of the external ``ontology-engineering`` checkout.
    The check binds the manifest, chapter contract, maintained chapter guide,
    generated TeX snapshot, and every package asset that declares the
    authoritative chapter as its source.
    Historical migration anchors remain provenance records and are not treated
    as files that must still exist in the book repository.
    """

    if volume not in (None, "vol1", "vol2"):
        raise ChapterPackageNotFoundError(
            "book bindings are not registered for volume: {}".format(volume)
        )
    root = Path(book_root)
    checks = []
    for descriptor in list_chapter_packages(volume):
        manifest = _load_yaml_mapping(descriptor.manifest_path)
        binding = _book_binding_metadata(descriptor, manifest)
        source_anchor = _binding_value(binding, "source_anchor", "logical_anchor")
        source_sha256 = _binding_value(binding, "source_sha256", "sha256")
        checks.append(
            _digest_check(
                check_id="book.primary.digest",
                descriptor=descriptor,
                book_root=root,
                source_anchor=source_anchor,
                expected_sha256=source_sha256,
            )
        )

        try:
            contract = _contract_for(descriptor)
        except ChapterPackageError as exc:
            checks.append(
                BookSourceCheckDTO(
                    check_id="book.contract.binding",
                    package_id=descriptor.package_id,
                    source_anchor="",
                    expected_sha256=source_sha256,
                    actual_sha256=None,
                    status="blocked",
                    reason=str(exc),
                )
            )
            contract_external = {}
        else:
            raw_contract_external = contract.get("external_specification")
            contract_external = (
                raw_contract_external
                if isinstance(raw_contract_external, Mapping)
                else {}
            )
            checks.append(
                _declared_binding_check(
                    check_id="book.contract.binding",
                    descriptor=descriptor,
                    source_anchor=source_anchor,
                    expected_sha256=source_sha256,
                    declared_anchor=_binding_value(
                        contract_external, "source_anchor", "logical_anchor"
                    ),
                    declared_sha256=_binding_value(
                        contract_external, "source_sha256", "sha256"
                    ),
                )
            )

        tex_anchor = _binding_value(binding, "tex_anchor")
        tex_sha256 = _binding_value(binding, "tex_sha256")
        if require_tex or tex_anchor or tex_sha256:
            checks.append(
                _digest_check(
                    check_id="book.tex.digest",
                    descriptor=descriptor,
                    book_root=root,
                    source_anchor=tex_anchor,
                    expected_sha256=tex_sha256,
                )
            )
            checks.append(
                _declared_binding_check(
                    check_id="book.contract.tex-binding",
                    descriptor=descriptor,
                    source_anchor=tex_anchor,
                    expected_sha256=tex_sha256,
                    declared_anchor=_binding_value(contract_external, "tex_anchor"),
                    declared_sha256=_binding_value(contract_external, "tex_sha256"),
                )
            )

        guide_anchor = _binding_value(binding, "guide_anchor")
        guide_sha256 = _binding_value(binding, "guide_sha256")
        if require_guide or guide_anchor or guide_sha256:
            checks.append(
                _digest_check(
                    check_id="book.guide.digest",
                    descriptor=descriptor,
                    book_root=root,
                    source_anchor=guide_anchor,
                    expected_sha256=guide_sha256,
                )
            )
            checks.append(
                _declared_binding_check(
                    check_id="book.contract.guide-binding",
                    descriptor=descriptor,
                    source_anchor=guide_anchor,
                    expected_sha256=guide_sha256,
                    declared_anchor=_binding_value(
                        contract_external, "guide_anchor"
                    ),
                    declared_sha256=_binding_value(
                        contract_external, "guide_sha256"
                    ),
                )
            )

        assets = manifest.get("assets")
        if isinstance(assets, list):
            for asset in assets:
                if not isinstance(asset, Mapping):
                    continue
                if asset.get("source_anchor") != source_anchor:
                    continue
                asset_id = str(asset.get("asset_id", "unknown"))
                checks.append(
                    _declared_binding_check(
                        check_id="book.asset-source.{}".format(asset_id),
                        descriptor=descriptor,
                        source_anchor=source_anchor,
                        expected_sha256=source_sha256,
                        declared_anchor=str(asset.get("source_anchor", "")),
                        declared_sha256=str(asset.get("source_sha256", "")),
                    )
                )
    return BookSourceVerificationDTO(checks=tuple(checks))


@lru_cache(maxsize=1)
def read_chapter_policy() -> Mapping[str, Any]:
    """Read the common 29-chapter policy embedded in Semantica."""

    return _load_yaml_mapping(_ROOT / "policy.yaml")


@lru_cache(maxsize=2)
def read_migration_map(volume: str) -> MigrationMapDTO:
    """Normalize and integrity-check one volume's asset migration ledger.

    Vol.1 records use ``legacy_path/package_id/asset_id`` while Vol.2 records
    use ``old_path/new_package/new_asset_id``.  Callers receive one stable DTO
    vocabulary and never need to branch on those source encodings.
    """

    normalized_volume = str(volume)
    if normalized_volume == "vol1":
        path = _ROOT / "vol1" / "migration-map.yaml"
        collection_key = "assets"
    elif normalized_volume == "vol2":
        path = _ROOT / "vol2" / "migration-map.json"
        collection_key = "mappings"
    else:
        raise ChapterPackageNotFoundError(
            "migration map is not registered for volume: {}".format(normalized_volume)
        )
    raw_bytes = path.read_bytes()
    raw = _load_yaml_mapping(path)
    if str(raw.get("schema_version", "")) != "1.0":
        raise ChapterPackageError("unsupported migration-map schema")
    records = raw.get(collection_key)
    if not isinstance(records, list):
        raise ChapterPackageError("migration map has no records list")
    declared_count = raw.get("mapping_count")
    if declared_count is not None and int(declared_count) != len(records):
        raise ChapterPackageError("migration map declared count is incorrect")

    entries = []
    for raw_entry in records:
        if not isinstance(raw_entry, Mapping):
            raise ChapterPackageError("migration-map record must be a mapping")
        if normalized_volume == "vol1":
            old_path = str(raw_entry.get("legacy_path", ""))
            old_sha256 = str(raw_entry.get("sha256", ""))
            package_id = str(raw_entry.get("package_id", ""))
            asset_id = str(raw_entry.get("asset_id", ""))
            successor_sha256 = str(raw_entry.get("sha256", ""))
            relation = str(raw_entry.get("migration", ""))
            successor_path = str(raw_entry.get("semantica_path", "")) or None
            source_fragment = None
            strict_value = raw_entry.get("strict_gate_asset")
            strict_gate_asset = strict_value if isinstance(strict_value, bool) else None
        else:
            old_path = str(raw_entry.get("old_path", ""))
            old_sha256 = str(raw_entry.get("old_sha256", ""))
            package_id = str(raw_entry.get("new_package", ""))
            asset_id = str(raw_entry.get("new_asset_id", ""))
            successor_sha256 = str(raw_entry.get("new_sha256", ""))
            relation = str(raw_entry.get("relation", ""))
            successor_path = None
            fragment_value = raw_entry.get("source_fragment")
            source_fragment = (
                str(fragment_value) if fragment_value is not None else None
            )
            strict_gate_asset = None

        entry = MigrationSuccessorDTO(
            volume=normalized_volume,
            old_path=old_path,
            old_sha256=old_sha256,
            package_id=package_id,
            asset_id=asset_id,
            successor_sha256=successor_sha256,
            relation=relation,
            successor_path=successor_path,
            source_fragment=source_fragment,
            strict_gate_asset=strict_gate_asset,
        )
        _validate_migration_successor(entry)
        entries.append(entry)

    retired_entries = []
    raw_retired = raw.get("retired_runtime_entries", [])
    if not isinstance(raw_retired, list):
        raise ChapterPackageError("retired_runtime_entries must be a list")
    retired_paths = set()
    for raw_entry in raw_retired:
        if not isinstance(raw_entry, Mapping):
            raise ChapterPackageError("retired runtime entry must be a mapping")
        legacy_path = str(raw_entry.get("legacy_path", ""))
        copied = raw_entry.get("copied_as_runtime")
        replacement_entry = str(raw_entry.get("replacement_entry", ""))
        reason = str(raw_entry.get("reason", ""))
        replacement_assets_value = raw_entry.get("replacement_assets", [])
        if (
            not legacy_path
            or legacy_path in retired_paths
            or copied is not False
            or not replacement_entry
            or not reason
            or not isinstance(replacement_assets_value, list)
        ):
            raise ChapterPackageError("retired runtime entry is incomplete or unsafe")
        retired_paths.add(legacy_path)
        retired_entries.append(
            RetiredRuntimeEntryDTO(
                legacy_path=legacy_path,
                copied_as_runtime=False,
                replacement_entry=replacement_entry,
                reason=reason,
                replacement_assets=tuple(
                    str(value) for value in replacement_assets_value
                ),
            )
        )

    return MigrationMapDTO(
        volume=normalized_volume,
        source_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        entries=tuple(entries),
        retired_runtime_entries=tuple(retired_entries),
    )


def resolve_migration_successor(
    old_path: str, volume: Optional[str] = None
) -> MigrationResolutionDTO:
    """Return every exact successor candidate; ambiguity is never collapsed."""

    requested = str(old_path)
    volumes = (str(volume),) if volume is not None else ("vol1", "vol2")
    candidates = tuple(
        entry
        for item_volume in volumes
        for entry in read_migration_map(item_volume).entries
        if entry.old_path == requested
    )
    return MigrationResolutionDTO(old_path=requested, candidates=candidates)


def _validate_migration_successor(entry: MigrationSuccessorDTO) -> None:
    required_text = (
        entry.old_path,
        entry.package_id,
        entry.asset_id,
        entry.relation,
    )
    if any(not value for value in required_text):
        raise ChapterPackageError("migration successor has an empty required field")
    for label, digest in (
        ("old_sha256", entry.old_sha256),
        ("successor_sha256", entry.successor_sha256),
    ):
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ChapterPackageError(
                "migration successor {} is not a SHA-256 digest".format(label)
            )

    manifest_path = _manifest_path_for_package_id(entry.package_id)
    manifest = _load_yaml_mapping(manifest_path)
    assets = manifest.get("assets")
    if not isinstance(assets, list):
        raise ChapterPackageError("successor package has no assets list")
    matches = [
        item
        for item in assets
        if isinstance(item, Mapping) and item.get("asset_id") == entry.asset_id
    ]
    if len(matches) != 1:
        raise ChapterPackageError(
            "migration successor must bind exactly one declared package asset"
        )
    asset = matches[0]
    if asset.get("sha256") != entry.successor_sha256:
        raise ChapterPackageError(
            "migration successor digest differs from the package manifest"
        )
    root = manifest_path.parent.resolve()
    asset_path = (root / Path(str(asset.get("path", "")))).resolve()
    try:
        asset_path.relative_to(root)
    except ValueError as exc:
        raise ChapterPackageError("migration successor asset escapes package") from exc
    if not asset_path.is_file():
        raise ChapterPackageError("migration successor asset is missing")
    actual = hashlib.sha256(asset_path.read_bytes()).hexdigest()
    if actual != entry.successor_sha256:
        raise ChapterPackageError("migration successor asset hash mismatch")
    if entry.successor_path is not None:
        repository_root = _ROOT.parents[1]
        mapped_path = (repository_root / Path(entry.successor_path)).resolve()
        try:
            mapped_path.relative_to(repository_root)
        except ValueError as exc:
            raise ChapterPackageError(
                "migration successor path escapes repository"
            ) from exc
        if mapped_path != asset_path:
            raise ChapterPackageError(
                "migration successor path differs from the package manifest"
            )


def _manifest_path_for_package_id(package_id: str) -> Path:
    chapter_matches = [
        item.manifest_path for item in _descriptors() if item.package_id == package_id
    ]
    domain_matches = [
        item.manifest_path
        for item in _domain_descriptors()
        if item.package_id == package_id
    ]
    matches = chapter_matches + domain_matches
    if len(matches) != 1:
        raise ChapterPackageNotFoundError(
            "migration successor package is not uniquely registered: {}".format(
                package_id
            )
        )
    return matches[0]


def _contract_for(descriptor: ChapterPackageDescriptor) -> Mapping[str, Any]:
    manifest = _load_yaml_mapping(descriptor.manifest_path)
    assets = manifest.get("assets")
    if not isinstance(assets, list):
        raise ChapterContractValidationError(
            "{} has no assets list".format(descriptor.key)
        )
    contract_asset = None
    for asset in assets:
        if isinstance(asset, Mapping) and asset.get("role") == "chapter_contract":
            contract_asset = asset
            break
    if contract_asset is None:
        raise ChapterContractValidationError(
            "{} has no chapter_contract asset".format(descriptor.key)
        )
    relative = Path(str(contract_asset.get("path", "")))
    contract_path = (descriptor.manifest_path.parent / relative).resolve()
    try:
        contract_path.relative_to(descriptor.manifest_path.parent.resolve())
    except ValueError as exc:
        raise ChapterContractValidationError(
            "{} contract path escapes package".format(descriptor.key)
        ) from exc
    return _load_yaml_mapping(contract_path)


def validate_chapter_contract(volume: str, chapter: str) -> Tuple[str, ...]:
    """Validate one package against the common payload/lifecycle/receipt policy."""

    descriptor = get_chapter_package(volume, chapter)
    policy = read_chapter_policy()
    manifest = _load_yaml_mapping(descriptor.manifest_path)
    contract = _contract_for(descriptor)
    issues = []

    if contract.get("package_id") != descriptor.package_id:
        issues.append("contract package_id differs from registry")
    if str(contract.get("package_version")) != descriptor.version:
        issues.append("contract version differs from registry")

    statuses = set(policy.get("status_vocabulary", ()))
    payload = contract.get("payload_status")
    if not isinstance(payload, Mapping):
        issues.append("payload_status is missing")
    else:
        for key in policy.get("required_migration_payload_kinds", ()):
            if key not in payload:
                issues.append("payload_status is missing {}".format(key))
            elif payload.get(key) not in statuses:
                issues.append("payload_status {} is invalid".format(key))

    lifecycle = contract.get("lifecycle")
    if not isinstance(lifecycle, Mapping):
        issues.append("lifecycle is missing")
    else:
        for key in policy.get("required_lifecycle_stages", ()):
            value = lifecycle.get(key)
            if not isinstance(value, Mapping):
                issues.append("lifecycle is missing {}".format(key))
            elif value.get("status") not in statuses:
                issues.append("lifecycle {} status is invalid".format(key))

    receipt = contract.get("receipt")
    required_receipt = tuple(policy.get("required_receipt_fields", ()))
    if not isinstance(receipt, Mapping):
        issues.append("receipt declaration is missing")
    else:
        declared = tuple(receipt.get("required_fields", ()))
        fields = receipt.get("fields")
        if set(declared) != set(required_receipt):
            issues.append("receipt.required_fields differs from policy")
        if not isinstance(fields, Mapping):
            issues.append("receipt.fields is missing")
        else:
            for key in required_receipt:
                if key not in fields:
                    issues.append("receipt.fields is missing {}".format(key))

    assets = manifest.get("assets")
    if not isinstance(assets, list) or not assets:
        issues.append("manifest assets are missing")
    else:
        seen = set()
        package_root = descriptor.manifest_path.parent.resolve()
        for asset in assets:
            if not isinstance(asset, Mapping):
                issues.append("manifest asset is not a mapping")
                continue
            asset_id = asset.get("asset_id")
            if not isinstance(asset_id, str) or not asset_id:
                issues.append("manifest asset_id is missing")
                continue
            if asset_id in seen:
                issues.append("manifest asset_id is duplicated: {}".format(asset_id))
            seen.add(asset_id)
            relative = Path(str(asset.get("path", "")))
            path = (package_root / relative).resolve()
            try:
                path.relative_to(package_root)
            except ValueError:
                issues.append("asset path escapes package: {}".format(asset_id))
                continue
            if not path.is_file():
                issues.append("asset is missing: {}".format(asset_id))
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != asset.get("sha256"):
                issues.append("asset sha256 mismatch: {}".format(asset_id))
            source_sha = asset.get("source_sha256")
            if (
                not isinstance(source_sha, str)
                or len(source_sha) != 64
                or any(char not in "0123456789abcdef" for char in source_sha)
            ):
                issues.append("source sha256 is invalid: {}".format(asset_id))
            if not asset.get("source_anchor"):
                issues.append("source anchor is missing: {}".format(asset_id))

    release = contract.get("release")
    if isinstance(release, Mapping) and release.get("status") == "complete":
        incomplete = []
        if isinstance(payload, Mapping):
            incomplete.extend(k for k, value in payload.items() if value != "native")
        if isinstance(lifecycle, Mapping):
            incomplete.extend(
                k
                for k, value in lifecycle.items()
                if not isinstance(value, Mapping) or value.get("status") != "native"
            )
        if incomplete:
            issues.append(
                "release is complete while non-native stages remain: {}".format(
                    ", ".join(sorted(incomplete))
                )
            )
    return tuple(issues)


def validate_chapter_registry(*, require_complete: bool = True) -> Tuple[str, ...]:
    """Validate registry coverage and every registered chapter contract."""

    registry = _load_yaml_mapping(_REGISTRY)
    policy = read_chapter_policy()
    descriptors = _descriptors()
    issues = []
    expected_count = int(
        registry.get("expected_package_count", policy.get("contract_count", 0))
    )
    if require_complete and len(descriptors) != expected_count:
        issues.append(
            "registry has {} packages; expected {}".format(
                len(descriptors), expected_count
            )
        )
    expected_coverage = registry.get("expected_coverage")
    if require_complete and isinstance(expected_coverage, Mapping):
        expected = {
            (str(volume), str(chapter))
            for volume, chapters in expected_coverage.items()
            for chapter in chapters
        }
        actual = {(item.volume, item.chapter) for item in descriptors}
        if expected != actual:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            if missing:
                issues.append("registry coverage is missing {!r}".format(missing))
            if extra:
                issues.append("registry coverage has extras {!r}".format(extra))
    for descriptor in descriptors:
        for issue in validate_chapter_contract(descriptor.volume, descriptor.chapter):
            issues.append("{}: {}".format(descriptor.key, issue))
    for descriptor in _domain_descriptors():
        for issue in validate_domain_package(descriptor.package_id):
            issues.append("{}: {}".format(descriptor.package_id, issue))
    return tuple(issues)


def load_chapter_package(runtime: Any, volume: str, chapter: str) -> Any:
    """Load one built-in package through ``SemanticRuntime.load_package``."""

    descriptor = get_chapter_package(volume, chapter)
    result = runtime.load_package(descriptor.manifest_path)
    if (
        result.identity.package_id != descriptor.package_id
        or result.identity.version != descriptor.version
    ):
        raise ChapterPackageError(
            "loaded package identity differs from the built-in registry"
        )
    return result


def execute_chapter_query(
    runtime: Any,
    volume: str,
    chapter: str,
    asset_id: str,
    *,
    namespaces: Optional[Mapping[str, str]] = None,
    bindings: Optional[Mapping[str, Any]] = None,
) -> Any:
    """Execute a registered SPARQL asset through the stable runtime DTO API.

    This is the native replacement entry point for the former book-local Jena
    query service.  A non-SPARQL asset is rejected instead of being executed.
    """

    loaded = load_chapter_package(runtime, volume, chapter)
    asset = None
    for candidate in loaded.assets:
        if candidate.asset_id == asset_id:
            asset = candidate
            break
    if asset is None:
        raise ChapterPackageAssetError(
            "chapter query asset is not registered: {}.{}:{}".format(
                volume, chapter, asset_id
            )
        )
    if asset.role != "sparql":
        raise ChapterPackageAssetError(
            "chapter asset is not executable SPARQL: {} ({})".format(
                asset_id, asset.role
            )
        )
    return runtime.query(asset.text(), namespaces=namespaces, bindings=bindings)


def chapter_asset_text(runtime: Any, volume: str, chapter: str, asset_id: str) -> str:
    """Load a package and return one exact, hash-verified text asset."""

    loaded = load_chapter_package(runtime, volume, chapter)
    for asset in loaded.assets:
        if asset.asset_id == asset_id:
            return asset.text()
    raise ChapterPackageAssetError(
        "chapter asset is not registered: {}.{}:{}".format(volume, chapter, asset_id)
    )


def package_asset_text(package_id: str, asset_id: str) -> str:
    """Return one UTF-8 asset from the fixed chapter/domain package registry.

    The package is loaded through the stable RDF-profile runtime, which checks
    every manifest asset hash before this function resolves ``asset_id``.
    Unknown packages, missing/duplicate assets, and binary payloads fail closed.
    """

    manifest_path = _manifest_path_for_package_id(str(package_id))
    # Keep registry discovery dependency-light.  Reading executable package
    # content is the point at which the caller explicitly opts into the RDF
    # runtime dependency.
    from semantica.ontology.runtime import SemanticRuntime

    runtime = SemanticRuntime(profile="rdf", backend="rdflib")
    loaded = runtime.load_package(manifest_path)
    matches = tuple(asset for asset in loaded.assets if asset.asset_id == str(asset_id))
    if len(matches) != 1:
        raise ChapterPackageAssetError(
            "package asset is not uniquely registered: {}:{}".format(
                package_id, asset_id
            )
        )
    asset = matches[0]
    if hashlib.sha256(asset.content).hexdigest() != asset.sha256:
        raise ChapterPackageAssetError("package asset failed its SHA-256 check")
    if b"\x00" in asset.content:
        raise ChapterPackageAssetError("package asset is binary, not UTF-8 text")
    try:
        return asset.content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChapterPackageAssetError(
            "package asset is binary, not UTF-8 text"
        ) from exc


# Runner imports are lazy so dependency-light registry discovery still works
# without the optional ontology-runtime environment.  PEP 562 preserves the
# normal ``from semantica.chapter_packages import SemanticPackageRunner`` API.
_LAZY_RUNNER_EXPORTS = frozenset(
    {
        "OracleCheckDTO",
        "PackageOperationReportDTO",
        "RUNNER_CONTRACT",
        "SemanticPackageRunResultDTO",
        "SemanticPackageRunner",
    }
)

if TYPE_CHECKING:
    from .runner import (
        OracleCheckDTO,
        PackageOperationReportDTO,
        SemanticPackageRunResultDTO,
        SemanticPackageRunner,
    )


def __getattr__(name: str) -> Any:
    if name in _LAZY_RUNNER_EXPORTS:
        from . import runner

        return getattr(runner, name)
    raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))


__all__ = [
    "BookSourceCheckDTO",
    "BookSourceVerificationDTO",
    "ChapterPackageAssetError",
    "ChapterContractValidationError",
    "ChapterPackageDescriptor",
    "ChapterPackageError",
    "ChapterPackageNotFoundError",
    "DomainPackageDescriptor",
    "MigrationMapDTO",
    "MigrationResolutionDTO",
    "MigrationSuccessorDTO",
    "OracleCheckDTO",
    "PackageOperationReportDTO",
    "RUNNER_CONTRACT",
    "RetiredRuntimeEntryDTO",
    "SemanticPackageRunResultDTO",
    "SemanticPackageRunner",
    "chapter_asset_text",
    "execute_chapter_query",
    "get_chapter_package",
    "get_domain_package",
    "list_chapter_packages",
    "list_domain_packages",
    "load_chapter_package",
    "load_domain_package",
    "package_asset_text",
    "read_chapter_manifest",
    "read_chapter_policy",
    "read_domain_manifest",
    "read_migration_map",
    "resolve_migration_successor",
    "validate_chapter_contract",
    "validate_chapter_registry",
    "validate_domain_package",
    "verify_book_source_bindings",
]
