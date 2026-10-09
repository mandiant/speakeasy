"""Physical export tables of Windows modules.

Each ``resources/win32/exports/<arch>/<module>.json`` file records the export
directory of one real Windows binary: ordinals, names, forwarder strings and
whether the export is code or data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path

MANIFEST_ROOT = Path(__file__).resolve().parent.parent / "resources" / "win32" / "exports"


@dataclass(frozen=True)
class ManifestExport:
    ordinal: int
    name: str | None = None
    forwarder: str | None = None
    kind: str = "function"


@dataclass(frozen=True)
class ExportManifest:
    module: str
    file: str
    arch: str
    file_version: str | None
    timestamp: int
    size_of_image: int
    sha256: str
    exports: tuple[ManifestExport, ...]

    @classmethod
    def from_path(cls, path: Path) -> ExportManifest:
        data = json.loads(path.read_text())
        exports = tuple(ManifestExport(**entry) for entry in data.pop("exports"))
        return cls(exports=exports, **data)


@cache
def get_manifest_names(arch: str) -> frozenset[str]:
    directory = MANIFEST_ROOT / arch
    if not directory.is_dir():
        return frozenset()
    return frozenset(path.stem for path in directory.glob("*.json"))


@cache
def get_export_manifest(module: str, arch: str) -> ExportManifest | None:
    """Return the manifest for a lower-case module name on ``x86`` or ``x64``, if one exists."""
    if module not in get_manifest_names(arch):
        return None
    return ExportManifest.from_path(MANIFEST_ROOT / arch / f"{module}.json")
