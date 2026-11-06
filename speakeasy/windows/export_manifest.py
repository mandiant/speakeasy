"""
Physical export tables of Windows modules.

Each ``resources/win32/exports/<arch>/<module>.json`` file records the export
directory of one real Windows binary: ordinals, names, forwarder strings and
whether the export is code or data. ``ExportManifest`` defines the file format.

Each ``resources/win32/ordinals/<arch>/<module>.json`` file gives the names of
the export ordinals of a module that has no manifest. ``OrdinalNames`` defines
the file format.
"""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from speakeasy.windows.loaders import validate_forwarder

MANIFEST_ROOT = Path(__file__).resolve().parent.parent / "resources" / "win32" / "exports"
ORDINAL_NAMES_ROOT = MANIFEST_ROOT.parent / "ordinals"

# The MSVC decoration of a variable is ?name@scope@...@@ and a storage class: 0, 1 or 2 for a
# private, protected or public static data member, 3 for a global variable.
MSVC_DATA_NAME = re.compile(r"\?[A-Za-z_][A-Za-z0-9_]*@(?:[A-Za-z_][A-Za-z0-9_]*@)*@[0-3]")


class ManifestExport(BaseModel):
    """One entry of the export address table."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ordinal: int = Field(ge=1, le=0xFFFF, description="Biased export ordinal, as an importer uses it.")
    name: str | None = Field(
        default=None, min_length=1, description="Exported name. Absent when the export has only an ordinal."
    )
    forwarder: str | None = Field(
        default=None,
        description="Forwarder string in `DLL.name` or `DLL.#ordinal` form, if the export is a forwarder.",
    )
    kind: Literal["function", "data"] = Field(
        default="function",
        description="`data` when the export RVA is in a section without IMAGE_SCN_MEM_EXECUTE, otherwise `function`.",
    )

    @field_validator("forwarder")
    @classmethod
    def _check_forwarder(cls, value: str | None) -> str | None:
        if value is not None:
            validate_forwarder(value)
        return value


class ExportManifest(BaseModel):
    """The export directory of one Windows binary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    module: str = Field(min_length=1, description="Lower-case file stem. It is also the manifest file name.")
    file: str = Field(min_length=1, description="File name of the source binary, for example `kernel32.dll`.")
    export_name: str = Field(
        min_length=1, description="Name field of the export directory, for example `KERNEL32.dll`."
    )
    arch: Literal["x86", "x64"] = Field(description="Architecture of the source binary. It is also the directory name.")
    file_version: str | None = Field(description="FileVersion from the version resource, if the binary has one.")
    timestamp: int = Field(ge=0, description="TimeDateStamp from the PE file header.")
    size_of_image: int = Field(gt=0, description="SizeOfImage from the PE optional header.")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 of the source binary, in lower-case hex.")
    exports: tuple[ManifestExport, ...] = Field(
        description="Exports sorted by ordinal, then by name. Names are unique. Exports with RVA 0 are not in the list."
    )

    @model_validator(mode="after")
    def _check_exports(self) -> ExportManifest:
        keys = [(export.ordinal, export.name or "") for export in self.exports]
        if keys != sorted(set(keys)):
            raise ValueError("exports must be unique and sorted by ordinal, then by name")
        names = [export.name for export in self.exports if export.name]
        if len(names) != len(set(names)):
            raise ValueError("export names must be unique")
        return self

    @classmethod
    def from_path(cls, path: Path) -> ExportManifest:
        """
        Load and validate one manifest file.

        Raises:
            pydantic.ValidationError: if the file does not follow the manifest format.
        """
        return cls.model_validate_json(path.read_bytes())


class OrdinalName(BaseModel):
    """The exported name of one ordinal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ordinal: int = Field(ge=1, le=0xFFFF, description="Biased export ordinal, as an importer uses it.")
    name: str = Field(min_length=1, description="Exported name.")

    @property
    def kind(self) -> Literal["function", "data"]:
        """`data` when the name has the MSVC decoration of a static data member or a global variable."""
        return "data" if MSVC_DATA_NAME.match(self.name) else "function"


class OrdinalNames(BaseModel):
    """
    The names of the export ordinals of a module.

    The file does not identify a binary. The decoration of each name tells if the export is code or data.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    module: str = Field(min_length=1, description="Lower-case file stem. It is also the file name.")
    arch: Literal["x86", "x64"] = Field(description="Architecture of the module. It is also the directory name.")
    names: tuple[OrdinalName, ...] = Field(description="Names sorted by ordinal. Ordinals and names are unique.")

    @model_validator(mode="after")
    def _check_names(self) -> OrdinalNames:
        ordinals = [entry.ordinal for entry in self.names]
        if ordinals != sorted(set(ordinals)):
            raise ValueError("ordinals must be unique and sorted")
        if len({entry.name for entry in self.names}) != len(self.names):
            raise ValueError("names must be unique")
        return self

    @classmethod
    def from_path(cls, path: Path) -> OrdinalNames:
        """
        Load and validate one ordinal names file.

        Raises:
            pydantic.ValidationError: if the file does not follow the format.
        """
        return cls.model_validate_json(path.read_bytes())


@cache
def get_resource_names(root: Path, arch: str) -> frozenset[str]:
    directory = root / arch
    if not directory.is_dir():
        return frozenset()
    return frozenset(path.stem for path in directory.glob("*.json"))


@cache
def get_export_manifest(module: str, arch: str) -> ExportManifest | None:
    """Return the manifest for a lower-case module name on ``x86`` or ``x64``, if one exists."""
    if module not in get_resource_names(MANIFEST_ROOT, arch):
        return None
    return ExportManifest.from_path(MANIFEST_ROOT / arch / f"{module}.json")


@cache
def get_ordinal_names(module: str, arch: str) -> OrdinalNames | None:
    """Return the ordinal names for a lower-case module name on ``x86`` or ``x64``, if they exist."""
    if module not in get_resource_names(ORDINAL_NAMES_ROOT, arch):
        return None
    return OrdinalNames.from_path(ORDINAL_NAMES_ROOT / arch / f"{module}.json")
