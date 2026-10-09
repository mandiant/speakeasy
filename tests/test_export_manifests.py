"""Physical export manifests follow the manifest format and agree with handler ordinals."""

import json

import pydantic
import pytest

from speakeasy.windows.export_manifest import MANIFEST_ROOT, ExportManifest, get_export_manifest
from speakeasy.winenv.api.winapi import autoload_api_handlers

MANIFEST_PATHS = sorted(MANIFEST_ROOT.glob("*/*.json"))


def test_handler_ordinals_match_the_physical_exports():
    mismatches = []
    for _, handler in autoload_api_handlers():
        hooks = [h for attr in dir(handler) if (h := getattr(getattr(handler, attr), "__apihook__", None))]
        for arch in ("x86", "x64"):
            manifest = get_export_manifest(handler.name.lower(), arch)
            if manifest is None:
                continue
            ordinals = {e.name: e.ordinal for e in manifest.exports if e.name}
            for name, _, _, _, ordinal in hooks:
                if ordinal and ordinals.get(name) != ordinal:
                    mismatches.append((handler.name, arch, name, ordinal, ordinals.get(name)))
    assert mismatches == []


@pytest.mark.parametrize("path", MANIFEST_PATHS, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_manifest_is_well_formed(path):
    manifest = ExportManifest.from_path(path)
    assert manifest.module == path.stem
    assert manifest.arch == path.parent.name


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"arch": "arm64"},
        {"sha256": "ABC"},
        {"exports": [{"ordinal": 2, "name": "b"}, {"ordinal": 1, "name": "a"}]},
        {"exports": [{"ordinal": 1, "name": "a"}, {"ordinal": 2, "name": "a"}]},
        {"exports": [{"ordinal": 0, "name": "a"}]},
        {"exports": [{"ordinal": 1, "name": "a", "kind": "code"}]},
        {"exports": [{"ordinal": 1, "name": "a", "forwarder": "NTDLL"}]},
        {"exports": [{"ordinal": 1, "name": "a", "forwarder": "NTDLL.#0"}]},
    ],
)
def test_manifest_format_rejects_invalid_files(tmp_path, change):
    data = {
        "module": "m",
        "file": "m.dll",
        "arch": "x86",
        "file_version": None,
        "timestamp": 0,
        "size_of_image": 0x1000,
        "sha256": "0" * 64,
        "exports": [{"ordinal": 1, "name": "a", "forwarder": "NTDLL.#1"}],
    }
    path = tmp_path / "m.json"
    path.write_text(json.dumps(data))
    ExportManifest.from_path(path)
    path.write_text(json.dumps(data | change))
    with pytest.raises(pydantic.ValidationError):
        ExportManifest.from_path(path)
