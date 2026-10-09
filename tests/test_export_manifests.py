"""Physical export manifests define the names and ordinals of synthetic modules."""

import json

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.api_image import validate_forwarder
from speakeasy.windows.export_manifest import MANIFEST_ROOT, get_export_manifest
from speakeasy.winenv.api.winapi import autoload_api_handlers

MANIFEST_PATHS = sorted(MANIFEST_ROOT.glob("*/*.json"))


@pytest.fixture(params=["x86", "amd64"])
def started(request, config):
    config["timeout"] = 3
    config["modules"]["functions_always_exist"] = False
    with Speakeasy(config=config) as se:
        se.run_shellcode(se.load_shellcode(data=b"\xc3", arch=request.param))
        yield se


@pytest.mark.parametrize(
    "module,ordinal,name",
    [
        ("ws2_32", 5, "getpeername"),
        ("ws2_32", 17, "recvfrom"),
        ("ws2_32", 20, "sendto"),
        ("oleaut32", 9, "VariantClear"),
    ],
)
def test_ordinal_import_resolves_to_the_physical_export(started, module, ordinal, name):
    address = started.emu.get_proc(module, f"ordinal_{ordinal}")
    assert address == started.emu.get_proc(module, name)
    assert started.get_symbols()[address] == (module, name)


def test_generic_handler_names_are_not_exported(started):
    kernel32 = started.emu.get_mod_by_name("kernel32")
    assert kernel32.get_export_by_name("CreateFileA") is not None
    assert kernel32.get_export_by_name("CreateFileW") is not None
    assert kernel32.get_export_by_name("CreateFile") is None


def test_handler_ordinals_match_the_physical_exports():
    mismatches = []
    for _, handler in autoload_api_handlers():
        hooks = [h for attr in dir(handler) for h in getattr(getattr(handler, attr), "__apihooks__", ())]
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
    data = json.loads(path.read_text())
    assert data["module"] == path.stem
    assert data["arch"] == path.parent.name
    manifest = get_export_manifest(path.stem, path.parent.name)
    assert manifest is not None
    keys = [(e.ordinal, e.name or "") for e in manifest.exports]
    assert keys == sorted(set(keys))
    names = [e.name for e in manifest.exports if e.name]
    assert len(names) == len(set(names))
    for export in manifest.exports:
        assert 0 < export.ordinal <= 0xFFFF
        assert export.kind in ("function", "data")
        if export.forwarder is not None:
            validate_forwarder(export.forwarder)


@pytest.mark.parametrize("module,name", [("ntdll", "NlsMbCodePageTag"), ("user32", "gSharedInfo")])
def test_physical_data_exports_are_zeroed_variables(started, module, name):
    address = started.emu.get_proc(module, name)
    export = started.emu.get_mod_by_name(module).get_export_by_name(name)
    assert export.kind == "data" and export.address == address
    assert started.mem_read(address, 0x100) == b"\0" * 0x100
    assert started.get_symbols()[address] == (module, name)
