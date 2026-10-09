"""Physical export manifests define the names and ordinals of synthetic modules."""

import json
import struct

import pydantic
import pytest

from speakeasy import Speakeasy
from speakeasy.windows.export_manifest import MANIFEST_ROOT, ExportManifest, get_export_manifest
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


@pytest.mark.parametrize("module,name", [("ntdll", "NlsMbCodePageTag"), ("user32", "gSharedInfo")])
def test_physical_data_exports_are_zeroed_variables(started, module, name):
    address = started.emu.get_proc(module, name)
    export = started.emu.get_mod_by_name(module).get_export_by_name(name)
    assert export.kind == "data" and export.address == address
    assert started.mem_read(address, 0x100) == b"\0" * 0x100
    assert started.get_symbols()[address] == (module, name)


def call_get_proc_address(config, architecture, module, name):
    """Run guest code that calls GetProcAddress, then GetLastError."""
    with Speakeasy(config=config) as se:
        code_base = se.load_shellcode(data=b"\xcc" * 0x100, arch=architecture)
        base = se.emu.load_module_by_name(module).base
        # GetProcAddress treats pointers below 64 KiB as ordinals.
        data = se.mem_alloc(0x1000, base=0x20000000)
        se.mem_write(data, b"\0" * 0x20 + name.encode() + b"\0")
        resolver = se.emu.get_proc("kernel32", "GetProcAddress")
        last_error = se.emu.get_proc("kernel32", "GetLastError")
        if architecture == "x86":

            def d(value):
                return struct.pack("<I", value)

            code = b"\x68" + d(data + 0x20) + b"\x68" + d(base) + b"\xb8" + d(resolver) + b"\xff\xd0\xa3" + d(data)
            code += b"\xb8" + d(last_error) + b"\xff\xd0\xa3" + d(data + 8) + b"\xc3"
        else:

            def q(value):
                return struct.pack("<Q", value)

            code = b"\x48\x83\xec\x28\x48\xb9" + q(base) + b"\x48\xba" + q(data + 0x20) + b"\x48\xb8" + q(resolver)
            code += b"\xff\xd0\x49\xba" + q(data) + b"\x49\x89\x02\x48\xb8" + q(last_error)
            code += b"\xff\xd0\x49\xba" + q(data) + b"\x49\x89\x42\x08\x48\x83\xc4\x28\xc3"
        se.mem_write(code_base, code)
        se.run_shellcode(code_base)
        assert se.get_report().entry_points[0].error is None
        width = se.get_ptr_size()
        result, error = (int.from_bytes(se.mem_read(data + offset, width), "little") for offset in (0, 8))
        expected = se.emu.get_proc(module, name) if result else 0
        return result, error & 0xFFFFFFFF, expected


@pytest.mark.parametrize("architecture", ["x86", "amd64"])
def test_get_proc_address_resolves_declared_names_missing_from_the_manifest(config, architecture):
    name = "GetSystemLeapSecondInformation"
    assert name not in {e.name for e in get_export_manifest("kernel32", architecture.replace("amd64", "x64")).exports}
    result, _, expected = call_get_proc_address(config, architecture, "kernel32", name)
    assert result and result == expected


@pytest.mark.parametrize("architecture", ["x86", "amd64"])
def test_get_proc_address_reports_unknown_names(config, architecture):
    config["modules"]["functions_always_exist"] = False
    assert call_get_proc_address(config, architecture, "kernel32", "SpeakeasyNoSuchExport")[:2] == (0, 127)
