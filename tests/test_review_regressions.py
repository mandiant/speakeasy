"""Public PE/IAT counterparts of the supplied PR review reproductions."""

import struct
import time
from types import SimpleNamespace

import pefile
import pytest
import unicorn

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from speakeasy.windows import winemu
from speakeasy.winenv.api import sigdb
from tests.review_pebuild import build_pe
from tests.test_public_api_regressions import UnsafeDeclarationSource

TICK = {"kernel32.dll": ["GetTickCount"]}


def configured(**overrides):
    config = get_default_config_dict()
    config.update(timeout=3, max_instructions=1000, max_api_count=10)
    for key, value in overrides.items():
        node = config
        *parents, leaf = key.split(".")
        for parent in parents:
            node = node[parent]
        node[leaf] = value
    return config


def calls(architecture, imports, *, prefix=b"", suffix=b""):
    def text(base, iat):
        code = b"\x48\x83\xec\x28" if architecture == 64 else b""
        code += prefix
        for dll, name in imports:
            target = iat[dll, name]
            operand = (
                struct.pack("<i", target - (0x1000 + len(code) + 6))
                if architecture == 64
                else struct.pack("<I", base + target)
            )
            code += b"\xff\x15" + operand
        code += suffix
        if architecture == 64:
            code += b"\x48\x83\xc4\x28"
        return code + b"\xc3"

    return text


def api_names(entry):
    return [event.api_name for event in (entry.events or []) if event.event == "api"]


@pytest.mark.parametrize("architecture", [32, 64])
def test_timeout_budget_public_pe_iat_calls_are_independent(architecture, monkeypatch):
    marker = b"\xb8\x37\x13\0\0"
    data, _ = build_pe(
        architecture, text=calls(architecture, [("kernel32.dll", "GetTickCount")], suffix=marker), imports=TICK
    )
    clock = [0.0]
    origins = []
    with Speakeasy(config=configured(timeout=1)) as se:

        def tick(emu, name, original, args):
            assert emu.curr_run.execution_elapsed == 0
            origins.append(emu.curr_run)
            clock[0] += 0.6
            return 7

        se.add_api_hook(tick, "kernel32", "GetTickCount", argc=0)
        module = se.load_module(data=data)
        monkeypatch.setattr(winemu, "time", SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
        se.run_module(module)
        for _ in range(4):
            se.call(module.base + 0x1000)
            assert se.reg_read("eax") == 0x1337
        assert len(origins) == 5 and len({id(run) for run in origins}) == 5
        assert clock[0] == pytest.approx(3)
        assert all(run.execution_elapsed == pytest.approx(0.6) for run in origins)
        entries = se.get_report().entry_points
        assert len(entries) == 5
        assert all(entry.error is None and api_names(entry) == ["kernel32.GetTickCount"] for entry in entries)


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("nxcompat", [False, True])
@pytest.mark.parametrize("strict_nx", [None, False, True], ids=["default", "recover", "enforce"])
def test_public_guest_data_execution_and_nx_policy(architecture, nxcompat, strict_nx):
    def text(base, iat):
        load = (
            b"\x48\xb8" + struct.pack("<Q", base + 0x2000)
            if architecture == 64
            else b"\xb8" + struct.pack("<I", base + 0x2000)
        )
        return calls(architecture, [("kernel32.dll", "GetTickCount")], prefix=load + b"\xff\xd0")(base, iat)

    data, _ = build_pe(architecture, text=text, data=b"\xb8\x2a\0\0\0\xc3", imports=TICK, nxcompat=nxcompat)
    hits = []
    overrides = {} if strict_nx is None else {"analysis.enforce_nx": strict_nx}
    with Speakeasy(config=configured(**overrides)) as se:

        def tick(emu, name, original, args):
            hits.append(name)
            assert emu.reg_read("eax") == 42
            return 77

        se.add_api_hook(tick, "kernel32", "GetTickCount", argc=0)
        module = se.load_module(data=data)
        emu = se.emu

        def permissions(address):
            return next(p for start, end, p in emu.get_mem_regions() if start <= address <= end)

        data_address = module.base + 0x2000
        previous = permissions(data_address)
        adjacent = permissions(module.base + 0x3000)
        assert previous == unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        if strict_nx:
            assert entry.error.type == "invalid_protect_fetch"
            assert entry.error.pc == data_address
            assert hits == [] and api_names(entry) == []
            assert permissions(data_address) == previous
        else:
            assert entry.error is None and entry.ret_val == 77
            assert hits == ["kernel32.GetTickCount"]
            assert api_names(entry) == hits
            assert permissions(data_address) == previous | unicorn.UC_PROT_EXEC
        assert permissions(module.base + 0x3000) == adjacent


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("malformation", ["delay-outside", "delay-attributes", "export-outside", "non-ascii-dll"])
def test_public_malformed_optional_pe_inventory_still_executes(architecture, malformation, caplog):
    imports, dirs, section = TICK, {}, b""
    if malformation == "delay-outside":
        dirs = {13: (0x7FFF0000, 64)}
    elif malformation == "delay-attributes":
        section = struct.pack("<8I", 5, 0x2100, 0, 0x2200, 0x2300, 0, 0, 0) + b"\0" * 32
        dirs = {13: (0x2000, 64)}
    elif malformation == "export-outside":
        section = bytearray(0x80)
        struct.pack_into("<IIHHIIIIIII", section, 0, 0, 0, 0, 0, 0x2060, 1, 1, 0, 0x2040, 0, 0)
        struct.pack_into("<I", section, 0x40, 0x00FF0000)
        section[0x60:0x66] = b"x.dll\0"
        dirs = {0: (0x2000, 0x80)}
    else:
        imports = {**TICK, "k\xe9rnel.dll": ["Foo"]}
    data, _ = build_pe(
        architecture,
        text=calls(architecture, [("kernel32.dll", "GetTickCount")]),
        data=section,
        imports=imports,
        extra_dirs=dirs,
    )
    with Speakeasy(config=configured()) as se:
        module = se.load_module(data=data)
        if malformation == "non-ascii-dll":
            assert any(imp.dll_name == "k\xe9rnel" and imp.func_name == "Foo" for imp in module._image.imports)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None and api_names(entry) == ["kernel32.GetTickCount"]
        assert caplog.records
    with Speakeasy(config=configured(**{"modules.strict_pe_parsing": True})) as se:
        with pytest.raises(ValueError):
            se.load_module(data=data)


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("oft_zero", [False, True])
@pytest.mark.parametrize("bad_name", [0, 0xE9], ids=["empty", "non-ascii"])
def test_public_filtered_import_does_not_shift_valid_iat_call(architecture, oft_zero, bad_name, caplog):
    imports = {"kernel32.dll": ["BadFunction", "GetTickCount"]}
    data, slots = build_pe(architecture, text=calls(architecture, [("kernel32.dll", "GetTickCount")]), imports=imports)
    pe = pefile.PE(data=data)
    first = pe.DIRECTORY_ENTRY_IMPORT[0].imports[0]
    if oft_zero:
        pe.DIRECTORY_ENTRY_IMPORT[0].struct.OriginalFirstThunk = 0
    raw = bytearray(pe.write())
    raw[first.name_offset] = bad_name
    first_value = int.from_bytes(pe.get_data(slots["kernel32.dll", "BadFunction"], architecture // 8), "little")
    with Speakeasy(config=configured()) as se:
        module = se.load_module(data=bytes(raw))
        static = module._image.imports
        assert [(imp.func_name, imp.iat_address) for imp in static] == [
            ("GetTickCount", module.base + slots["kernel32.dll", "GetTickCount"])
        ]
        assert (
            int.from_bytes(se.mem_read(module.base + slots["kernel32.dll", "BadFunction"], architecture // 8), "little")
            == first_value
        )
        target = se.emu.get_proc("kernel32", "GetTickCount")
        assert int.from_bytes(se.mem_read(static[0].iat_address, architecture // 8), "little") == target
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None and api_names(entry) == ["kernel32.GetTickCount"]
        assert "Skipping malformed PE static import entry" in caplog.text
    with Speakeasy(config=configured(**{"modules.strict_pe_parsing": True})) as se:
        with pytest.raises(ValueError):
            se.load_module(data=bytes(raw))


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("always_exist", [False, True])
def test_public_unknown_iat_call_has_architecture_safe_return(architecture, always_exist):
    unknown = "SpeakeasyNoSuchExport"
    imports = {"kernel32.dll": [unknown, "GetTickCount"]}
    data, _ = build_pe(
        architecture,
        text=calls(architecture, [("kernel32.dll", unknown), ("kernel32.dll", "GetTickCount")]),
        imports=imports,
    )
    with Speakeasy(config=configured(**{"modules.functions_always_exist": always_exist})) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        if architecture == 64 and always_exist:
            assert entry.error is None
            assert api_names(entry) == [f"kernel32.{unknown}", "kernel32.GetTickCount"]
            event = next(event for event in entry.events if event.event == "api")
            assert event.ret_val == "0x1" and event.args == []
        else:
            assert entry.error.type == "unsupported_api"
            assert entry.error.api_name == f"kernel32.{unknown}"
            assert api_names(entry) == [f"kernel32.{unknown}"]


class ImportedUnsafeSource(UnsafeDeclarationSource):
    def iter_functions(self, dll, architecture):
        declaration = self.lookup(dll, self.declaration.name, architecture)
        return iter(()) if declaration is None else iter((declaration,))


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize(
    "return_type, parameter_type",
    [("f64", None), ("u32", "f32"), ("st:PAIR:16", None), ("u32", "st:PAIR:16")],
    ids=["float-return", "float-argument", "aggregate-return", "aggregate-argument"],
)
def test_public_catalogued_unsafe_iat_call_cannot_use_unknown_fallback(
    architecture, return_type, parameter_type, monkeypatch
):
    dll, name = "review_unsafe", "RequiresExplicitHandler"
    declaration = sigdb.FuncSig(
        dll=dll,
        name=name,
        ret=return_type,
        params=() if parameter_type is None else (sigdb.ParamSig("value", parameter_type),),
    )
    database = sigdb.SignatureDatabase([ImportedUnsafeSource(declaration)])
    monkeypatch.setattr(winemu.WindowsEmulator, "get_signature_db", lambda self: database)
    imports = {dll + ".dll": [name], **TICK}
    data, _ = build_pe(
        architecture,
        text=calls(architecture, [(dll + ".dll", name), ("kernel32.dll", "GetTickCount")]),
        imports=imports,
    )
    with Speakeasy(config=configured(**{"modules.functions_always_exist": True})) as se:
        module = se.load_module(data=data)
        dependency = se.emu.get_mod_by_name(dll)
        export = dependency.get_export_by_name(name)
        assert export is not None
        assert not declaration.supports_emulation(architecture // 8)
        assert se.get_symbols()[export.address] == (dll, name)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error.type == "unsupported_api"
        assert entry.error.api_name == f"{dll}.{name}"
        assert api_names(entry) == [f"{dll}.{name}"]


@pytest.mark.parametrize("architecture", [32, 64])
def test_non_ascii_imported_modules_keep_distinct_callable_identity(architecture):
    dlls = ("k\xe9rnel", "f\xfcnk")
    imports = {dll + ".dll": ["Foo"] for dll in dlls}
    imports.update(TICK)
    sequence = [(dll + ".dll", "Foo") for dll in dlls] + [("kernel32.dll", "GetTickCount")]
    data, _ = build_pe(architecture, text=calls(architecture, sequence), imports=imports)
    hits = []
    with Speakeasy(config=configured()) as se:

        def hook(emu, name, original, args):
            assert original is None and args == []
            hits.append(name)
            return 11

        for dll in dlls:
            se.add_api_hook(hook, dll, "Foo", argc=0)
        module = se.load_module(data=data)
        targets = []
        for dll in dlls:
            dependency = se.emu.get_mod_by_name(dll)
            assert dependency.name == dll
            assert dependency.emu_path.endswith(dll + ".dll")
            assert dependency in se.emu.get_peb_modules()
            target = se.emu.get_proc(dll, "Foo")
            targets.append(target)
            assert se.get_symbols()[target] == (dll, "Foo")
            imported = next(imp for imp in module._image.imports if imp.dll_name == dll)
            assert int.from_bytes(se.mem_read(imported.iat_address, architecture // 8), "little") == target
        assert len(set(targets)) == 2
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None
        assert hits == [dll + ".Foo" for dll in dlls]
        assert api_names(entry) == hits + ["kernel32.GetTickCount"]


@pytest.mark.parametrize("architecture", [32, 64])
def test_public_import_symbols_and_sp_changing_hook(architecture):
    data, _ = build_pe(architecture, text=calls(architecture, [("kernel32.dll", "GetTickCount")]), imports=TICK)
    hits = []
    with Speakeasy(config=configured()) as se:

        def hook(emu, api, original, args):
            hits.append(api)
            emu.push_stack(0x41414141)
            return 7

        se.add_api_hook(hook, "kernel32", "GetTickCount", argc=0)
        module = se.load_module(data=data)
        address = se.emu.get_proc("kernel32", "GetTickCount")
        assert se.get_symbols()[address] == ("kernel32", "GetTickCount")
        slot = module._image.imports[0].iat_address
        assert int.from_bytes(se.mem_read(slot, architecture // 8), "little") == address
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert hits == ["kernel32.GetTickCount"]
        assert entry.error.type == "api_handler_did_not_return"
        assert entry.error.api_name == "kernel32.GetTickCount"
