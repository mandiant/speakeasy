"""Built PE32/PE32+ images that call APIs through their IAT."""

import struct
import time

import pefile
import pytest
import unicorn

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from tests.pe_builder import build_pe

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


def test_timeout_budget_public_pe_iat_calls_are_independent():
    marker = b"\xb8\x37\x13\0\0"
    data, _ = build_pe(32, text=calls(32, [("kernel32.dll", "GetTickCount")], suffix=marker), imports=TICK)
    with Speakeasy(config=configured(timeout=0.5)) as se:

        def tick(emu, name, original, args):
            time.sleep(0.3)
            return 7

        se.add_api_hook(tick, "kernel32", "GetTickCount", argc=0)
        module = se.load_module(data=data)
        se.run_module(module)
        se.call(module.base + 0x1000)
        assert se.reg_read("eax") == 0x1337
        entries = se.get_report().entry_points
        assert len(entries) == 2
        assert all(entry.error is None and api_names(entry) == ["kernel32.GetTickCount"] for entry in entries)


def test_public_guest_data_execution_and_nx_policy():
    def text(base, iat):
        load = b"\xb8" + struct.pack("<I", base + 0x2000)
        return calls(32, [("kernel32.dll", "GetTickCount")], prefix=load + b"\xff\xd0")(base, iat)

    data, _ = build_pe(32, text=text, data=b"\xb8\x2a\0\0\0\xc3", imports=TICK, nxcompat=True)
    hits = []
    with Speakeasy(config=configured()) as se:

        def tick(emu, name, original, args):
            hits.append(name)
            assert emu.reg_read("eax") == 42
            return 77

        se.add_api_hook(tick, "kernel32", "GetTickCount", argc=0)
        module = se.load_module(data=data)

        def permissions(address):
            return next(p for start, end, p in se.emu.get_mem_regions() if start <= address <= end)

        data_address = module.base + 0x2000
        previous = permissions(data_address)
        adjacent = permissions(module.base + 0x3000)
        assert previous == unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None and entry.ret_val == 77
        assert hits == ["kernel32.GetTickCount"]
        assert api_names(entry) == hits
        assert permissions(data_address) == previous | unicorn.UC_PROT_EXEC
        assert permissions(module.base + 0x3000) == adjacent


@pytest.mark.parametrize("malformation", ["delay-outside", "export-outside"])
def test_public_malformed_optional_pe_inventory_still_executes(malformation, caplog):
    if malformation == "delay-outside":
        section = b""
        dirs = {13: (0x7FFF0000, 64)}
    else:
        section = bytearray(0x80)
        struct.pack_into("<IIHHIIIIIII", section, 0, 0, 0, 0, 0, 0x2060, 1, 1, 0, 0x2040, 0, 0)
        struct.pack_into("<I", section, 0x40, 0x00FF0000)
        section[0x60:0x66] = b"x.dll\0"
        dirs = {0: (0x2000, 0x80)}
    data, _ = build_pe(
        32, text=calls(32, [("kernel32.dll", "GetTickCount")]), data=section, imports=TICK, extra_dirs=dirs
    )
    with Speakeasy(config=configured()) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None and api_names(entry) == ["kernel32.GetTickCount"]
        assert caplog.records


@pytest.mark.parametrize("oft_zero", [False, True])
def test_public_filtered_import_does_not_shift_valid_iat_call(oft_zero):
    imports = {"kernel32.dll": ["BadFunction", "GetTickCount"]}
    data, slots = build_pe(32, text=calls(32, [("kernel32.dll", "GetTickCount")]), imports=imports)
    pe = pefile.PE(data=data)
    first = pe.DIRECTORY_ENTRY_IMPORT[0].imports[0]
    if oft_zero:
        pe.DIRECTORY_ENTRY_IMPORT[0].struct.OriginalFirstThunk = 0
    raw = bytearray(pe.write())
    raw[first.name_offset] = 0xE9
    bad_slot = slots["kernel32.dll", "BadFunction"]
    original = pe.get_data(bad_slot, 4)
    with Speakeasy(config=configured()) as se:
        module = se.load_module(data=bytes(raw))
        assert se.mem_read(module.base + bad_slot, 4) == original
        bound = int.from_bytes(se.mem_read(module.base + slots["kernel32.dll", "GetTickCount"], 4), "little")
        assert bound == se.emu.get_proc("kernel32", "GetTickCount")
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None and api_names(entry) == ["kernel32.GetTickCount"]


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("always_exist", [False, True])
def test_public_unknown_iat_call_uses_four_argument_stub(architecture, always_exist):
    unknown = "SpeakeasyNoSuchExport"
    imports = {"kernel32.dll": [unknown, "GetTickCount"]}
    # The x86 stub is stdcall and pops four arguments.
    prefix = b"\x6a\x00" * 4 if architecture == 32 else b""
    data, _ = build_pe(
        architecture,
        text=calls(architecture, [("kernel32.dll", unknown), ("kernel32.dll", "GetTickCount")], prefix=prefix),
        imports=imports,
    )
    with Speakeasy(config=configured(**{"modules.functions_always_exist": always_exist})) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        if always_exist:
            assert entry.error is None
            assert api_names(entry) == [f"kernel32.{unknown}", "kernel32.GetTickCount"]
            event = next(event for event in entry.events if event.event == "api")
            assert event.ret_val == "0x1" and len(event.args) == 4
        else:
            assert entry.error.type == "unsupported_api"
            assert entry.error.api_name == f"kernel32.{unknown}"
            assert api_names(entry) == [f"kernel32.{unknown}"]


def test_unsupported_api_error_names_the_api_and_its_caller(caplog):
    unknown = "SpeakeasyNoSuchExport"
    data, _ = build_pe(32, text=calls(32, [("kernel32.dll", unknown)]), imports={"kernel32.dll": [unknown]})
    with Speakeasy(config=configured()) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        error = se.get_report().entry_points[0].error
        name = module.name
    assert error.type == "unsupported_api"
    assert error.instr == f"api_trap kernel32.{unknown}"
    assert error.context_summary == f"unsupported_api kernel32.{unknown} called from {name}+0x1006"
    assert error.nearby_regions is None
    assert "Invalid memory read" not in caplog.text


def test_public_catalogued_unsafe_iat_call_cannot_use_unknown_fallback():
    name = "GetLargestConsoleWindowSize"
    data, _ = build_pe(
        64,
        text=calls(64, [("kernel32.dll", name), ("kernel32.dll", "GetTickCount")]),
        imports={"kernel32.dll": [name, "GetTickCount"]},
    )
    with Speakeasy(config=configured(**{"modules.functions_always_exist": True})) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error.type == "unsupported_api"
        assert entry.error.api_name == f"kernel32.{name}"
        assert api_names(entry) == [f"kernel32.{name}"]


def test_non_ascii_imported_modules_keep_distinct_callable_identity():
    dlls = ("k\xe9rnel", "f\xfcnk")
    imports = {dll + ".dll": ["Foo"] for dll in dlls}
    imports.update(TICK)
    sequence = [(dll + ".dll", "Foo") for dll in dlls] + [("kernel32.dll", "GetTickCount")]
    data, _ = build_pe(32, text=calls(32, sequence), imports=imports)
    hits = []
    with Speakeasy(config=configured()) as se:

        def hook(emu, name, original, args):
            assert original is None and args == []
            hits.append(name)
            return 11

        for dll in dlls:
            se.add_api_hook(hook, dll, "Foo", argc=0)
        module = se.load_module(data=data)
        targets = set()
        for dll in dlls:
            dependency = se.emu.get_mod_by_name(dll)
            assert dependency.name == dll
            assert dependency.emu_path.endswith(dll + ".dll")
            assert dependency in se.emu.get_peb_modules()
            target = se.emu.get_proc(dll, "Foo")
            assert se.get_symbols()[target] == (dll, "Foo")
            targets.add(target)
        assert len(targets) == 2
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert entry.error is None
        assert hits == [dll + ".Foo" for dll in dlls]
        assert api_names(entry) == hits + ["kernel32.GetTickCount"]


def test_public_sp_changing_hook_stops_once_without_redispatch():
    data, _ = build_pe(32, text=calls(32, [("kernel32.dll", "GetTickCount")]), imports=TICK)
    hits = []
    with Speakeasy(config=configured()) as se:

        def hook(emu, api, original, args):
            hits.append(api)
            emu.push_stack(0x41414141)
            return 7

        se.add_api_hook(hook, "kernel32", "GetTickCount", argc=0)
        module = se.load_module(data=data)
        se.run_module(module)
        entry = se.get_report().entry_points[0]
        assert hits == ["kernel32.GetTickCount"]
        assert entry.error.type == "api_handler_did_not_return"
        assert entry.error.api_name == "kernel32.GetTickCount"
        events = [event for event in entry.events if event.event == "api"]
        assert len(events) == 1 and events[0].ret_val == "0x7"


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("memory_tracing", [False, True])
def test_api_event_pc_is_the_call_site(architecture, memory_tracing):
    data, _ = build_pe(architecture, text=calls(architecture, [("kernel32.dll", "GetTickCount")]), imports=TICK)
    with Speakeasy(config=configured(**{"analysis.memory_tracing": memory_tracing})) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        (event,) = [event for event in se.get_report().entry_points[0].events if event.event == "api"]
    call = module.base + 0x1000 + (4 if architecture == 64 else 0)
    assert event.pos.pc == (call if memory_tracing else call + 6)


NT_THREAD = {
    "ntdll.dll": ["NtCreateThreadEx", "NtWaitForSingleObject"],
    "kernel32.dll": ["GetTickCount"],
}


def nt_create_thread(base, iat):
    code = bytearray()

    def call_iat(dll, name):
        code.extend(b"\xff\x15" + struct.pack("<i", iat[dll, name] - (0x1000 + len(code) + 6)))

    code += b"\x48\x83\xec\x68"  # sub rsp, 0x68
    code += b"\x48\x8d\x4c\x24\x60"  # lea rcx, [rsp+0x60]
    code += b"\xba\xff\xff\x1f\x00"  # mov edx, 0x1fffff
    code += b"\x45\x31\xc0"  # xor r8d, r8d
    code += b"\x49\x83\xc9\xff"  # or r9, -1
    lea = len(code)
    code += b"\x48\x8d\x05\0\0\0\0"  # lea rax, [rip+thread_proc]
    code += b"\x48\x89\x44\x24\x20"  # mov [rsp+0x20], rax
    code += b"\x31\xc0"  # xor eax, eax
    for slot in range(0x28, 0x58, 8):
        code += b"\x48\x89\x44\x24" + bytes([slot])  # mov [rsp+slot], rax
    call_iat("ntdll.dll", "NtCreateThreadEx")
    code += b"\x48\x8b\x4c\x24\x60"  # mov rcx, [rsp+0x60]
    code += b"\x31\xd2"  # xor edx, edx
    code += b"\x45\x31\xc0"  # xor r8d, r8d
    call_iat("ntdll.dll", "NtWaitForSingleObject")
    code += b"\x48\x83\xc4\x68\xc3"  # add rsp, 0x68; ret
    struct.pack_into("<i", code, lea + 3, len(code) - (lea + 7))
    code += b"\x48\x83\xec\x28"  # sub rsp, 0x28
    call_iat("kernel32.dll", "GetTickCount")
    code += b"\x48\x83\xc4\x28\xc3"  # add rsp, 0x28; ret
    return bytes(code)


def test_nt_create_thread_ex_runs_the_thread():
    data, _ = build_pe(64, text=nt_create_thread, imports=NT_THREAD)
    with Speakeasy(config=configured()) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        entries = se.get_report().entry_points
        assert [(entry.ep_type, entry.error) for entry in entries] == [("module_entry", None), ("thread", None)]
        assert api_names(entries[0]) == ["ntdll.NtCreateThreadEx", "ntdll.NtWaitForSingleObject"]
        assert api_names(entries[1]) == ["kernel32.GetTickCount"]
        assert entries[1].start_addr == module.base + 0x105C


def test_nt_terminate_process_ends_the_run():
    def text(base, iat):
        code = b"\x48\x83\xec\x28"  # sub rsp, 0x28
        code += b"\x48\x83\xc9\xff"  # or rcx, -1
        code += b"\x31\xd2"  # xor edx, edx
        code += b"\xff\x15" + struct.pack("<i", iat["ntdll.dll", "NtTerminateProcess"] - (0x1000 + len(code) + 6))
        return code + b"\x0f\x0b"  # ud2

    data, _ = build_pe(64, text=text, imports={"ntdll.dll": ["NtTerminateProcess"]})
    with Speakeasy(config=configured()) as se:
        se.run_module(se.load_module(data=data))
        entry = se.get_report().entry_points[0]
        assert entry.error is None
        assert api_names(entry) == ["ntdll.NtTerminateProcess"]
