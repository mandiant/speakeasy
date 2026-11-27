"""Child processes run after the parent unless runs.children is false."""

import hashlib
import logging
import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows import windows as windefs
from tests.guest_harness import read_process_parameters
from tests.handler_harness import call
from tests.pe_builder import build_pe

CHILD_PATH = "c:\\child.exe"
CHILD_BASE = 0x10000000
# parent.c starts c:\child.exe. child.c returns the base of the first image in its loader
# list; child_x86 has the image base of the parent, child_at_10000000_x86 has CHILD_BASE.
PARENT = "parent_x86.exe.xz"
CHILD = "child_x86.exe.xz"
CHILD_AT_CHILD_BASE = "child_at_10000000_x86.exe.xz"
MUTEX_NAME = b"parent_mutex\0"
MUTEX_ALL_ACCESS = 0x1F0001


def get_parent(se, module):
    return next(p for p in se.emu.processes if p.path == module.emu_path)


def test_child_exe_runs_at_the_base_of_the_parent_exe(config, load_test_bin):
    parent = load_test_bin(PARENT)
    with Speakeasy(config=config) as se:
        module = se.load_module(data=parent)
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.run_module(module)
        child = se.emu.get_mod_from_addr(module.base)
        pids = [get_parent(se, module).pid, se.emu.get_current_process().pid]
        report = se.get_report()
        entries = report.runs

    assert (child.name, child.emu_path) == ("child", CHILD_PATH)
    assert report.sha256 == hashlib.sha256(parent).hexdigest()

    assert [(ep.type, ep.error) for ep in entries] == [("module_entry", None), ("module_entry", None)]
    assert entries[0].return_value == 1
    assert entries[1].return_value == module.base
    assert len(set(pids)) == 2
    assert [ep.pid for ep in entries] == pids


def test_report_lists_the_parent_and_the_child_with_their_runs(config, load_test_bin):
    config["process"]["command_line"] = "parent.exe -x"
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.run_module(module)
        report = se.get_report()

    parent, child = report.processes
    # The child loads at the base of the parent, so the module at image_base does not identify the process of the input.
    assert report.pid == parent.pid
    assert (parent.pid, parent.parent_pid, parent.path, parent.command_line, parent.runs) == (
        report.runs[0].pid,
        None,
        module.emu_path,
        "parent.exe -x",
        [0],
    )
    # parent.c gives CreateProcessA no command line, so the application name is the command line.
    assert (child.pid, child.parent_pid, child.path, child.command_line, child.runs) == (
        report.runs[1].pid,
        parent.pid,
        CHILD_PATH,
        CHILD_PATH,
        [1],
    )


@pytest.mark.parametrize(("runs", "count"), [({}, 2), ({"children": False}, 1)])
def test_child_runs_by_default_unless_runs_children_is_false(config, load_test_bin, runs, count):
    config["runs"] = runs
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.run_module(module)

        assert len(se.get_report().runs) == count


def test_child_without_relocations_whose_base_is_in_use_is_skipped(config, load_test_bin, caplog):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.emu.mem_map(0x1000, base=CHILD_BASE, tag="test.block")
        with caplog.at_level(logging.WARNING):
            se.run_module(module)
        report = se.get_report()

    assert [(ep.type, ep.error) for ep in report.runs] == [("module_entry", None)]
    assert f"skipping child process {CHILD_PATH}" in caplog.text
    assert "Cannot rebase a guest PE without valid relocation data" in caplog.text
    assert [(e.type, e.pid) for e in report.errors] == [("child_process_skipped", report.processes[1].pid)]


def test_child_finds_its_own_image_first_in_its_loader_list(config, load_test_bin):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.run_module(module)
        child = se.emu.get_current_process()
        entries = se.get_report().runs

    assert [(ep.type, ep.error) for ep in entries] == [("module_entry", None), ("module_entry", None)]
    assert entries[1].return_value == CHILD_BASE
    assert [entry.object.DllBase for entry in child.ldr_entries][:4] == [
        CHILD_BASE,
        se.emu.get_mod_by_name("ntdll").base,
        se.emu.get_mod_by_name("kernel32").base,
        se.emu.get_mod_by_name("kernelbase").base,
    ]


def test_finished_parent_gives_up_its_image_peb_and_heap(config, load_test_bin):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.run_module(module)
        parent = get_parent(se, module)
        maps = se.emu.get_mem_maps()
        heap = [address for address, _, name in parent.heap_allocs if name == "LocalAlloc"]

    assert parent.pe is module
    assert module not in se.emu.modules
    assert all(not m.base <= module.base < m.base + m.size for m in maps)
    assert all(m.free for m in maps if m.base <= parent.peb.address < m.base + m.size)
    assert len(heap) == 1
    assert all(m.free for m in maps if m.base <= heap[0] < m.base + m.size)


def test_child_does_not_get_the_exception_handlers_of_the_parent(config, load_test_bin):
    def create_process(e, api, original, args):
        # As AddVectoredExceptionHandler and SetUnhandledExceptionFilter do before CreateProcessA
        e.add_vectored_exception_handler(True, module.base + 0x1000)
        e.set_unhandled_exception_handler(module.base + 0x1100)
        return original(args)

    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.add_api_hook(create_process, "kernel32", "CreateProcessA")
        se.run_module(module)
        child = (se.emu.get_veh_handlers(), se.emu.get_unhandled_exception_handler())
        se.emu.set_current_process(get_parent(se, module))
        parent = (se.emu.get_veh_handlers(), se.emu.get_unhandled_exception_handler())

    assert parent == ([module.base + 0x1000], module.base + 0x1100)
    assert child == ([], 0)


def test_child_gets_a_copy_of_the_directory_and_environment_of_the_parent(config, load_test_bin):
    def create_process(e, api, original, args):
        e.set_cd("C:\\parent\\")
        rv = original(args)
        e.set_env("after", "1")
        return rv

    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.add_api_hook(create_process, "kernel32", "CreateProcessA")
        se.run_module(module)
        child = (se.emu.get_cd(), "after" in se.emu.get_env())
        se.emu.set_current_process(get_parent(se, module))
        parent = (se.emu.get_cd(), "after" in se.emu.get_env())

    assert parent == ("C:\\parent\\", True)
    assert child == ("C:\\parent\\", False)


def test_child_peb_has_its_image_path_command_line_and_directory(config, load_test_bin):
    def create_process(e, api, original, args):
        command_line, directory = se.mem_alloc(0x100), se.mem_alloc(0x100)
        se.mem_write(command_line, f"{CHILD_PATH} -run\0".encode())
        se.mem_write(directory, b"C:\\work\0")
        args[1], args[7] = command_line, directory
        return original(args)

    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.add_api_hook(create_process, "kernel32", "CreateProcessA")
        se.run_module(module)
        child = se.emu.get_current_process()

        assert len(se.get_report().runs) == 2
        assert read_process_parameters(se, child) == (CHILD_PATH, f"{CHILD_PATH} -run", "C:\\work\\")


def push(value):
    return b"\x68" + struct.pack("<I", value)


def call_import(base, iat, name, dll="kernel32.dll"):
    return b"\xff\x15" + struct.pack("<I", base + iat[dll, name])


def build_mutex_parent():
    """
    Build a parent that creates a mutex, starts a thread that waits on it, starts the child, and calls ExitProcess.

    The thread gets the mutex handle as its parameter and returns the result of WaitForSingleObject.
    """
    thread_offset = 0x100
    # .data: the mutex name at 0, the child path at 0x20, STARTUPINFOA at 0x40, PROCESS_INFORMATION at 0x90
    data = MUTEX_NAME.ljust(0x20, b"\0") + CHILD_PATH.encode() + b"\0"
    data = data.ljust(0x40, b"\0") + struct.pack("<I", 0x44)
    data = data.ljust(0xA0, b"\0")

    def text(base, iat):
        data_va = base + 0x2000
        code = push(data_va) + push(1) + push(0) + call_import(base, iat, "CreateMutexA")
        code += push(0) * 2 + b"\x50" + push(base + 0x1000 + thread_offset) + push(0) * 2
        code += call_import(base, iat, "CreateThread")
        code += push(data_va + 0x90) + push(data_va + 0x40) + push(0) * 7 + push(data_va + 0x20)
        code += call_import(base, iat, "CreateProcessA")
        code += push(0) + call_import(base, iat, "ExitProcess")
        # push INFINITE; push [esp + 8]; call WaitForSingleObject; ret 4
        thread = b"\x6a\xff\xff\x74\x24\x08" + call_import(base, iat, "WaitForSingleObject") + b"\xc2\x04\x00"
        return code.ljust(thread_offset, b"\xcc") + thread

    imports = {"kernel32.dll": ["CreateMutexA", "CreateThread", "CreateProcessA", "ExitProcess", "WaitForSingleObject"]}
    return build_pe(32, text=text, data=data, imports=imports)[0]


def build_mutex_child():
    """Build a child that returns the handle that OpenMutexA gives for the mutex name of the parent."""

    def text(base, iat):
        return push(base + 0x2000) + push(0) + push(MUTEX_ALL_ACCESS) + call_import(base, iat, "OpenMutexA") + b"\xc3"

    return build_pe(32, text=text, data=MUTEX_NAME, imports={"kernel32.dll": ["OpenMutexA"]})[0]


def test_child_does_not_find_a_mutex_that_only_its_exited_parent_had_open(config):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=build_mutex_parent())
        se.emu.fileman.add_existing_file(CHILD_PATH, build_mutex_child())
        se.run_module(module)
        entries = se.get_report().runs

    assert [(ep.type, ep.error) for ep in entries] == [("module_entry", None), ("thread", None), ("module_entry", None)]
    # The parent's thread runs after ExitProcess, and its handle is still open
    assert entries[1].return_value == windefs.WAIT_OBJECT_0
    assert entries[2].return_value == 0


def get_args(se, api):
    name = se.mem_alloc(0x100)
    se.mem_write(name, f"{CHILD_PATH}\x00".encode())
    pi = se.mem_alloc(0x10)
    return {
        "ShellExecuteA": [0, 0, name, 0, 0, 1],
        "WinExec": [name, 1],
        "CreateProcessAsUserA": [0, name, 0, 0, 0, 0, 0, 0, 0, pi, pi],
    }[api]


@pytest.mark.parametrize(
    "dll, api",
    [("shell32", "ShellExecuteA"), ("kernel32", "WinExec"), ("advapi32", "CreateProcessAsUserA")],
)
def test_child_started_without_create_process_runs(config, load_test_bin, dll, api):
    # parent.c starts the child with CreateProcessA. The hook starts it with another API.
    def create_process(e, api_name, original, args):
        call(se, dll, api, get_args(se, api))
        return 1

    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.add_api_hook(create_process, "kernel32", "CreateProcessA")
        se.run_module(module)
        entries = se.get_report().runs

    assert [(ep.type, ep.error) for ep in entries] == [("module_entry", None), ("module_entry", None)]
    assert entries[1].return_value == module.base


def test_child_that_is_not_a_pe_is_skipped(config, load_test_bin):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, b"@echo off\r\n")
        se.run_module(module)
        report = se.get_report()

    child = report.processes[1]
    assert [(ep.type, ep.error) for ep in report.runs] == [("module_entry", None)]
    assert (child.path, child.runs) == (CHILD_PATH, [])
    assert [(e.type, e.pid, e.context_summary) for e in report.errors] == [
        ("child_process_skipped", child.pid, f"{CHILD_PATH}: no PE image in the emulated file system")
    ]


def test_child_from_a_volume_runs(config, load_test_bin, tmp_path):
    (tmp_path / "child.exe").write_bytes(load_test_bin(CHILD))
    with Speakeasy(config=config, volumes=[f"{tmp_path}:c:\\"]) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.run_module(module)
        report = se.get_report()

    assert [(ep.type, ep.error) for ep in report.runs] == [("module_entry", None), ("module_entry", None)]
    assert report.runs[1].return_value == module.base
    assert [(p.path, p.runs) for p in report.processes][1:] == [(CHILD_PATH, [1])]
    assert report.errors == []


def build_command_line_child():
    """Build a child that returns the pointer that GetCommandLineA gives."""

    def text(base, iat):
        return call_import(base, iat, "GetCommandLineA") + b"\xc3"

    return build_pe(32, text=text, imports={"kernel32.dll": ["GetCommandLineA"]})[0]


def test_child_started_without_a_command_line_gets_the_application_name(config):
    # The parent calls CreateProcessA with lpApplicationName set and lpCommandLine NULL
    with Speakeasy(config=config) as se:
        module = se.load_module(data=build_mutex_parent())
        se.emu.fileman.add_existing_file(CHILD_PATH, build_command_line_child())
        se.run_module(module)
        entries = se.get_report().runs
        command_line = se.read_mem_string(entries[-1].return_value, 1)

    assert [e.command_line for e in entries[0].events if e.event == "process_create"] == [CHILD_PATH]
    assert entries[-1].type == "module_entry"
    assert command_line == CHILD_PATH


NOTEPAD_PATH = "C:\\Windows\\system32\\notepad.exe"
PROCESS_ALL_ACCESS = 0x1F0FFF


def build_injector():
    """
    Build a parent that starts notepad.exe suspended, opens it again by its PID, and starts a thread in it.

    The thread runs code that the parent wrote into memory that it allocated in the child. The code returns 42.
    """
    # .data: the path at 0, STARTUPINFOA at 0x40, PROCESS_INFORMATION at 0x90, the thread code at 0xA0
    data = NOTEPAD_PATH.encode().ljust(0x40, b"\0") + struct.pack("<I", 0x44)
    data = data.ljust(0xA0, b"\0") + b"\xb8\x2a\x00\x00\x00\xc2\x04\x00"
    data = data.ljust(0xB0, b"\0")

    def text(base, iat):
        data_va = base + 0x2000
        code = push(data_va + 0x90) + push(data_va + 0x40) + push(0) * 2 + push(4) + push(0) * 4 + push(data_va)
        code += call_import(base, iat, "CreateProcessA")
        # esi keeps the process handle, edi keeps the address of the memory in the child
        code += b"\xff\x35" + struct.pack("<I", data_va + 0x98) + push(0) + push(PROCESS_ALL_ACCESS)
        code += call_import(base, iat, "OpenProcess") + b"\x8b\xf0"
        code += push(0x40) + push(0x3000) + push(0x1000) + push(0) + b"\x56"
        code += call_import(base, iat, "VirtualAllocEx") + b"\x8b\xf8"
        code += push(0) + push(8) + push(data_va + 0xA0) + b"\x57\x56"
        code += call_import(base, iat, "WriteProcessMemory")
        code += push(0) * 3 + b"\x57" + push(0) * 2 + b"\x56" + call_import(base, iat, "CreateRemoteThread")
        return code + b"\xc3"

    imports = {
        "kernel32.dll": ["CreateProcessA", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    }
    return build_pe(32, text=text, data=data, imports=imports)[0]


def test_parent_opens_a_child_by_its_pid_and_runs_code_in_it(config):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=build_injector())
        se.run_module(module)
        report = se.get_report()

    child = next(p for p in report.processes if p.path == NOTEPAD_PATH)
    assert [(r.type, r.error) for r in report.runs] == [("module_entry", None), ("thread", None)]
    assert (report.runs[1].pid, report.runs[1].return_value) == (child.pid, 42)


def call_api(base, iat, dll, name, args):
    """
    Call an import with args.

    An int arg is a value, and a tuple (address,) is the value at the address.
    """
    code = b""
    for arg in reversed(args):
        code += b"\xff\x35" + struct.pack("<I", arg[0]) if isinstance(arg, tuple) else push(arg)
    return code + call_import(base, iat, name, dll)


def build_hollower(resume):
    """
    Build a parent that hollows notepad.exe and then calls the resume API to start the child.

    The parent starts the child suspended, writes a stub into it, and sets the thread context to the stub. The stub
    returns 42. The parent returns the previous suspend count that NtResumeThread gives, or the status of
    NtResumeProcess.
    """
    # .data: the path at 0, STARTUPINFOA at 0x40, PROCESS_INFORMATION at 0xB0, the stub at 0xD0, the previous suspend
    # count at 0xD8, the address of the stub in the child at 0xE0, CONTEXT at 0x100
    stub = b"\xb8\x2a\x00\x00\x00\xc2\x04\x00"
    data = NOTEPAD_PATH.encode().ljust(0x40, b"\0") + struct.pack("<I", 0x44)
    data = data.ljust(0xD0, b"\0") + stub
    data = data.ljust(0x100, b"\0") + struct.pack("<I", 0x10003)
    data = data.ljust(0x100 + 0x2CC, b"\0")

    def text(base, iat):
        data_va = base + 0x2000
        hproc, hthread = (data_va + 0xB0,), (data_va + 0xB4,)
        prev, remote, context = data_va + 0xD8, data_va + 0xE0, data_va + 0x100

        def api(name, args, dll="kernel32.dll"):
            return call_api(base, iat, dll, name, args)

        code = api("CreateProcessA", [data_va, 0, 0, 0, 0, 4, 0, 0, data_va + 0x40, data_va + 0xB0])
        code += api("VirtualAllocEx", [hproc, 0, 0x1000, 0x3000, 0x40]) + b"\xa3" + struct.pack("<I", remote)
        code += api("WriteProcessMemory", [hproc, (remote,), data_va + 0xD0, len(stub), 0])
        code += api("GetThreadContext", [hthread, context])
        code += b"\xa1" + struct.pack("<I", remote) + b"\xa3" + struct.pack("<I", context + 0xB8)
        code += api("SetThreadContext", [hthread, context])
        if resume == "NtResumeThread":
            code += api("NtResumeThread", [hthread, prev], "ntdll.dll") + b"\xa1" + struct.pack("<I", prev)
        else:
            code += api("NtResumeProcess", [hproc], "ntdll.dll")
        return code + b"\xc3"

    imports = {
        "kernel32.dll": [
            "CreateProcessA",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "GetThreadContext",
            "SetThreadContext",
        ],
        "ntdll.dll": ["NtResumeThread", "NtResumeProcess"],
    }
    return build_pe(32, text=text, data=data, imports=imports)[0]


@pytest.mark.parametrize(("resume", "previous"), [("NtResumeThread", 1), ("NtResumeProcess", 0)])
def test_parent_resumes_a_hollowed_child_at_the_stub_that_it_wrote(config, resume, previous):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=build_hollower(resume))
        se.run_module(module)
        stub = int.from_bytes(se.mem_read(module.base + 0x20E0, 4), "little")
        report = se.get_report()

    child = next(p for p in report.processes if p.path == NOTEPAD_PATH)
    assert [(r.type, r.error) for r in report.runs] == [("module_entry", None), ("thread", None)]
    assert report.runs[0].return_value == previous
    assert (report.runs[1].pid, report.runs[1].start_address, report.runs[1].return_value) == (child.pid, stub, 42)
