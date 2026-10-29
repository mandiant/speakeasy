"""CPU exceptions reach guest handlers with the code and addresses Windows reports."""

import struct
from functools import partial

import pytest

from speakeasy import Speakeasy
from tests.guest_harness import Deref, get_api, guest_call

STATUS_GUARD_PAGE_VIOLATION = 0x80000001
STATUS_BREAKPOINT = 0x80000003
STATUS_SINGLE_STEP = 0x80000004
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096

MEM_COMMIT_RESERVE = 0x3000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100

# name: (code, exception code, ExceptionAddress - start, the Rip adjustment a handler makes to continue)
CASES = {
    "int3": (b"\xcc", STATUS_BREAKPOINT, 0, 1),
    "int 3": (b"\xcd\x03", STATUS_BREAKPOINT, 1, 1),
    "int 2d": (b"\xcd\x2d", STATUS_BREAKPOINT, 3, 0),
    "int 0x80": (b"\xcd\x80", STATUS_ACCESS_VIOLATION, 0, 2),
    "int 1": (b"\xcd\x01", STATUS_ACCESS_VIOLATION, 0, 2),
    "icebp": (b"\xf1", STATUS_SINGLE_STEP, 1, 0),
    "ud2": (b"\x0f\x0b", STATUS_ILLEGAL_INSTRUCTION, 0, 2),
    "hlt": (b"\xf4", STATUS_PRIVILEGED_INSTRUCTION, 0, 1),
    "in": (b"\xec", STATUS_PRIVILEGED_INSTRUCTION, 0, 1),
    "out": (b"\xee", STATUS_PRIVILEGED_INSTRUCTION, 0, 1),
    "divide by zero": (b"\x31\xc9\xf7\xf1", STATUS_INTEGER_DIVIDE_BY_ZERO, 2, 2),
    "read null": (b"\x31\xc0\x8b\x00", STATUS_ACCESS_VIOLATION, 2, 2),  # xor eax, eax; mov eax, [rax]
    # pushf; or dword [rsp], 0x100; popf; nop: the trap follows the nop
    "trap flag": (b"\x9c\x81\x0c\x24\x00\x01\x00\x00\x9d\x90", STATUS_SINGLE_STEP, 10, 0),
}

RETURN_42 = b"\xb8\x2a\x00\x00\x00\xc3"

GP_FAULT_LOOP = "0260bad6886b0ec43193ce4157586568e275fc4e942bf4c7f7eb63c0c74ce2cb.exe.xz"
MEMCPY_PAST_ARGS = "0fcf7079fe017d13ab73f81c1b7e0b11b551f763469bae89a783ae98eae43db7.dll.xz"
FASTFAIL_IN_DLL_MAIN = "0ee3d87024f8d450521f99d1157c8899012d37a543147ffe9623eef6ec8ab60e.dll.xz"


def vectored_handler(data, step):
    """
    Store the exception code, address and first two parameters at data, advance Rip by step,
    and continue execution.
    """
    code = b"\x48\x8b\x01"  # mov rax, [rcx]  (ExceptionRecord)
    code += b"\x8b\x10\x89\x14\x25" + struct.pack("<I", data)  # [data] = ExceptionCode
    code += b"\x48\x8b\x50\x10\x48\x89\x14\x25" + struct.pack("<I", data + 8)  # [data + 8] = ExceptionAddress
    code += b"\x48\x8b\x50\x20\x48\x89\x14\x25" + struct.pack("<I", data + 16)  # [data + 16] = parameter 0
    code += b"\x48\x8b\x50\x28\x48\x89\x14\x25" + struct.pack("<I", data + 24)  # [data + 24] = parameter 1
    code += b"\x48\x8b\x41\x08"  # mov rax, [rcx + 8]  (ContextRecord)
    code += b"\x48\x83\x80\xf8\x00\x00\x00" + bytes([step])  # add qword [rax + Rip], step
    code += b"\xb8\xff\xff\xff\xff\xc3"  # return EXCEPTION_CONTINUE_EXECUTION
    return code


def vectored_handler_x86(data, step):
    """vectored_handler for x86."""
    code = b"\x8b\x44\x24\x04\x8b\x08"  # mov eax, [esp + 4]; mov ecx, [eax]  (ExceptionRecord)
    code += b"\x8b\x11\x89\x15" + struct.pack("<I", data)  # [data] = ExceptionCode
    code += b"\x8b\x51\x0c\x89\x15" + struct.pack("<I", data + 8)  # [data + 8] = ExceptionAddress
    code += b"\x8b\x51\x14\x89\x15" + struct.pack("<I", data + 16)  # [data + 16] = parameter 0
    code += b"\x8b\x51\x18\x89\x15" + struct.pack("<I", data + 24)  # [data + 24] = parameter 1
    code += b"\x8b\x40\x04"  # mov eax, [eax + 4]  (ContextRecord)
    code += b"\x83\x80\xb8\x00\x00\x00" + bytes([step])  # add dword [eax + Eip], step
    code += b"\xb8\xff\xff\xff\xff\xc2\x04\x00"  # return EXCEPTION_CONTINUE_EXECUTION
    return code


def module_entry(se):
    return next(e for e in se.get_report().entry_points if e.ep_type == "module_entry")


def run_under_handler(config, arch, insn, step):
    """Run insn under vectored_handler; return the run, the address of insn and the handler's record."""
    ptr_size = 8 if arch == "amd64" else 4
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x2000, arch=arch)
        data = se.mem_alloc(0x1000)
        handler = code + 0x1000
        se.mem_write(handler, (vectored_handler if ptr_size == 8 else vectored_handler_x86)(data, step))
        setup = guest_call(ptr_size, get_api(se, "kernel32", "AddVectoredExceptionHandler"), 1, handler)
        se.mem_write(code, setup + insn + RETURN_42)

        se.run_shellcode(code)

        record = struct.unpack("<IxxxxQQQ", se.mem_read(data, 32))
        return se.get_report().entry_points[0], code + len(setup), record


@pytest.mark.parametrize("arch", ["amd64", "x86"])
@pytest.mark.parametrize("name", CASES)
def test_cpu_exception_reaches_vectored_handler(config, arch, name):
    insn, exception_code, offset, step = CASES[name]
    run, start, record = run_under_handler(config, arch, insn, step)
    assert run.error is None
    assert run.ret_val == 42
    assert record[:2] == (exception_code, start + offset)


def test_general_protection_fault_reports_the_faulting_instruction(config, load_test_bin):
    """
    0260bad6 (x86) decrypts its code in place, then runs the far call lcall 0xde98:0xfb5d7f90
    at 0x40f231 under an SEH handler at 0x4115a0. The bad selector raises a general
    protection fault: an access violation at the start of the lcall.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(GP_FAULT_LOOP))
        seen = []

        def at_handler(emu, address, size):
            record, _, context = struct.unpack("<III", se.mem_read(se.reg_read("esp") + 4, 12))
            code, _, _, fault_address = struct.unpack("<IIII", se.mem_read(record, 16))
            (eip,) = struct.unpack("<I", se.mem_read(context + 0xB8, 4))  # CONTEXT.Eip
            seen.append((code, fault_address, eip))
            se.stop()

        se.add_code_hook(at_handler, begin=0x4115A0, end=0x4115A0)
        se.run_module(module)

    assert seen == [(STATUS_ACCESS_VIOLATION, 0x40F231, 0x40F231)]


@pytest.mark.parametrize("arch, gate", [("amd64", 0x2E), ("x86", 0x2A)])
def test_system_service_gate_is_not_an_exception(config, arch, gate):
    run, _, _ = run_under_handler(config, arch, b"\xcd" + bytes([gate]), 2)
    assert run.error is not None
    assert run.error.type == "unhandled_interrupt"
    assert run.error.interrupt_num == gate
    assert not [e for e in run.events or [] if e.event == "exception"]


def test_debug_service_without_exception_skips_a_byte(config):
    # mov eax, 1 (BREAKPOINT_PRINT); int 2d; a byte the kernel skips; mov eax, 42; ret
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xb8\x01\x00\x00\x00\xcd\x2d\xcc" + RETURN_42, arch="amd64")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 42
        assert not [e for e in run.events or [] if e.event == "exception"]


@pytest.mark.parametrize("handler", [False, True], ids=["no handler", "handler continues search"])
@pytest.mark.parametrize(
    "insn, error, interrupt_num",
    [
        (b"\xcc", "unhandled_interrupt", 3),
        (b"\x0f\x0b", "Invalid instruction (UC_ERR_INSN_INVALID)", None),
        (b"\xf4", "privileged_instruction", None),
        (b"\xc6\x00\x00", "invalid_protect_write", None),  # mov byte [rax], 0
    ],
)
def test_unhandled_cpu_exception_ends_the_run(config, insn, error, interrupt_num, handler):
    """The run ends with the same error whether or not a handler saw the exception."""
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x2000, arch="amd64")
        continue_search = code + 0x1000
        se.mem_write(continue_search, b"\x31\xc0\xc3")
        setup = b""
        if handler:
            setup += guest_call(8, get_api(se, "kernel32", "AddVectoredExceptionHandler"), 1, continue_search)
        # rax: a read-only page
        setup += guest_call(8, get_api(se, "kernel32", "VirtualAlloc"), 0, 0x1000, MEM_COMMIT_RESERVE, PAGE_READONLY)
        se.mem_write(code, setup + insn + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert run.error.type == error
        assert run.error.pc == code + len(setup)
        assert run.error.interrupt_num == interrupt_num
        assert len([e for e in run.events or [] if e.event == "exception"]) == handler


def run_with_page(config, protect, access, step=0, before=None):
    """
    Allocate a page with protect, then run access against it, its address in rax,
    under a vectored handler. Return the run, the page, and the handler's record.
    before is a protection and an access to run first.
    """
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x2000, arch="amd64")
        data = se.mem_alloc(0x1000)
        handler = code + 0x1000
        se.mem_write(handler, vectored_handler(data, step))
        page = data + 0x100
        setup = guest_call(
            8,
            get_api(se, "kernel32", "VirtualAlloc"),
            0,
            0x1000,
            MEM_COMMIT_RESERVE,
            PAGE_EXECUTE_READWRITE,
            store=page,
        )
        setup += b"\x48\xa1" + struct.pack("<Q", page) + b"\xc6\x00\xc3"  # mov rax, [page]; mov byte [rax], ret
        protect_page = partial(guest_call, 8, get_api(se, "kernel32", "VirtualProtect"), Deref(page), 0x1000)
        if before:
            protect_first, access_first = before
            setup += protect_page(protect_first, data + 0x108)
            setup += b"\x48\xa1" + struct.pack("<Q", page) + access_first  # mov rax, [page]
        setup += protect_page(protect, data + 0x108)
        setup += guest_call(8, get_api(se, "kernel32", "AddVectoredExceptionHandler"), 1, handler)
        setup += b"\x48\xa1" + struct.pack("<Q", page)  # mov rax, [page]
        se.mem_write(code, setup + access + RETURN_42)

        se.run_shellcode(code)

        address = struct.unpack("<Q", se.mem_read(page, 8))[0]
        record = struct.unpack("<IxxxxQQQ", se.mem_read(data, 32))
        return se.get_report().entry_points[0], address, record


def test_guard_page_raises_once_on_execute(config):
    # call rax twice: the first fetch hits the guard, the handler retries it, the second call just runs
    run, page, record = run_with_page(config, PAGE_EXECUTE_READWRITE | PAGE_GUARD, b"\xff\xd0\xff\xd0")
    assert run.error is None
    assert run.ret_val == 42
    assert record == (STATUS_GUARD_PAGE_VIOLATION, page, 8, page)
    assert [e.exception_code for e in run.events or [] if e.event == "exception"] == ["0x80000001"]


def test_guard_page_raises_on_execute_of_code_that_ran(config):
    before = (PAGE_EXECUTE_READ, b"\xff\xd0")  # call rax
    run, page, record = run_with_page(config, PAGE_EXECUTE_READ | PAGE_GUARD, b"\xff\xd0\xff\xd0", before=before)
    assert run.error is None
    assert record == (STATUS_GUARD_PAGE_VIOLATION, page, 8, page)


def test_guard_page_raises_on_read_of_memory_read_before(config):
    before = (PAGE_READONLY, b"\x8a\x00")  # mov al, [rax]
    run, page, record = run_with_page(config, PAGE_READONLY | PAGE_GUARD, b"\x8a\x00", before=before)
    assert run.error is None
    assert record[0] == STATUS_GUARD_PAGE_VIOLATION
    assert record[2:] == (0, page)


@pytest.mark.parametrize(
    "protect, access, step, access_code",
    [
        (PAGE_NOACCESS, b"\x8a\x08", 2, 0),  # mov cl, [rax]
        (PAGE_READONLY, b"\xc6\x00\x00", 3, 1),  # mov byte [rax], 0
    ],
    ids=["read of no-access page", "write to read-only page"],
)
def test_protection_fault_is_access_violation(config, protect, access, step, access_code):
    run, page, record = run_with_page(config, protect, access, step=step)  # the handler skips the access
    assert run.error is None
    assert run.ret_val == 42
    assert record[0] == STATUS_ACCESS_VIOLATION
    assert record[2:] == (access_code, page)


def test_virtual_query_shows_guard(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        data = se.mem_alloc(0x1000)
        page, old, mbi = data, data + 8, data + 0x40
        call = lambda name, *args, **kw: guest_call(8, get_api(se, "kernel32", name), *args, **kw)  # noqa: E731
        body = call("VirtualAlloc", 0, 0x1000, MEM_COMMIT_RESERVE, PAGE_READONLY, store=page)
        body += call("VirtualProtect", Deref(page), 0x1000, PAGE_READONLY | PAGE_GUARD, old)
        body += call("VirtualQuery", Deref(page), mbi, 48)
        se.mem_write(code, body + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        (protect,) = struct.unpack("<I", se.mem_read(mbi + 36, 4))
        assert run.error is None
        assert protect == PAGE_READONLY | PAGE_GUARD


def test_api_fault_without_handler_keeps_its_error(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        data = se.mem_alloc(0x1000)
        body = guest_call(8, get_api(se, "kernel32", "RtlMoveMemory"), data, 0x10, 4)
        se.mem_write(code, body + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert run.error.type == "invalid_read"
        assert [e.api_name for e in run.events or [] if e.event == "api"] == ["kernel32.RtlMoveMemory"]


def test_api_fault_reports_the_first_unmapped_byte(config, load_test_bin):
    """
    0fcf7079 (x64 DLL) exports CHwDataEvent::operator=(const CHwDataEvent &), which calls
    memcpy(this, other, 0xa118). The export run passes the placeholder argument pages at
    0x41420000 and 0x41421000, and the four placeholder pages end at 0x41424000, so memcpy
    reads from mapped memory into unmapped memory.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(MEMCPY_PAST_ARGS))
        se.run_module(module, all_entrypoints=True)
        run = next(
            ep for ep in se.get_report().entry_points if ep.ep_type == "export.??4CHwDataEvent@@QEAAAEAU0@AEBU0@@Z"
        )
        first_unmapped = se.get_address_map(0x41424000)

    assert [e.api_name for e in run.events or [] if e.event == "api"] == ["msvcrt.memcpy"]
    assert run.error is not None
    assert (run.error.type, run.error.address) == ("invalid_read", 0x41424000)
    assert run.error.address_region is None
    assert first_unmapped is None


def test_exception_continued_with_nt_continue_can_repeat(config):
    # for (ecx = 6; ecx; ecx--) int3;  under a handler that skips the int3 with NtContinue
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x2000, arch="amd64")
        handler = code + 0x1000
        nt_continue = get_api(se, "ntdll", "NtContinue")
        se.mem_write(
            handler,
            b"\x48\x8b\x49\x08"  # mov rcx, [rcx + 8]  (ContextRecord)
            + b"\x48\xff\x81\xf8\x00\x00\x00"  # inc qword [rcx + Rip]
            + b"\x31\xd2\x48\x83\xec\x28"  # xor edx, edx; sub rsp, 0x28
            + b"\x48\xb8"
            + struct.pack("<Q", nt_continue)
            + b"\xff\xd0",  # call NtContinue
        )
        setup = guest_call(8, get_api(se, "kernel32", "AddVectoredExceptionHandler"), 1, handler)
        loop = b"\xb9\x06\x00\x00\x00\xcc\xff\xc9\x75\xfb"  # mov ecx, 6; int3; dec ecx; jnz int3
        se.mem_write(code, setup + loop + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 42
        assert len([e for e in run.events or [] if e.event == "exception"]) == 6


def test_contributory_exception_can_repeat(config, load_test_bin):
    """
    0260bad6 (x86): the SEH handler at 0x4115a0 of the far call at 0x40f231 runs the far jump
    ljmp 0x368a:0x3798c3bf at 0x4115a7, under the same handler. Each general protection
    fault is a new access violation, not a double fault after the first.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(GP_FAULT_LOOP))
        se.run_module(module)
        run = module_entry(se)

    faults = [(e.exception_code, e.pos.pc) for e in run.events or [] if e.event == "exception"][:3]
    assert [code for code, _ in faults] == [hex(STATUS_ACCESS_VIOLATION)] * 3
    assert [pc for _, pc in faults] == [0x40F231, 0x4115A7, 0x4115A7]


def test_engine_stop_without_a_cause_ends_the_run_with_an_error(config):
    # A triple fault stops Unicorn like this: no hook records why.
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\x90\x90" + RETURN_42, arch="amd64")
        se.add_code_hook(lambda emu, address, size: se.emu.emu_eng.stop(), begin=code + 1, end=code + 1)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert (run.error.type, run.error.pc) == ("engine_stopped", code + 1)


def test_invalid_instruction_without_handler_dispatch_ends_the_run(config):
    config["exceptions"]["dispatch_handlers"] = False
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\x90\x0f\x0b" + RETURN_42, arch="x86")  # nop; ud2

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert (run.error.type, run.error.pc) == ("Invalid instruction (UC_ERR_INSN_INVALID)", code + 1)


def test_hlt_byte_ending_an_instruction_is_not_hlt(config):
    # mov al, 0xf4 stopped by the instruction limit right after it
    config.update(max_instructions=1)
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xb0\xf4" + RETURN_42, arch="amd64")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert run.error.type == "max_instructions"


def test_guard_on_commit_of_part_of_a_reservation(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        data = se.mem_alloc(0x1000)
        page = data

        def call(name, *args, **kw):
            return guest_call(8, get_api(se, "kernel32", name), *args, **kw)

        body = call("VirtualAlloc", 0, 0x1000, 0x2000, PAGE_READONLY, store=page)  # MEM_RESERVE
        body += call("VirtualAlloc", Deref(page), 0x10, 0x1000, PAGE_READONLY | PAGE_GUARD)  # MEM_COMMIT
        body += b"\x48\xa1" + struct.pack("<Q", page) + b"\x8a\x00"  # read the page: guarded as a whole
        se.mem_write(code, body + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert run.error.type == "guard_page_violation"


def test_generator_handler_fault_ends_the_run_where_it_reads(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        record = 0xDEAD0000
        se.mem_write(code, guest_call(8, get_api(se, "ntdll", "RtlUnwindEx"), 0, 0, record, 0, 0, 0) + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert (run.error.type, run.error.address) == ("invalid_read", record)


def test_vectored_handler_added_first_runs_first(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x2000, arch="amd64")
        data = se.mem_alloc(0x1000)
        setup = b""
        for number, first in ((1, 0), (2, 1)):
            handler = code + 0x1000 + 0x40 * number
            se.mem_write(
                handler,
                b"\xc7\x04\x25"
                + struct.pack("<II", data, number)  # mov dword [data], number
                + b"\x48\x8b\x41\x08\x48\xff\x80\xf8\x00\x00\x00"  # inc qword [ContextRecord->Rip]
                + b"\xb8\xff\xff\xff\xff\xc3",  # return EXCEPTION_CONTINUE_EXECUTION
            )
            setup += guest_call(8, get_api(se, "kernel32", "AddVectoredExceptionHandler"), first, handler)
        se.mem_write(code, setup + b"\xcc" + RETURN_42)

        se.run_shellcode(code)

        assert se.get_report().entry_points[0].ret_val == 42
        assert struct.unpack("<I", se.mem_read(data, 4))[0] == 2


def test_run_after_a_fastfail_runs_once(config, load_test_bin):
    """
    0ee3d870 (x64 DLL): the CRT start-up in DllMain ends with __fastfail(7), int 0x29 at
    0x180085acb. The next run is the export RdvServiceMain, a loader that calls
    VirtualAlloc with the SizeOfImage of the PE image at its first argument. The zero
    placeholder argument gives a size of 0, VirtualAlloc returns NULL, and the loader reads
    NULL + 0xc at 0x180012276.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(FASTFAIL_IN_DLL_MAIN))
        se.run_module(module, all_entrypoints=True)
        dll_main, export = se.get_report().entry_points[:2]

    assert dll_main.ep_type == "dll_entry.DLL_PROCESS_ATTACH"
    assert (dll_main.error.type, dll_main.error.interrupt_num) == ("unhandled_interrupt", 0x29)
    assert export.ep_type == "export.?RdvServiceMain@@YAXPEAX0K0K@Z"
    assert [e.api_name for e in export.events or [] if e.event == "api"] == ["kernel32.VirtualAlloc"]
    assert (export.error.type, export.error.pc, export.error.address) == ("invalid_read", module.base + 0x12276, 0xC)
