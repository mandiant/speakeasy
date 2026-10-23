"""x64 CPU exceptions reach guest handlers with the code and addresses Windows reports."""

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
    # mov eax, 'VMXh'; mov dx, 'VX'; in eax, dx
    "vmware backdoor": (b"\xb8\x68\x58\x4d\x56\x66\xba\x58\x56\xed", STATUS_PRIVILEGED_INSTRUCTION, 9, 1),
    "out": (b"\xee", STATUS_PRIVILEGED_INSTRUCTION, 0, 1),
    "divide by zero": (b"\x31\xc9\xf7\xf1", STATUS_INTEGER_DIVIDE_BY_ZERO, 2, 2),
    "read null": (b"\x48\x8b\x04\x25\x00\x00\x00\x00", STATUS_ACCESS_VIOLATION, 0, 8),
    # pushfq; or dword [rsp], 0x100; popfq; nop: the trap follows the nop
    "trap flag": (b"\x9c\x81\x0c\x24\x00\x01\x00\x00\x9d\x90", STATUS_SINGLE_STEP, 10, 0),
}

RETURN_42 = b"\xb8\x2a\x00\x00\x00\xc3"


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


@pytest.mark.parametrize("name", CASES)
def test_cpu_exception_reaches_vectored_handler(config, name):
    insn, exception_code, offset, step = CASES[name]
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x2000, arch="amd64")
        data = se.mem_alloc(0x1000)
        handler = code + 0x1000
        se.mem_write(handler, vectored_handler(data, step))
        setup = guest_call(8, get_api(se, "kernel32", "AddVectoredExceptionHandler"), 1, handler)
        se.mem_write(code, setup + insn + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 42
        assert struct.unpack("<IxxxxQ", se.mem_read(data, 16)) == (exception_code, code + len(setup) + offset)


def test_debug_service_without_exception_skips_a_byte(config):
    # mov eax, 1 (BREAKPOINT_PRINT); int 2d; a byte the kernel skips; mov eax, 42; ret
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xb8\x01\x00\x00\x00\xcd\x2d\xcc" + RETURN_42, arch="amd64")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 42
        assert not [e for e in run.events or [] if e.event == "exception"]


@pytest.mark.parametrize(
    "insn, error",
    [
        (b"\xcc", "unhandled_interrupt"),
        (b"\x0f\x0b", "Invalid instruction (UC_ERR_INSN_INVALID)"),
        (b"\xf4", "privileged_instruction"),
        (b"\xec", "privileged_instruction"),
    ],
)
def test_unhandled_cpu_exception_ends_the_run(config, insn, error):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=insn + RETURN_42, arch="amd64")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert run.error.type == error
        assert run.error.pc == code


MEM_COMMIT_RESERVE = 0x3000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100


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


def test_guard_page_raises_on_read(config):
    run, page, record = run_with_page(config, PAGE_EXECUTE_READWRITE | PAGE_GUARD, b"\x8a\x00")  # mov al, [rax]
    assert run.error is None
    assert record[0] == STATUS_GUARD_PAGE_VIOLATION
    assert record[2:] == (0, page)


def test_read_of_no_access_page_is_access_violation(config):
    # mov cl, [rax], skipped by the handler
    run, page, record = run_with_page(config, PAGE_NOACCESS, b"\x8a\x08", step=2)
    assert run.error is None
    assert run.ret_val == 42
    assert record[0] == STATUS_ACCESS_VIOLATION
    assert record[2:] == (0, page)


def test_write_to_read_only_page_is_access_violation(config):
    # mov byte [rax], 0, skipped by the handler
    run, page, record = run_with_page(config, PAGE_READONLY, b"\xc6\x00\x00", step=3)
    assert run.error is None
    assert run.ret_val == 42
    assert record[0] == STATUS_ACCESS_VIOLATION
    assert record[2:] == (1, page)


def test_guard_shows_in_virtual_query_and_old_protection(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        data = se.mem_alloc(0x1000)
        page, old, mbi = data, data + 8, data + 0x40
        call = lambda name, *args, **kw: guest_call(8, get_api(se, "kernel32", name), *args, **kw)  # noqa: E731
        body = call("VirtualAlloc", 0, 0x1000, MEM_COMMIT_RESERVE, PAGE_READONLY, store=page)
        body += call("VirtualProtect", Deref(page), 0x1000, PAGE_READONLY | PAGE_GUARD, old)
        body += call("VirtualQuery", Deref(page), mbi, 48)
        body += b"\x48\xa1" + struct.pack("<Q", page) + b"\x8a\x00"  # read the page: guard violation, unhandled
        se.mem_write(code, body + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        (protect,) = struct.unpack("<I", se.mem_read(mbi + 36, 4))
        assert protect == PAGE_READONLY | PAGE_GUARD
        assert run.error is not None
        assert run.error.type == "guard_page_violation"
        assert run.error.address == struct.unpack("<Q", se.mem_read(page, 8))[0]


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


def test_handled_exception_can_repeat_at_one_address(config):
    # for (ecx = 6; ecx; ecx--) int3;  under a handler that skips the int3
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x2000, arch="amd64")
        data = se.mem_alloc(0x1000)
        handler = code + 0x1000
        se.mem_write(handler, vectored_handler(data, 1))
        setup = guest_call(8, get_api(se, "kernel32", "AddVectoredExceptionHandler"), 1, handler)
        loop = b"\xb9\x06\x00\x00\x00\xcc\xff\xc9\x75\xfb"  # mov ecx, 6; int3; dec ecx; jnz int3
        se.mem_write(code, setup + loop + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 42
        assert len([e for e in run.events or [] if e.event == "exception"]) == 6


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


def test_hlt_byte_ending_an_instruction_is_not_hlt(config):
    # mov al, 0xf4 stopped by the instruction limit right after it
    config.update(max_instructions=1)
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xb0\xf4" + RETURN_42, arch="amd64")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert run.error.type == "max_instructions"


@pytest.mark.parametrize("size", [0x1000, 0x10])
def test_guard_on_commit_of_a_reservation(config, size):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        data = se.mem_alloc(0x1000)
        page = data

        def call(name, *args, **kw):
            return guest_call(8, get_api(se, "kernel32", name), *args, **kw)

        body = call("VirtualAlloc", 0, 0x1000, 0x2000, PAGE_READONLY, store=page)  # MEM_RESERVE
        body += call("VirtualAlloc", Deref(page), size, 0x1000, PAGE_READONLY | PAGE_GUARD)  # MEM_COMMIT
        body += b"\x48\xa1" + struct.pack("<Q", page) + b"\x8a\x00"  # read the page
        se.mem_write(code, body + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert run.error.type == "guard_page_violation"
