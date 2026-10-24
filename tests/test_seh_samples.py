"""
Exception-based checks of real samples, each run from the code that sets it up, with
the result Windows gives.

al-khaser (https://github.com/LordNoteworthy/al-khaser) is an open-source suite of
anti-analysis checks; its binaries are builds of the project's CI. The other samples
are malware from VirusTotal, named by SHA-256.
"""

import struct

import pytest

from speakeasy import Speakeasy

STATUS_GUARD_PAGE_VIOLATION = "0x80000001"
STATUS_BREAKPOINT = "0x80000003"
STATUS_SINGLE_STEP = "0x80000004"
STATUS_PRIVILEGED_INSTRUCTION = "0xc0000096"

TROJAN_DISCO = "6957854f43a95f86dee1d3464d65e5f0e1ad5aea41cf9128b63d3b3f72c289f7.exe.xz"
AMSI_BYPASS = "87173c223a4d16a770de86b9599707b681d4b2752b8aac7990bad53c4249af9f.exe.xz"
KHALESI = "4b60f76584ccf31f0abb050c69d5bc975356792c2235b4e7b313455d89aa6297.exe.xz"


def exceptions(run):
    return [e.exception_code for e in run.events or [] if e.event == "exception"]


def module_entry(se):
    return next(e for e in se.get_report().entry_points if e.ep_type == "module_entry")


def run_span(se, module, start, stop):
    """Run the module from RVA start until RVA stop."""

    def stop_here(emu, address, size):
        se.stop()

    se.add_code_hook(stop_here, begin=module.base + stop, end=module.base + stop)
    se.run_module(module, entry_point=start)
    return module_entry(se)


def read_u32(se, address):
    return struct.unpack("<I", se.mem_read(address, 4))[0]


@pytest.mark.parametrize("arch, check", [("x64", 0x9250), ("x86", 0xAC20)])
def test_al_khaser_page_guard(config, load_test_bin, arch, check):
    """
    MemoryBreakpoints_PageGuard calls into a PAGE_GUARD page under __try, and reports a
    debugger unless the guard page violation reaches the __except block: through
    __GSHandlerCheck_SEH and __C_specific_handler on x64, an SEH4 frame on x86.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(f"al-khaser_{arch}.exe.xz"))
        se.run_module(module, entry_point=check)
        run = module_entry(se)

    assert run.error is None
    assert run.ret_val == 0  # FALSE: no debugger
    assert exceptions(run) == [STATUS_GUARD_PAGE_VIOLATION]


def test_al_khaser_int_2d(config, load_test_bin):
    """
    Interrupt_0x2d (x86): under a vectored handler that clears the "debugger" flag and
    continues on STATUS_BREAKPOINT, which a debugger would swallow.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin("al-khaser_x86.exe.xz"))
        run = run_span(se, module, 0x2F82, 0x2FA9)  # AddVectoredExceptionHandler .. RemoveVectoredExceptionHandler
        detected = read_u32(se, module.base + 0x3E1A8)

    assert run.error is None
    assert exceptions(run) == [STATUS_BREAKPOINT]
    assert detected == 0


def test_al_khaser_unhandled_exception_filter(config, load_test_bin):
    """
    UnhandledExcepFilterTest (x86): RaiseException with no frame handler, so that the
    filter of SetUnhandledExceptionFilter clears the "debugger" flag and continues, which
    it does not under a debugger.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin("al-khaser_x86.exe.xz"))
        flag = module.base + 0x2A92C
        se.mem_write(flag, struct.pack("<I", 1))
        run = run_span(se, module, 0x2D34, 0x2D57)  # SetUnhandledExceptionFilter .. restore the filter
        detected = read_u32(se, flag)

    assert run.error is None
    assert exceptions(run) == ["0xc000008e"]  # EXCEPTION_FLT_DIVIDE_BY_ZERO
    assert detected == 0


def test_raise_exception_anti_emulation(config, load_test_bin):
    """
    trojan.disco (x64): a function that raises 0x40010006 under __try and returns the
    code from the __except block; an emulator without x64 SEH never gets there.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(TROJAN_DISCO))
        se.run_module(module, entry_point=0x22B0)
        run = module_entry(se)

    assert run.error is None
    assert run.ret_val == 0x40010006
    assert exceptions(run) == ["0x40010006"]


def test_vmware_backdoor_under_vectored_handler(config, load_test_bin):
    """
    trojan.khalesi (x64): the VMware backdoor `in eax, dx` under a vectored handler. In user
    mode it is a privileged instruction, and the handler marks that it ran (2) and skips it.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(KHALESI))
        run = run_span(se, module, 0x23F0, 0x2444)  # AddVectoredExceptionHandler .. RemoveVectoredExceptionHandler
        handled = read_u32(se, module.base + 0x401A088)

    assert run.error is None
    assert exceptions(run) == [STATUS_PRIVILEGED_INSTRUCTION]
    assert handled == 2


def test_amsi_bypass_with_hardware_breakpoint(config, load_test_bin):
    """
    A patchless AMSI bypass (x64): its setup sets Dr0 on AmsiScanBuffer with
    Get/SetThreadContext, under a vectored handler that answers the breakpoint by
    returning S_OK with AMSI_RESULT_CLEAN instead of running the function.

    The setup is the middle of a function that first reads a file named on the command
    line, so the run enters it with a stack frame of its own, and calls AmsiScanBuffer
    once it is done.
    """
    config["modules"]["functions_always_exist"] = True
    config["modules"]["modules_always_exist"] = True
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(AMSI_BYPASS))
        code = se.mem_alloc(0x2000)
        data = code + 0x1000
        result, status = data + 8, data + 16
        amsi_scan_buffer = module.base + 0x5100  # the sample's pointer to it

        enter = b"\x48\x81\xec\x00\x08\x00\x00"  # sub rsp, 0x800
        enter += b"\x48\x8d\xac\x24\x00\x01\x00\x00"  # lea rbp, [rsp + 0x100]
        enter += b"\x48\xb8" + struct.pack("<Q", module.base + 0x1B86) + b"\xff\xe0"  # jmp setup
        # AmsiScanBuffer(NULL, data, 4, NULL, NULL, &result)
        scan = b"\x48\x83\xe4\xf0\x48\x83\xec\x40"  # and rsp, -16; sub rsp, 0x40
        scan += b"\x31\xc9\x48\xba" + struct.pack("<Q", data)  # xor ecx, ecx; mov rdx, data
        scan += b"\x41\xb8\x04\x00\x00\x00\x45\x31\xc9"  # mov r8d, 4; xor r9d, r9d
        scan += b"\x48\xc7\x44\x24\x20\x00\x00\x00\x00"  # mov qword [rsp + 0x20], 0
        scan += b"\x48\xb8" + struct.pack("<Q", result) + b"\x48\x89\x44\x24\x28"  # mov [rsp + 0x28], &result
        scan += b"\x48\xa1" + struct.pack("<Q", amsi_scan_buffer) + b"\xff\xd0"  # call [AmsiScanBuffer]
        scan += b"\x48\xa3" + struct.pack("<Q", status)  # mov [status], rax
        se.mem_write(code, enter)
        se.mem_write(code + 0x100, scan)
        se.mem_write(result, struct.pack("<I", 0x7777))  # not yet written
        se.mem_write(status, struct.pack("<Q", 0x7777))

        def scan_after_setup(emu, address, size):
            emu.set_pc(code + 0x100)

        def stop(emu, address, size):
            se.stop()

        se.add_code_hook(scan_after_setup, begin=module.base + 0x1CDE, end=module.base + 0x1CDE)
        se.add_code_hook(stop, begin=code + 0x100 + len(scan), end=code + 0x100 + len(scan))
        se.run_module(module, entry_point=code - module.base)
        run = module_entry(se)
        scanned = read_u32(se, result), struct.unpack("<Q", se.mem_read(status, 8))[0]

    assert run.error is None
    assert exceptions(run) == [STATUS_SINGLE_STEP]
    assert scanned == (0, 0)  # AMSI_RESULT_CLEAN, S_OK
