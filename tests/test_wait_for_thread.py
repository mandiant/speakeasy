"""A wait on a thread that has not started runs the thread to its end before the wait returns, as on Windows."""

import struct

import pytest

from speakeasy import Speakeasy
from tests.pe_builder import build_pe

G = 0x2000
EXIT_CODE = 0x2004
HANDLES = 0x2008
IMPORTS = {
    "kernel32.dll": [
        "CreateThread",
        "WaitForSingleObject",
        "WaitForSingleObjectEx",
        "WaitForMultipleObjects",
        "GetExitCodeThread",
        "GetCurrentThreadId",
        "ExitThread",
    ]
}


class Code:
    """Machine code at the start of .text, with operands that give data and IAT slots by RVA."""

    def __init__(self, arch, base, iat):
        self.arch, self.base, self.iat = arch, base, iat
        self.text = bytearray()

    def emit(self, opcode, target=None, imm=b""):
        """
        Add an instruction: opcode, the address of target, then the immediate operand imm.

        target is an RVA. The address is absolute on x86 and RIP-relative on x64.
        """
        self.text += opcode
        if target is not None:
            if self.arch == 32:
                self.text += struct.pack("<I", self.base + target)
            else:
                self.text += struct.pack("<i", target - (0x1000 + len(self.text) + 4 + len(imm)))
        self.text += imm

    def call(self, name):
        self.emit(b"\xff\x15", self.iat["kernel32.dll", name])


def emit_wait(code, wait):
    """Wait with an INFINITE timeout for the thread handle at HANDLES."""
    if code.arch == 32:
        if wait == "WaitForMultipleObjects":
            code.emit(b"\x6a\xff\x6a\x01")  # push INFINITE; push TRUE
            code.emit(b"\x68", HANDLES)  # push HANDLES
            code.emit(b"\x6a\x01")  # push 1
        else:
            if wait == "WaitForSingleObjectEx":
                code.emit(b"\x6a\x00")
            code.emit(b"\x6a\xff")  # push INFINITE
            code.emit(b"\xff\x35", HANDLES)  # push [HANDLES]
    elif wait == "WaitForMultipleObjects":
        code.emit(b"\xb9\x01\0\0\0")  # mov ecx, 1
        code.emit(b"\x48\x8d\x15", HANDLES)  # lea rdx, [HANDLES]
        code.emit(b"\x41\xb8\x01\0\0\0\x41\xb9\xff\xff\xff\xff")  # mov r8d, TRUE; mov r9d, INFINITE
    else:
        code.emit(b"\x48\x8b\x0d", HANDLES)  # mov rcx, [HANDLES]
        code.emit(b"\xba\xff\xff\xff\xff\x45\x31\xc0")  # mov edx, INFINITE; xor r8d, r8d
    code.call(wait)


def emit_main(code, wait, worker):
    """CreateThread(worker), wait for it, then return [G] + the exit code + the thread ID in the TEB."""
    if code.arch == 32:
        code.emit(b"\x6a\x00" * 3)  # push 0; push 0; push 0
        code.emit(b"\x68", worker)  # push worker
        code.emit(b"\x6a\x00" * 2)  # push 0; push 0
        code.call("CreateThread")
        code.emit(b"\xa3", HANDLES)  # mov [HANDLES], eax
        emit_wait(code, wait)
        code.emit(b"\x68", EXIT_CODE)  # push EXIT_CODE
        code.emit(b"\xff\x35", HANDLES)  # push [HANDLES]
        code.call("GetExitCodeThread")
        code.emit(b"\xa1", G)  # mov eax, [G]
        code.emit(b"\x03\x05", EXIT_CODE)  # add eax, [EXIT_CODE]
        code.emit(b"\x64\x03\x05\x24\0\0\0\xc3")  # add eax, fs:[0x24]; ret
        return
    # sub rsp, 0x38; xor ecx, ecx; xor edx, edx; lea r8, [worker]
    code.emit(b"\x48\x83\xec\x38\x31\xc9\x31\xd2\x4c\x8d\x05", worker)
    # xor r9d, r9d; mov qword [rsp + 0x20], 0; mov qword [rsp + 0x28], 0
    code.emit(b"\x45\x31\xc9\x48\xc7\x44\x24\x20\0\0\0\0\x48\xc7\x44\x24\x28\0\0\0\0")
    code.call("CreateThread")
    code.emit(b"\x48\x89\x05", HANDLES)  # mov [HANDLES], rax
    emit_wait(code, wait)
    code.emit(b"\x48\x8b\x0d", HANDLES)  # mov rcx, [HANDLES]
    code.emit(b"\x48\x8d\x15", EXIT_CODE)  # lea rdx, [EXIT_CODE]
    code.call("GetExitCodeThread")
    code.emit(b"\x8b\x05", G)  # mov eax, [G]
    code.emit(b"\x03\x05", EXIT_CODE)  # add eax, [EXIT_CODE]
    code.emit(b"\x65\x03\x04\x25\x48\0\0\0")  # add eax, gs:[0x48]
    code.emit(b"\x48\x83\xc4\x38\xc3")  # add rsp, 0x38; ret


def emit_worker(code, exit_thread):
    """Call GetCurrentThreadId, set [G] to 0x1234, then return 7 or call ExitThread(5)."""
    if code.arch == 64:
        code.emit(b"\x48\x83\xec\x28")  # sub rsp, 0x28
    code.call("GetCurrentThreadId")
    code.emit(b"\xc7\x05", G, b"\x34\x12\0\0")  # mov dword [G], 0x1234
    if exit_thread:
        code.emit(b"\x6a\x05" if code.arch == 32 else b"\xb9\x05\0\0\0")  # push 5 / mov ecx, 5
        code.call("ExitThread")
    elif code.arch == 32:
        code.emit(b"\xb8\x07\0\0\0\xc2\x04\x00")  # mov eax, 7; ret 4
    else:
        code.emit(b"\xb8\x07\0\0\0\x48\x83\xc4\x28\xc3")  # mov eax, 7; add rsp, 0x28; ret


def build(arch, wait, exit_thread=False):
    def text(base, iat):
        size = Code(arch, base, iat)
        emit_main(size, wait, 0x1000)
        code = Code(arch, base, iat)
        emit_main(code, wait, 0x1000 + len(size.text))
        emit_worker(code, exit_thread)
        return bytes(code.text)

    data, _ = build_pe(arch, text=text, data=b"\0" * 0x10, imports=IMPORTS)
    return data


def run_exe(config, data):
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=data))
        return se.get_report().entry_points


def get_api_events(entry):
    return [event for event in entry.events if event.event == "api"]


@pytest.mark.parametrize("arch", [32, 64])
@pytest.mark.parametrize("wait", ["WaitForSingleObject", "WaitForSingleObjectEx", "WaitForMultipleObjects"])
def test_wait_runs_the_thread_before_it_returns(config, arch, wait):
    (main,) = run_exe(config, build(arch, wait))

    assert main.error is None
    assert main.return_value == 0x1234 + 7 + main.tid
    events = get_api_events(main)
    assert [event.api_name for event in events] == [
        "kernel32.CreateThread",
        f"kernel32.{wait}",
        "kernel32.GetCurrentThreadId",
        "kernel32.GetExitCodeThread",
    ]
    create, wait_event, thread_id, exit_code = events
    assert wait_event.return_value == 0
    assert thread_id.pos.tid == thread_id.return_value != main.tid
    assert create.pos.tid == wait_event.pos.tid == exit_code.pos.tid == main.tid


@pytest.mark.parametrize("arch", [32, 64])
def test_exit_thread_in_a_waited_thread_continues_the_wait(config, arch):
    (main,) = run_exe(config, build(arch, "WaitForSingleObject", exit_thread=True))

    assert main.error is None
    assert main.return_value == 0x1234 + 5 + main.tid
    assert [event.api_name for event in get_api_events(main)] == [
        "kernel32.CreateThread",
        "kernel32.WaitForSingleObject",
        "kernel32.GetCurrentThreadId",
        "kernel32.ExitThread",
        "kernel32.GetExitCodeThread",
    ]
