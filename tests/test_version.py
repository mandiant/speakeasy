import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.usermode.version import Version
from speakeasy.winenv.defs.windows.windows import ERROR_RESOURCE_TYPE_NOT_FOUND


class Memory:
    def __init__(self):
        self.writes = {}
        self.error = None

    def mem_write(self, address, data):
        self.writes[address] = data

    def set_last_error(self, value):
        self.error = value


@pytest.mark.parametrize(
    "func, argv, handle",
    [
        (Version.GetFileVersionInfoSize, [8, 16], 16),
        (Version.GetFileVersionInfoSizeEx, [0, 8, 16], 16),
    ],
)
def test_size_reports_no_resource_and_zeroes_handle(func, argv, handle):
    memory = Memory()
    assert func(memory, memory, argv) == 0
    assert memory.writes == {handle: b"\0\0\0\0"}
    assert memory.error == ERROR_RESOURCE_TYPE_NOT_FOUND


def test_size_accepts_null_handle():
    memory = Memory()
    assert Version.GetFileVersionInfoSize(memory, memory, [8, 0]) == 0
    assert not memory.writes
    assert memory.error == ERROR_RESOURCE_TYPE_NOT_FOUND


@pytest.mark.parametrize(
    "func, argv",
    [
        (Version.GetFileVersionInfo, [8, 0, 64, 16]),
        (Version.GetFileVersionInfoEx, [0, 8, 0, 64, 16]),
    ],
)
def test_info_fails_without_touching_the_buffer(func, argv):
    memory = Memory()
    assert func(memory, memory, argv) == 0
    assert not memory.writes
    assert memory.error == ERROR_RESOURCE_TYPE_NOT_FOUND


def test_query_value_finds_nothing_and_leaves_outputs_untouched():
    memory = Memory()
    assert Version.VerQueryValue(memory, memory, [8, 16, 24, 32]) == 0
    assert not memory.writes


def _x86_blob():
    """GetFileVersionInfoSizeA(name, &handle), then VerQueryValueA(0, 0, &ptr, &len); ret."""
    code = bytearray(b"\xe8\x00\x00\x00\x00\x5b")  # call $+5; pop ebx
    fixups = []

    def push_address(label):  # lea eax, [ebx+disp32]; push eax
        fixups.append((len(code) + 2, label))
        code.extend(b"\x8d\x83\0\0\0\0\x50")

    push_address("handle")
    push_address("name")
    calls = {"GetFileVersionInfoSizeA": len(code) + 1}
    code.extend(b"\xb8\0\0\0\0\xff\xd0")  # mov eax, imm32; call eax
    push_address("length")
    push_address("pointer")
    code.extend(b"\x6a\x00\x6a\x00")
    calls["VerQueryValueA"] = len(code) + 1
    code.extend(b"\xb8\0\0\0\0\xff\xd0\xc3")
    return code, fixups, calls, 4, 5


def _x64_blob():
    """Same calls with the x64 convention and shadow space."""
    code = bytearray(b"\xe8\x00\x00\x00\x00\x5b")  # call $+5; pop rbx
    fixups = []
    calls = {}

    def lea(prefix, label):  # lea reg, [rbx+disp32]
        code.extend(prefix)
        fixups.append((len(code), label))
        code.extend(b"\0\0\0\0")

    def call(name):  # sub rsp, 0x28; mov rax, imm64; call rax; add rsp, 0x28
        code.extend(b"\x48\x83\xec\x28\x48\xb8")
        calls[name] = len(code)
        code.extend(b"\0" * 8 + b"\xff\xd0\x48\x83\xc4\x28")

    lea(b"\x48\x8d\x8b", "name")  # rcx
    lea(b"\x48\x8d\x93", "handle")  # rdx
    call("GetFileVersionInfoSizeA")
    code.extend(b"\x31\xc9\x31\xd2")  # xor ecx, ecx; xor edx, edx
    lea(b"\x4c\x8d\x83", "pointer")  # r8
    lea(b"\x4c\x8d\x8b", "length")  # r9
    call("VerQueryValueA")
    code.extend(b"\xc3")
    return code, fixups, calls, 8, 5


@pytest.mark.parametrize("arch, build", [("x86", _x86_blob), ("x64", _x64_blob)])
def test_handler_takes_precedence_over_signature_fallback(arch, build):
    code, fixups, calls, width, anchor = build()
    labels = {}
    for label, fill in (("handle", b"\xff" * 4), ("pointer", b"\xee" * width), ("length", b"\xdd" * 4)):
        labels[label] = len(code)
        code.extend(fill)
    labels["name"] = len(code)
    code.extend(b"C:\\Windows\\system32\\kernel32.dll\0")
    for offset, label in fixups:
        code[offset : offset + 4] = struct.pack("<i", labels[label] - anchor)

    se = Speakeasy()
    base = se.load_shellcode(data=bytes(code), arch=arch)
    emu = se.emu
    for name, offset in calls.items():
        emu.mem_write(base + offset, emu.get_proc("version", name).to_bytes(width, "little"))
    se.run_shellcode(base)

    entry = se.get_report().entry_points[0]
    assert entry.error is None
    results = {event.api_name: event.ret_val for event in entry.events if event.api_name.startswith("version.")}
    assert results == {"version.GetFileVersionInfoSizeA": "0x0", "version.VerQueryValueA": "0x0"}
    assert emu.get_last_error() == ERROR_RESOURCE_TYPE_NOT_FOUND
    assert emu.mem_read(base + labels["handle"], 4) == b"\0" * 4
    assert emu.mem_read(base + labels["pointer"], width) == b"\xee" * width
    assert emu.mem_read(base + labels["length"], 4) == b"\xdd" * 4
