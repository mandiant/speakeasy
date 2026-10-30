import copy
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows.windows import ERROR_RESOURCE_TYPE_NOT_FOUND
from tests.handler_harness import alloc, call, load_emu

MPSIGSTUB = "012740784079e4bdc9f48d28d3156031626889c12d58ed0ecd84d04cd6b29342.exe.xz"
VS_FFI_SIGNATURE = 0xFEEF04BD
FILE_VERSION = (1, 461, 119, 0)
INSTALLED_STUB = "C:\\Windows\\system32\\MpSigStub.exe"


@dataclass
class VersionRun:
    module_path: str
    calls: list[tuple[str, str, str]] = field(default_factory=list)
    roots: list[tuple[int, bytes]] = field(default_factory=list)


@pytest.fixture(scope="module")
def mpsigstub_run(base_config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> VersionRun:
    """
    Run 01274078, with a copy of it at the path where it looks for the installed
    MpSigStub.exe. Record the version calls that name a file, and the size and the
    first 16 bytes of each value that VerQueryValueW returns.
    """
    data = load_test_bin(MPSIGSTUB)
    with Speakeasy(config=copy.deepcopy(base_config)) as se:
        module = se.load_module(data=data)
        se.emu.get_file_manager().add_existing_file(INSTALLED_STUB, data)
        run = VersionRun(se.emu.modules[0].emu_path)

        def query(emu, api, original, args):
            result = original(args)
            pointer = int.from_bytes(emu.mem_read(args[2], 8), "little")
            (length,) = struct.unpack("<I", emu.mem_read(args[3], 4))
            run.roots.append((length, bytes(emu.mem_read(pointer, 16))))
            return result

        se.add_api_hook(query, "version", "VerQueryValueW", argc=4)
        se.run_module(module)
        events = se.get_report().entry_points[0].events or []

    for event in events:
        if event.event == "api" and event.api_name.startswith("version.GetFileVersionInfo"):
            path = event.args[1].display
            if path:
                run.calls.append((event.api_name, path, event.ret_val))
    return run


@pytest.fixture(scope="module")
def mpsigstub(base_config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_emu(copy.deepcopy(base_config), load_test_bin(MPSIGSTUB))


def module_path(se: Speakeasy) -> str:
    path: str = se.emu.modules[0].emu_path
    return path


def get_version_info(se: Speakeasy, name: str, wide: bool) -> int:
    suffix = "W" if wide else "A"
    path = alloc(se, (name + "\0").encode("utf-16le" if wide else "latin-1"))
    handle = alloc(se, b"\xff" * 4)
    size, _ = call(se, "version", "GetFileVersionInfoSizeEx" + suffix, [0, path, handle])
    assert size
    assert se.mem_read(handle, 4) == b"\0" * 4
    block = alloc(se, b"\0" * size)
    assert call(se, "version", "GetFileVersionInfoEx" + suffix, [0, path, 0, size, block])[0] == 1
    return block


def query_value(se: Speakeasy, block: int, sub_block: str, wide: bool) -> tuple[int, int]:
    suffix = "W" if wide else "A"
    query = alloc(se, (sub_block + "\0").encode("utf-16le" if wide else "latin-1"))
    pointer = alloc(se, b"\0" * 8)
    length = alloc(se, b"\0" * 4)
    assert call(se, "version", "VerQueryValue" + suffix, [block, query, pointer, length])[0] == 1
    (value_length,) = struct.unpack("<I", se.mem_read(length, 4))
    (value,) = struct.unpack("<Q", se.mem_read(pointer, 8))
    return value_length, value


def file_version(fixed_file_info: bytes) -> tuple[int, int, int, int]:
    signature, _, ms, ls = struct.unpack("<4I", fixed_file_info)
    assert signature == VS_FFI_SIGNATURE
    return ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF


def test_query_root_returns_the_fixed_file_info(mpsigstub_run: VersionRun) -> None:
    """
    01274078 is MpSigStub, the Microsoft Defender update stub. It reads the version of its
    own image: GetFileVersionInfoSizeExW and GetFileVersionInfoExW on the path from
    GetModuleFileNameW, then VerQueryValueW(block, "\\") for the VS_FIXEDFILEINFO.
    """
    own = [(api, ok) for api, path, ok in mpsigstub_run.calls if path == mpsigstub_run.module_path]
    assert own[:2] == [("version.GetFileVersionInfoSizeExW", "0xc1c"), ("version.GetFileVersionInfoExW", "0x1")]
    length, fixed_file_info = mpsigstub_run.roots[0]
    assert length == 52
    assert file_version(fixed_file_info) == FILE_VERSION


@pytest.mark.parametrize("wide", [False, True])
def test_query_translation_returns_the_language_and_code_page(mpsigstub: Speakeasy, wide: bool) -> None:
    """
    The VarFileInfo of 01274078 gives US English (0x409) and Unicode (code page 1200).
    """
    block = get_version_info(mpsigstub, module_path(mpsigstub), wide)
    length, value = query_value(mpsigstub, block, "\\VarFileInfo\\Translation", wide)
    assert length == 4
    assert mpsigstub.mem_read(value, 4) == struct.pack("<HH", 0x409, 1200)


@pytest.mark.parametrize("wide", [False, True])
def test_query_string_returns_the_text_in_the_call_width(mpsigstub: Speakeasy, wide: bool) -> None:
    """
    The string table 040904b0 of 01274078 has CompanyName "Microsoft Corporation". The
    query uses upper case hex digits, which match without regard to case.
    """
    block = get_version_info(mpsigstub, module_path(mpsigstub), wide)
    length, value = query_value(mpsigstub, block, "\\StringFileInfo\\040904B0\\CompanyName", wide)
    expected = "Microsoft Corporation\0".encode("utf-16le" if wide else "latin-1")
    assert length == 22
    assert mpsigstub.mem_read(value, len(expected)) == expected


def test_the_module_matches_by_file_name(mpsigstub: Speakeasy) -> None:
    name = module_path(mpsigstub).rsplit("\\", 1)[1]
    block = get_version_info(mpsigstub, name.upper(), True)
    length, value = query_value(mpsigstub, block, "\\", True)
    assert length == 52
    assert file_version(bytes(mpsigstub.mem_read(value, 16))) == FILE_VERSION


def test_an_emulated_file_has_its_version_resource(mpsigstub_run: VersionRun) -> None:
    """
    After its own version, 01274078 reads the version of the installed
    C:\\Windows\\system32\\MpSigStub.exe. That path holds a copy of the sample in the
    emulated file system, so the query gives the same VS_FIXEDFILEINFO.
    """
    installed = [(api, ok) for api, path, ok in mpsigstub_run.calls if path == INSTALLED_STUB]
    assert installed == [("version.GetFileVersionInfoSizeExW", "0xc1c"), ("version.GetFileVersionInfoExW", "0x1")]
    length, fixed_file_info = mpsigstub_run.roots[-1]
    assert length == 52
    assert file_version(fixed_file_info) == FILE_VERSION


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
