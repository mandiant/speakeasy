import struct
from collections.abc import Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows.windows import ERROR_RESOURCE_TYPE_NOT_FOUND
from tests.handler_harness import alloc, call, load_emu, start_process
from tests.pe_builder import build_pe

RT_VERSION = 16
VS_FFI_SIGNATURE = 0xFEEF04BD
FILE_VERSION = (1, 2, 3, 4)


def version_node(key: str, value: bytes = b"", text: bool = False, children: tuple[bytes, ...] = ()) -> bytes:
    """Encode one VS_VERSIONINFO node. A text value is UTF-16 with a terminating NUL."""
    header_size = 6
    body = (key + "\0").encode("utf-16le")
    node = bytearray(header_size) + body
    node += b"\0" * (-len(node) % 4)
    node += value
    for child in children:
        node += b"\0" * (-len(node) % 4)
        node += child
    value_length = len(value) // 2 if text else len(value)
    struct.pack_into("<HHH", node, 0, len(node), value_length, 1 if text else 0)
    return bytes(node)


def text_node(key: str, value: str) -> bytes:
    return version_node(key, (value + "\0").encode("utf-16le"), text=True)


def version_info() -> bytes:
    major, minor, build, patch = FILE_VERSION
    fixed = struct.pack(
        "<13I",
        VS_FFI_SIGNATURE,
        0x10000,
        major << 16 | minor,
        build << 16 | patch,
        major << 16 | minor,
        build << 16 | patch,
        0x3F,
        0,
        0x40004,
        1,
        0,
        0,
        0,
    )
    strings = version_node(
        "StringFileInfo",
        text=True,
        children=(
            version_node(
                "040904b0",
                text=True,
                children=(text_node("CompanyName", "Acme"), text_node("FileVersion", "1.2.3.4")),
            ),
        ),
    )
    translation = version_node(
        "VarFileInfo", text=True, children=(version_node("Translation", struct.pack("<HH", 0x409, 0x4B0)),)
    )
    return version_node("VS_VERSION_INFO", fixed, children=(strings, translation))


def resource_section(rva: int, payload: bytes) -> bytes:
    """Encode a resource tree with one RT_VERSION entry, ID 1, language 0x409."""
    directory = struct.Struct("<IIHHHH")
    entry = struct.Struct("<II")
    level = directory.size + entry.size
    data_entry = 3 * level
    data = data_entry + 16
    section = bytearray()
    for offset, name in ((level, RT_VERSION), (2 * level, 1), (data_entry, 0x409)):
        section += directory.pack(0, 0, 0, 0, 0, 1)
        section += entry.pack(name, offset | (0x80000000 if offset != data_entry else 0))
    section += struct.pack("<IIII", rva + data, len(payload), 0, 0)
    return bytes(section + payload)


def version_pe() -> bytes:
    rsrc = resource_section(0x2000, version_info())
    data, _ = build_pe(32, text=b"\xc3", data=rsrc, extra_dirs={2: (0x2000, len(rsrc))})
    return data


@pytest.fixture
def emu(dll_emu: Speakeasy) -> Speakeasy:
    start_process(dll_emu)
    return dll_emu


@pytest.fixture
def version_emu(config: dict[str, Any]) -> Iterator[Speakeasy]:
    yield from load_emu(config, version_pe())


def module_path(se: Speakeasy) -> str:
    assert se.emu is not None
    return se.emu.modules[0].emu_path


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


def query_value(se: Speakeasy, block: int, sub_block: str, wide: bool) -> tuple[int, bytes]:
    suffix = "W" if wide else "A"
    query = alloc(se, (sub_block + "\0").encode("utf-16le" if wide else "latin-1"))
    pointer = alloc(se, b"\0" * 4)
    length = alloc(se, b"\0" * 4)
    assert call(se, "version", "VerQueryValue" + suffix, [block, query, pointer, length])[0] == 1
    (value_length,) = struct.unpack("<I", se.mem_read(length, 4))
    (value,) = struct.unpack("<I", se.mem_read(pointer, 4))
    return value_length, value


@pytest.mark.parametrize("wide", [False, True])
def test_query_root_returns_the_fixed_file_info(version_emu: Speakeasy, wide: bool) -> None:
    block = get_version_info(version_emu, module_path(version_emu), wide)
    length, value = query_value(version_emu, block, "\\", wide)
    assert length == 52
    signature, _, ms, ls = struct.unpack("<4I", version_emu.mem_read(value, 16))
    assert signature == VS_FFI_SIGNATURE
    assert (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF) == FILE_VERSION


@pytest.mark.parametrize("wide", [False, True])
def test_query_translation_returns_the_language_and_code_page(version_emu: Speakeasy, wide: bool) -> None:
    block = get_version_info(version_emu, module_path(version_emu), wide)
    length, value = query_value(version_emu, block, "\\VarFileInfo\\Translation", wide)
    assert length == 4
    assert version_emu.mem_read(value, 4) == struct.pack("<HH", 0x409, 0x4B0)


@pytest.mark.parametrize("wide", [False, True])
def test_query_string_returns_the_text_in_the_call_width(version_emu: Speakeasy, wide: bool) -> None:
    block = get_version_info(version_emu, module_path(version_emu), wide)
    length, value = query_value(version_emu, block, "\\StringFileInfo\\040904B0\\CompanyName", wide)
    expected = "Acme\0".encode("utf-16le" if wide else "latin-1")
    assert length == 5
    assert version_emu.mem_read(value, len(expected)) == expected


def test_the_module_matches_by_file_name(version_emu: Speakeasy) -> None:
    name = module_path(version_emu).rsplit("\\", 1)[1]
    block = get_version_info(version_emu, name.upper(), True)
    assert query_value(version_emu, block, "\\", True)[0] == 52


def test_an_emulated_file_has_its_version_resource(emu: Speakeasy) -> None:
    assert emu.emu is not None
    emu.emu.get_file_manager().add_existing_file("C:\\Users\\Public\\dropped.dll", version_pe())
    block = get_version_info(emu, "C:\\Users\\Public\\dropped.dll", False)
    length, value = query_value(emu, block, "\\StringFileInfo\\040904b0\\FileVersion", False)
    assert length == 8
    assert emu.mem_read(value, length) == b"1.2.3.4\0"


def test_query_of_a_missing_value_fails(version_emu: Speakeasy) -> None:
    block = get_version_info(version_emu, module_path(version_emu), True)
    query = alloc(version_emu, "\\StringFileInfo\\040904B0\\Missing\0".encode("utf-16le"))
    pointer = alloc(version_emu, b"\xee" * 4)
    length = alloc(version_emu, b"\xdd" * 4)
    assert call(version_emu, "version", "VerQueryValueW", [block, query, pointer, length])[0] == 0
    assert version_emu.mem_read(pointer, 4) == b"\xee" * 4


@pytest.mark.parametrize("name", ["GetFileVersionInfoSizeA", "GetFileVersionInfoSizeW"])
def test_size_of_a_module_without_a_resource_is_zero(emu: Speakeasy, name: str) -> None:
    cw = "utf-16le" if name.endswith("W") else "latin-1"
    path = alloc(emu, "C:\\Windows\\system32\\kernel32.dll\0".encode(cw))
    handle = alloc(emu, b"\xff" * 4)
    assert call(emu, "version", name, [path, handle])[0] == 0
    assert emu.mem_read(handle, 4) == b"\0" * 4
    assert emu.emu.get_last_error() == ERROR_RESOURCE_TYPE_NOT_FOUND


def test_info_of_a_file_without_a_resource_fails(emu: Speakeasy) -> None:
    path = alloc(emu, b"C:\\missing.dll\0")
    block = alloc(emu, b"\xcc" * 64)
    assert call(emu, "version", "GetFileVersionInfoA", [path, 0, 64, block])[0] == 0
    assert emu.mem_read(block, 64) == b"\xcc" * 64
    assert emu.emu.get_last_error() == ERROR_RESOURCE_TYPE_NOT_FOUND


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
