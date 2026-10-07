import struct
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, load_emu


@pytest.fixture
def adapter_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    config["network"]["adapters"] = [
        {
            "name": "{00000000-1111-2222-3333-444444444444}",
            "description": "Intel(R) Ethernet",
            "mac_address": "00-11-22-33-44-55",
            "type": "ethernet",
            "ip_address": "192.168.1.5",
            "subnet_mask": "255.255.255.0",
            "dhcp_enabled": True,
        }
    ]
    yield from load_emu(config, load_test_bin("dll_test_x86.dll.xz"))


def test_get_adapters_info_fills_the_adapter(adapter_emu: Speakeasy) -> None:
    buf = alloc(adapter_emu, b"\xcc" * 0x400)
    size = alloc(adapter_emu, struct.pack("<I", 0x400))
    rv, _ = call(adapter_emu, "iphlpapi", "GetAdaptersInfo", [buf, size])
    assert rv == 0
    info = adapter_emu.mem_read(buf, 0x1D0)
    assert info[8:47] == b"{00000000-1111-2222-3333-444444444444}\x00"
    assert info[268:286] == b"Intel(R) Ethernet\x00"
    assert struct.unpack_from("<I", info, 400)[0] == 6
    assert info[404:410] == bytes.fromhex("001122334455")
    assert struct.unpack_from("<I", info, 416)[0] == 6
    assert info[432:444] == b"192.168.1.5\x00"
    assert info[448:462] == b"255.255.255.0\x00"


def test_get_adapters_info_small_buffer_gives_size(adapter_emu: Speakeasy) -> None:
    buf = alloc(adapter_emu, b"\xcc" * 0x400)
    size = alloc(adapter_emu, struct.pack("<I", 16))
    rv, _ = call(adapter_emu, "iphlpapi", "GetAdaptersInfo", [buf, size])
    assert rv == 111
    assert struct.unpack("<I", adapter_emu.mem_read(size, 4))[0] > 16
    assert adapter_emu.mem_read(buf, 0x400) == b"\xcc" * 0x400


def test_get_adapters_info_accepts_a_partial_adapter(
    config: dict[str, Any], load_test_bin: Callable[[str], bytes]
) -> None:
    config["network"]["adapters"] = [{"name": "eth0", "type": "wireless"}]
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        buf = alloc(se, b"\xcc" * 0x400)
        size = alloc(se, struct.pack("<I", 0x400))
        rv, _ = call(se, "iphlpapi", "GetAdaptersInfo", [buf, size])
        assert rv == 0
        info = se.mem_read(buf, 0x1D0)
        assert info[8:13] == b"eth0\x00"
        assert struct.unpack_from("<I", info, 416)[0] == 1


def test_uuid_to_string_a_returns_a_string_pointer(dll_emu: Speakeasy) -> None:
    guid = alloc(dll_emu, bytes(range(16)))
    out = alloc(dll_emu, b"\xcc" * 64)
    rv, _ = call(dll_emu, "rpcrt4", "UuidToStringA", [guid, out])
    assert rv == 0
    ptr = struct.unpack("<I", dll_emu.mem_read(out, 4))[0]
    assert dll_emu.mem_read(out + 4, 60) == b"\xcc" * 60
    assert dll_emu.mem_read(ptr, 37) == b"03020100-0504-0706-0809-0a0b0c0d0e0f\x00"


def test_inet_ntoa_reuses_the_buffer_for_an_address(dll_emu: Speakeasy) -> None:
    addr = struct.unpack("<I", bytes([10, 1, 2, 3]))[0]
    first, _ = call(dll_emu, "ws2_32", "inet_ntoa", [addr])
    second, _ = call(dll_emu, "ws2_32", "inet_ntoa", [addr])
    assert first == second
    assert dll_emu.mem_read(first, 9) == b"10.1.2.3\x00"


@pytest.mark.parametrize(
    "emu_fixture, max_sockets_offset, description_offset, size",
    [("dll_emu", 390, 4, 400), ("dll64_emu", 4, 16, 408)],
)
@pytest.mark.parametrize("requested, version", [(0x0202, 0x0202), (0x0101, 0x0101), (0x0303, 0x0202)])
def test_wsa_startup_fills_wsadata(
    request: pytest.FixtureRequest,
    emu_fixture: str,
    max_sockets_offset: int,
    description_offset: int,
    size: int,
    requested: int,
    version: int,
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_fixture)
    data = alloc(se, b"\xcc" * 0x200)
    rv, _ = call(se, "ws2_32", "WSAStartup", [requested, data])
    assert rv == 0
    wsadata = se.mem_read(data, 0x200)
    assert struct.unpack_from("<HH", wsadata, 0) == (version, 0x0202)
    assert struct.unpack_from("<H", wsadata, max_sockets_offset)[0] != 0xCCCC
    assert wsadata[description_offset : description_offset + 12] == b"WinSock 2.0\x00"
    assert wsadata[size:] == b"\xcc" * (0x200 - size)
