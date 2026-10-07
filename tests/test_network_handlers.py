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
