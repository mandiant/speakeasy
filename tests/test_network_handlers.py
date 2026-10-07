import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import speakeasy
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


def _read_ptr(se: Speakeasy, addr: int) -> int:
    size = se.emu.get_ptr_size()  # type: ignore[union-attr]
    return int.from_bytes(se.mem_read(addr, size), "little")


@pytest.mark.parametrize("emu_fixture, addr_offset", [("dll_emu", 24), ("dll64_emu", 32)])
@pytest.mark.parametrize("service, port", [(None, 0), (b"443", 443), (b"http", 80)])
def test_getaddrinfo_without_hints(
    request: pytest.FixtureRequest, emu_fixture: str, addr_offset: int, service: bytes | None, port: int
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_fixture)
    node = alloc(se, b"example.com\x00")
    service_ptr = alloc(se, service + b"\x00") if service else 0
    result = alloc(se, b"\x00" * 8)
    rv, _ = call(se, "ws2_32", "getaddrinfo", [node, service_ptr, 0, result])
    assert rv == 0
    for last in range(4):
        call(se, "ws2_32", "inet_ntoa", [last << 24])
    info = _read_ptr(se, result)
    assert struct.unpack("<II", se.mem_read(info + 4, 8)) == (2, 0)
    assert _read_ptr(se, info + addr_offset - se.emu.get_ptr_size()) == 0  # type: ignore[union-attr]
    sockaddr = se.mem_read(_read_ptr(se, info + addr_offset), 8)
    assert struct.unpack("<H", sockaddr[:2])[0] == 2
    assert struct.unpack(">H", sockaddr[2:4])[0] == port
    assert sockaddr[4:8] == bytes([10, 1, 2, 3])


def test_getaddrinfo_unknown_service(dll_emu: Speakeasy) -> None:
    node = alloc(dll_emu, b"example.com\x00")
    service = alloc(dll_emu, b"nosuchservice\x00")
    result = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "ws2_32", "getaddrinfo", [node, service, 0, result])
    assert rv == 10109


def _wininet_request(se: Speakeasy, verb: bytes, objname: bytes) -> int:
    inet, _ = call(se, "wininet", "InternetOpenA", [0, 0, 0, 0, 0])
    server = alloc(se, b"example.com\x00")
    conn, _ = call(se, "wininet", "InternetConnectA", [inet, server, 80, 0, 0, 3, 0, 0])
    verb_ptr = alloc(se, verb + b"\x00")
    obj = alloc(se, objname + b"\x00")
    req, _ = call(se, "wininet", "HttpOpenRequestA", [conn, verb_ptr, obj, 0, 0, 0, 0, 0])
    assert req
    return req


def _winhttp_request(se: Speakeasy, verb: str, objname: str) -> int:
    session, _ = call(se, "winhttp", "WinHttpOpen", [0, 0, 0, 0, 0])
    server = alloc(se, "example.com\x00".encode("utf-16le"))
    conn, _ = call(se, "winhttp", "WinHttpConnect", [session, server, 80, 0])
    verb_ptr = alloc(se, (verb + "\x00").encode("utf-16le"))
    obj = alloc(se, (objname + "\x00").encode("utf-16le"))
    req, _ = call(se, "winhttp", "WinHttpOpenRequest", [conn, verb_ptr, obj, 0, 0, 0, 0])
    assert req
    return req


def test_internet_read_file_without_a_configured_response(dll_emu: Speakeasy) -> None:
    req = _wininet_request(dll_emu, b"POST", b"/gate.php")
    avail = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "wininet", "InternetQueryDataAvailable", [req, avail, 0, 0])
    assert rv == 1
    assert dll_emu.mem_read(avail, 4) == b"\x00" * 4
    buf = alloc(dll_emu, b"\xcc" * 16)
    read = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "wininet", "InternetReadFile", [req, buf, 16, read])
    assert rv == 1
    assert dll_emu.mem_read(read, 4) == b"\x00" * 4


def test_win_http_read_data_without_a_configured_response(dll_emu: Speakeasy) -> None:
    req = _winhttp_request(dll_emu, "POST", "/gate.php")
    buf = alloc(dll_emu, b"\xcc" * 16)
    read = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "winhttp", "WinHttpReadData", [req, buf, 16, read])
    assert rv == 1
    assert dll_emu.mem_read(read, 4) == b"\x00" * 4


def test_internet_open_url_with_headers(dll_emu: Speakeasy) -> None:
    inet, _ = call(dll_emu, "wininet", "InternetOpenA", [0, 0, 0, 0, 0])
    url = alloc(dll_emu, b"http://example.com/a.bin\x00")
    headers = alloc(dll_emu, b"Accept: */*\r\n\x00")
    req, _ = call(dll_emu, "wininet", "InternetOpenUrlA", [inet, url, headers, 0xFFFFFFFF, 0, 0])
    assert req
    buf = alloc(dll_emu, b"\xcc" * 16)
    read = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "wininet", "InternetReadFile", [req, buf, 16, read])
    assert rv == 1
    assert dll_emu.mem_read(read, 4) == struct.pack("<I", 16)


def test_internet_open_url_without_a_url(dll_emu: Speakeasy) -> None:
    inet, _ = call(dll_emu, "wininet", "InternetOpenA", [0, 0, 0, 0, 0])
    rv, _ = call(dll_emu, "wininet", "InternetOpenUrlA", [inet, 0, 0, 0, 0, 0])
    assert rv == 0


def _url_components(host_buf: int = 0, host_len: int = 1) -> bytes:
    fields = [60, 0, 1, 0, host_buf, host_len, 0, 0, 0, 0, 0, 0, 1, 0, 1]
    return struct.pack("<15I", *fields)


@pytest.mark.parametrize("dll, name, width", [("wininet", "InternetCrackUrlA", 1), ("winhttp", "WinHttpCrackUrl", 2)])
@pytest.mark.parametrize(
    "url, host, port, path, extra",
    [
        ("http://user@1.2.3.4:8080/x/y.php?a=1", "1.2.3.4", 8080, "/x/y.php", "?a=1"),
        ("https://Example.com/index.html", "Example.com", 443, "/index.html", ""),
        ("http://example.com", "example.com", 80, "", ""),
    ],
)
def test_crack_url_points_into_the_url(
    dll_emu: Speakeasy, dll: str, name: str, width: int, url: str, host: str, port: int, path: str, extra: str
) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    url_ptr = alloc(dll_emu, (url + "\x00").encode(enc))
    comp = alloc(dll_emu, _url_components())
    rv, _ = call(dll_emu, dll, name, [url_ptr, 0, 0, comp])
    assert rv == 1
    fields = struct.unpack("<15I", dll_emu.mem_read(comp, 60))
    assert fields[6] & 0xFFFF == port
    for ptr, length, text in [
        (fields[1], fields[2], url.split(":")[0]),
        (fields[4], fields[5], host),
        (fields[11], fields[12], path),
        (fields[13], fields[14], extra),
    ]:
        assert length == len(text)
        assert dll_emu.mem_read(ptr, length * width).decode(enc) == text


@pytest.mark.parametrize("dll, name, width", [("wininet", "InternetCrackUrlA", 1), ("winhttp", "WinHttpCrackUrl", 2)])
def test_crack_url_copies_the_host(dll_emu: Speakeasy, dll: str, name: str, width: int) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    url_ptr = alloc(dll_emu, "http://example.com:81/a\x00".encode(enc))
    host_buf = alloc(dll_emu, b"\xcc" * 64)
    comp = alloc(dll_emu, _url_components(host_buf, 32))
    rv, _ = call(dll_emu, dll, name, [url_ptr, 0, 0, comp])
    assert rv == 1
    fields = struct.unpack("<15I", dll_emu.mem_read(comp, 60))
    assert (fields[4], fields[5]) == (host_buf, 11)
    assert dll_emu.mem_read(host_buf, 12 * width) == "example.com\x00".encode(enc)


def test_recv_peek_keeps_the_read_position(dll_emu: Speakeasy) -> None:
    stager = (Path(speakeasy.__file__).parent / "resources" / "web" / "stager.bin").read_bytes()
    s, _ = call(dll_emu, "ws2_32", "socket", [2, 1, 6])
    buf = alloc(dll_emu, b"\x00" * 0x100)
    assert call(dll_emu, "ws2_32", "recv", [s, buf, 4, 0])[0] == 4
    peeked, _ = call(dll_emu, "ws2_32", "recv", [s, buf, 0x100, 2])
    assert dll_emu.mem_read(buf, peeked) == stager[4:]
    assert call(dll_emu, "ws2_32", "recv", [s, buf, 4, 0])[0] == 4
    assert dll_emu.mem_read(buf, 4) == stager[4:8]


@pytest.mark.parametrize("level", [101, 102])
def test_net_wksta_get_info_keeps_the_lanroot(dll_emu: Speakeasy, level: int) -> None:
    out = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(dll_emu, "netapi32", "NetWkstaGetInfo", [0, level, out])
    assert rv == 0
    info = dll_emu.mem_read(struct.unpack("<I", dll_emu.mem_read(out, 4))[0], 28 if level == 102 else 24)
    assert struct.unpack_from("<I", info, 0)[0] == 500
    lanroot = struct.unpack_from("<I", info, 20)[0]
    assert lanroot != 0
    assert dll_emu.mem_read(lanroot, 2) == b"\x00\x00"
    if level == 102:
        assert struct.unpack_from("<I", info, 24)[0] == 2


def test_url_download_to_cache_file_small_buffer_fails(dll_emu: Speakeasy) -> None:
    url = alloc(dll_emu, b"http://example.com/a.bin\x00")
    out = alloc(dll_emu, b"\xcc" * 8)
    rv, _ = call(dll_emu, "urlmon", "URLDownloadToCacheFileA", [0, url, out, 8, 0, 0])
    assert rv == 0x8007000E
    assert dll_emu.mem_read(out, 8) == b"\xcc" * 8


@pytest.mark.parametrize("emu_fixture, ptr_size", [("dll_emu", 4), ("dll64_emu", 8)])
def test_win_http_get_ie_proxy_config_clears_the_strings(
    request: pytest.FixtureRequest, emu_fixture: str, ptr_size: int
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_fixture)
    config = alloc(se, b"\xcc" * 40)
    rv, _ = call(se, "winhttp", "WinHttpGetIEProxyConfigForCurrentUser", [config])
    assert rv == 1
    size = 4 * ptr_size
    data = se.mem_read(config, 40)
    assert struct.unpack_from("<I", data, 0)[0] == 1
    assert data[ptr_size:size] == b"\x00" * (size - ptr_size)
    assert data[size:] == b"\xcc" * (40 - size)


@pytest.mark.parametrize("emu_fixture, ptr_size", [("dll_emu", 4), ("dll64_emu", 8)])
def test_win_http_get_proxy_for_url_reports_no_proxy(
    request: pytest.FixtureRequest, emu_fixture: str, ptr_size: int
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_fixture)
    url = alloc(se, "http://example.com/\x00".encode("utf-16le"))
    info = alloc(se, b"\xcc" * 32)
    rv, _ = call(se, "winhttp", "WinHttpGetProxyForUrl", [0, url, 0, info])
    assert rv == 1
    size = 3 * ptr_size
    data = se.mem_read(info, 32)
    assert struct.unpack_from("<I", data, 0)[0] == 1
    assert data[ptr_size:size] == b"\x00" * (size - ptr_size)
    assert data[size:] == b"\xcc" * (32 - size)
