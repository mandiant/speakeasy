from dataclasses import dataclass
from xml.etree import ElementTree

from speakeasy.gdb import GdbServer, _rsp_escape, _rsp_packet
from speakeasy.winenv import arch


@dataclass
class DummyTeb:
    address: int


@dataclass
class DummyThread:
    teb: DummyTeb


class DummyModule:
    def __init__(self, path, base):
        self.emu_path = path
        self.base = base


class DummyEmulator:
    def __init__(self):
        self.modules = [
            DummyModule(r"C:\sample.exe", 0x400000),
            DummyModule(r"C:\Windows\System32\weird&name.dll", 0x70000000),
        ]
        self.curr_thread = DummyThread(DummyTeb(0x7FFDE000))

    def get_arch(self):
        return arch.ARCH_AMD64


def make_server():
    return GdbServer(DummyEmulator(), 0)


def test_server_bind_host_defaults_to_loopback_and_can_be_overridden():
    assert make_server().host == "127.0.0.1"
    assert GdbServer(DummyEmulator(), 0, "0.0.0.0").host == "0.0.0.0"


def test_supported_features_include_ida_process_queries():
    server = make_server()
    replies = []
    server._reply = replies.append

    server._handle_command(b"qSupported:multiprocess+;xmlRegisters=i386")

    response = replies[0]
    assert b"qXfer:features:read+" in response
    assert b"qXfer:libraries:read+" in response
    assert b"qXfer:exec-file:read+" in response
    assert b"qXfer:threads:read+" in response
    assert b"qXfer:memory-map:read+" in response


def test_target_description_matches_native_x64_register_layout():
    response = make_server()._handle_xfer(b"qXfer:features:read:target.xml:0,4000")
    root = ElementTree.fromstring(response[1:])
    registers = root.findall(".//reg")

    assert response.startswith(b"l<?xml")
    assert root.findtext("architecture") == "i386:x86-64"
    assert root.findtext("osabi") == "Windows"
    assert len(registers) == 57
    assert sum(int(register.attrib["bitsize"]) for register in registers) == 4288
    assert any(register.attrib["name"] == "rip" for register in registers)


def test_library_list_uses_windows_gdb_segment_convention():
    response = make_server()._handle_xfer(b"qXfer:libraries:read::0,4000")

    assert response.startswith(b"l<library-list")
    assert b'name="C:\\sample.exe"' in response
    assert b'address="0x401000"' in response
    assert b"weird&amp;name.dll" in response
    assert b'address="0x70001000"' in response


def test_xfer_chunking_and_process_metadata():
    server = make_server()

    first = server._handle_xfer(b"qXfer:exec-file:read::0,4")
    second = server._handle_xfer(b"qXfer:exec-file:read::4,100")

    assert first == b"mC:\\s"
    assert second == b"lample.exe"
    assert server._handle_xfer(b"qXfer:exec-file:read:2a:0,100") == b"lC:\\sample.exe"
    assert server._teb_address() == 0x7FFDE000


def test_packet_extraction_validates_checksum_across_fragmented_input():
    raw = _rsp_packet(b"qC")
    buffer = bytearray(raw[:-1])
    assert GdbServer._extract_packet(buffer) is None

    buffer.extend(raw[-1:])
    assert GdbServer._extract_packet(buffer) == (raw, b"qC", True)

    corrupt = bytearray(raw)
    corrupt[-1] = ord("0") if corrupt[-1] != ord("0") else ord("1")
    assert GdbServer._extract_packet(corrupt)[2] is False

    trailing_escape = _rsp_packet(b"qC}")
    assert GdbServer._extract_packet(bytearray(trailing_escape))[2] is False

    oversized_payload = b"q" * (0x4000 + 1)
    oversized = _rsp_packet(oversized_payload)
    assert GdbServer._extract_packet(bytearray(oversized))[2] is False


def test_xfer_escaping_respects_advertised_packet_size():
    server = make_server()
    server._executable_path = lambda: "$#}*" * 5000

    response = server._handle_xfer(b"qXfer:exec-file:read::0,ffff")
    encoded = response[:1] + _rsp_escape(response[1:])

    assert response.startswith(b"m")
    assert len(encoded) <= 0x4000
    assert all(value not in encoded[1:] for value in b"$#*")
