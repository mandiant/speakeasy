from dataclasses import dataclass
from types import SimpleNamespace
from xml.etree import ElementTree

from unicorn import UC_ARCH_X86, UC_MODE_64, Uc

from speakeasy.gdb import _PACKET_SIZE, GdbServer, ResumeAction, StopReason, _rsp_escape, _rsp_packet
from speakeasy.winenv import arch


@dataclass
class DummyTeb:
    address: int


@dataclass
class DummyThread:
    teb: DummyTeb


class DummyHook:
    def __init__(self):
        self.enabled = True
        self.added = True
        self.native_hook = True
        self.handle = 1
        self.emu_eng = SimpleNamespace(hook_remove=lambda handle: None)

    def add(self):
        self.enabled = True
        self.added = True
        self.handle = 1


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
        self.module_change_listeners = []

    def get_arch(self):
        return arch.ARCH_AMD64

    def add_code_hook(self, callback):
        return DummyHook()

    def add_mem_read_hook(self, callback):
        return DummyHook()

    def add_mem_write_hook(self, callback):
        return DummyHook()


def make_server():
    return GdbServer(DummyEmulator(), 0, "127.0.0.1")


def test_server_uses_provided_bind_host():
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

    oversized_payload = b"q" * (_PACKET_SIZE + 1)
    oversized = _rsp_packet(oversized_payload)
    assert GdbServer._extract_packet(bytearray(oversized))[2] is False


def test_interrupt_during_resume_transition_is_preserved():
    server = make_server()
    server.emu.emu_eng = SimpleNamespace(stop=lambda: None)
    server._running = True

    server._interrupt()

    assert not server.begin_run(ResumeAction())
    reason = server.finish_run(ResumeAction())
    assert reason is not None
    assert reason.signal == 2


def test_instruction_and_memory_hooks_are_enabled_only_when_needed():
    server = make_server()
    server._reply = lambda payload: None
    server._install_hooks()

    assert not server._code_hook.enabled
    assert not server._read_hook.enabled
    assert not server._write_hook.enabled

    server._change_breakpoint(b"Z0,1000,1")
    assert server._code_hook.enabled
    server._change_breakpoint(b"z0,1000,1")
    assert not server._code_hook.enabled

    server._change_breakpoint(b"Z4,2000,4")
    assert server._read_hook.enabled
    assert server._write_hook.enabled
    server._change_breakpoint(b"z4,2000,4")
    assert not server._read_hook.enabled
    assert not server._write_hook.enabled


def test_access_watchpoint_does_not_clobber_write_watchpoint():
    server = make_server()
    replies = []
    server._reply = replies.append

    server._change_breakpoint(b"Z4,1000,4")
    server._change_breakpoint(b"Z2,1000,4")
    server._change_breakpoint(b"z4,1000,4")

    assert (0x1000, 4) not in server._access_watchpoints
    assert (0x1000, 4) in server._write_watchpoints
    assert replies == [b"OK", b"OK", b"OK"]


def test_access_watchpoint_reports_awatch_stop_reason():
    server = make_server()
    reasons = []
    server._access_watchpoints[(0x1000, 4)] = 4
    server._request_stop = reasons.append

    server._on_read(None, 0, 0x1001, 1, 0)

    assert len(reasons) == 1
    assert reasons[0].kind == "awatch"
    assert b"awatch:1001;" in server._stop_reply(reasons[0])


def test_library_stop_reason_reports_library_change():
    server = make_server()

    reply = server._stop_reply(StopReason(kind="library"))

    assert reply.startswith(b"T05")
    assert b"library:;" in reply


def test_library_change_flag_piggybacks_on_next_stop_reply_and_clears():
    server = make_server()
    server._library_list_changed = True

    breakpoint_reason = StopReason(kind="swbreak")
    first = server._stop_reply(breakpoint_reason)
    second = server._stop_reply(breakpoint_reason)

    assert b"swbreak:;" in first
    assert b"library:;" in first
    assert b"library:;" not in second


def test_module_change_while_running_requests_library_stop():
    server = make_server()
    reasons = []
    server._request_stop = reasons.append

    server._on_module_change()

    assert server._library_list_changed
    assert len(reasons) == 1
    assert reasons[0].kind == "library"


def test_module_change_listener_registration_follows_session_lifetime():
    server = make_server()
    server.emu.module_change_listeners.append(server._on_module_change)

    server.close()

    assert server._on_module_change not in server.emu.module_change_listeners


def test_x87_registers_use_full_80_bit_wire_format():
    emulator = DummyEmulator()
    emulator.emu_eng = SimpleNamespace(emu=Uc(UC_ARCH_X86, UC_MODE_64))
    server = GdbServer(emulator, 0, "127.0.0.1")
    st0_index = next(index for index, register in enumerate(server._registers) if register.name == "st0")
    wire_value = (3).to_bytes(8, "little") + (0x7FFF).to_bytes(2, "little")

    server._write_register_value(server._registers[st0_index], wire_value)

    assert server._read_register_value(st0_index) == wire_value


def test_xfer_escaping_respects_advertised_packet_size():
    server = make_server()
    server._executable_path = lambda: "$#}*" * 50000

    response = server._handle_xfer(b"qXfer:exec-file:read::0,ffff")
    encoded = response[:1] + _rsp_escape(response[1:])

    assert response.startswith(b"m")
    assert len(encoded) <= _PACKET_SIZE
    assert all(value not in encoded[1:] for value in b"$#*")


def test_hardware_breakpoint_accepts_large_ranges():
    server = make_server()
    replies = []
    server._reply = replies.append
    server._install_hooks()

    for size_hex in ("1c000", "28000", "2d000", "100000"):
        server._change_breakpoint(f"Z1,401000,{size_hex}".encode())

    assert replies == [b"OK"] * 4
    assert len(server._exec_breakpoints) == 4
    assert (0x401000, 0x2D000) in server._exec_breakpoints


def test_hardware_breakpoint_range_hit_detection():
    server = make_server()
    reasons = []
    server._request_stop = reasons.append
    server._exec_breakpoints[(0x401000, 0x2D000)] = 1

    server._on_code(None, 0x401000, 1)
    server._on_code(None, 0x42DFFF, 1)
    server._on_code(None, 0x415000, 1)
    server._on_code(None, 0x42E000, 1)
    server._on_code(None, 0x400FFF, 1)

    assert len(reasons) == 3
    assert all(r.kind == "hwbreak" for r in reasons)


def test_change_breakpoint_survives_hook_error(caplog):
    server = make_server()
    replies = []
    server._reply = replies.append

    def failing_refresh():
        raise RuntimeError("simulated Unicorn error")

    server._refresh_hooks = failing_refresh
    server._change_breakpoint(b"Z1,401000,2d000")

    assert replies == [b"E01"]
    assert any("breakpoint command failed" in r.message for r in caplog.records)
