import os
import socket
import struct
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass

import pytest

TESTS_DIR = os.path.dirname(__file__)


@dataclass(frozen=True)
class X86Registers:
    eax: int
    ecx: int
    edx: int
    ebx: int
    esp: int
    ebp: int
    esi: int
    edi: int
    eip: int
    eflags: int
    cs: int
    ss: int
    ds: int
    es: int
    fs: int
    gs: int

    @classmethod
    def from_rsp(cls, encoded: str):
        # The i386 core feature begins with these sixteen 32-bit registers in
        # the same order as the dataclass fields above.
        core_layout = struct.Struct("<16I")
        return cls(*core_layout.unpack(bytes.fromhex(encoded)[: core_layout.size]))


class GdbRspClient:
    def __init__(self, port: int, timeout: float = 10.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(("127.0.0.1", port))

    def close(self):
        self.sock.close()

    def _checksum(self, data: str) -> str:
        return f"{sum(ord(c) for c in data) & 0xFF:02x}"

    def send(self, data: str) -> str:
        packet = f"${data}#{self._checksum(data)}"
        self.sock.sendall(packet.encode())
        return self._recv()

    @staticmethod
    def _decode_rle(data: str) -> str:
        """Decode GDB RSP run-length encoding.

        x*N means: one explicit x, then (ord(N)-29) additional copies.
        """
        result = []
        i = 0
        while i < len(data):
            if i + 2 < len(data) and data[i + 1] == "*":
                repeat = ord(data[i + 2]) - 29
                result.append(data[i] * (repeat + 1))
                i += 3
            else:
                result.append(data[i])
                i += 1
        return "".join(result)

    def _recv(self) -> str:
        buf = b""
        while b"#" not in buf or len(buf) < buf.index(b"#") + 3:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        ack_end = 0
        while ack_end < len(buf) and buf[ack_end : ack_end + 1] == b"+":
            ack_end += 1
        buf = buf[ack_end:]
        if buf.startswith(b"$"):
            end = buf.index(b"#")
            return self._decode_rle(buf[1:end].decode())
        return self._decode_rle(buf.decode())

    def query_halt_reason(self) -> str:
        return self.send("?")

    def read_registers(self) -> str:
        return self.send("g")

    def read_x86_registers(self) -> X86Registers:
        return X86Registers.from_rsp(self.read_registers())

    def read_memory(self, addr: int, size: int) -> str:
        return self.send(f"m{addr:x},{size:x}")

    def continue_(self) -> str:
        return self.send("c")

    def step(self) -> str:
        return self.send("s")

    def query(self, packet: str) -> str:
        return self.send(packet)

    def send_no_wait(self, data: str):
        packet = f"${data}#{self._checksum(data)}"
        self.sock.sendall(packet.encode())

    def interrupt(self) -> str:
        self.sock.sendall(b"\x03")
        return self._recv()


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_is_listening(port: int) -> bool:
    """Check if a port is in use without consuming any connection."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True


def _wait_for_port(port: int, proc: subprocess.Popen, timeout: float = 15.0):
    """Wait until port is listening, or the subprocess dies."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _, stderr = proc.communicate(timeout=5)
            pytest.fail(f"GDB server exited early (rc={proc.returncode}): {stderr.decode(errors='replace')}")
        if _port_is_listening(port):
            return
        time.sleep(0.1)
    proc.kill()
    _, stderr = proc.communicate(timeout=5)
    pytest.fail(f"GDB server did not start within {timeout}s: {stderr.decode(errors='replace')}")


_PAUSE_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    with open(config_path) as f:
        cfg = json.load(f)

    se = Speakeasy(config=cfg, gdb_port=port)
    address = se.load_shellcode(data=b"\\xeb\\xfe", arch="x86")
    se.run_shellcode(address)
    se.shutdown()
""")


_FAULT_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    with open(config_path) as f:
        cfg = json.load(f)

    se = Speakeasy(config=cfg, gdb_port=port)
    address = se.load_shellcode(data=b"\\x90\\xc3", arch="x86")

    def fail_start(*args, **kwargs):
        raise RuntimeError("forced execution failure")

    se.emu.emu_eng.start = fail_start
    se.run_shellcode(address)
    se.shutdown()
""")


_EXIT_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    with open(config_path) as f:
        cfg = json.load(f)

    se = Speakeasy(config=cfg, gdb_port=port)
    address = se.load_shellcode(data=b"\\xc3", arch="x86")
    se.run_shellcode(address)
    se.shutdown()
""")


_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import lzma
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    bin_path = sys.argv[3]
    host = sys.argv[4]

    with open(config_path) as f:
        cfg = json.load(f)
    with lzma.open(bin_path) as f:
        data = f.read()

    se = Speakeasy(config=cfg, gdb_port=port, gdb_host=host)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)
    se.shutdown()
""")


def _start_module_server(filename: str, host: str = "127.0.0.1") -> tuple[int, subprocess.Popen]:
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    bin_path = os.path.join(TESTS_DIR, "bins", filename)
    proc = subprocess.Popen(
        [sys.executable, "-c", _SERVER_SCRIPT, str(port), config_path, bin_path, host],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_port(port, proc)
    return port, proc


def _stop_server(proc: subprocess.Popen):
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


@pytest.fixture
def gdb_emulator():
    """Start a 32-bit target with GDB enabled in an isolated subprocess."""
    port, proc = _start_module_server("dll_test_x86.dll.xz")
    yield port
    _stop_server(proc)


@pytest.fixture
def gdb_x64_emulator():
    port, proc = _start_module_server("dll_test_x64.dll.xz")
    yield port
    _stop_server(proc)


def test_gdb_connect_and_read_registers(gdb_emulator):
    port = gdb_emulator
    client = GdbRspClient(port)
    try:
        reason = client.query_halt_reason()
        assert reason

        regs = client.read_registers()
        assert len(regs) > 0
        assert all(char in "0123456789abcdefxx" for char in regs.lower())

        assert client.read_x86_registers().eip != 0

        client.continue_()
    finally:
        client.close()


def test_gdb_read_memory(gdb_emulator):
    port = gdb_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()

        registers = client.read_x86_registers()
        mem = client.read_memory(registers.esp, 4)
        assert len(mem) == 8
        assert all(char in "0123456789abcdef" for char in mem.lower())

        client.continue_()
    finally:
        client.close()


def test_gdb_ida_process_metadata(gdb_emulator):
    client = GdbRspClient(gdb_emulator)
    try:
        supported = client.query("qSupported:multiprocess+;xmlRegisters=i386")
        assert "qXfer:libraries:read+" in supported
        assert "qXfer:exec-file:read+" in supported
        assert "qXfer:threads:read+" in supported

        target = client.query("qXfer:features:read:target.xml:0,4000")
        assert "<architecture>i386</architecture>" in target
        assert 'name="eip" bitsize="32"' in target

        libraries = client.query("qXfer:libraries:read::0,4000")
        assert libraries.startswith("l<library-list")
        assert "kernel32.dll" in libraries
        assert '<segment address="0x' in libraries

        executable = client.query("qXfer:exec-file:read::0,4000")
        assert executable.startswith("lC:\\")
        assert executable.endswith((".exe", ".dll", ".sys"))

        threads = client.query("qXfer:threads:read::0,4000")
        assert threads == 'l<threads><thread id="1" name="main"/></threads>'
        assert client.query("qGetTIBAddr:1") != "0"

        client.continue_()
    finally:
        client.close()


@pytest.fixture
def gdb_pause_emulator():
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    proc = subprocess.Popen(
        [sys.executable, "-c", _PAUSE_SERVER_SCRIPT, str(port), config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_port(port, proc)
    yield port
    _stop_server(proc)


@pytest.fixture
def gdb_fault_emulator():
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    proc = subprocess.Popen(
        [sys.executable, "-c", _FAULT_SERVER_SCRIPT, str(port), config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_port(port, proc)
    yield port, proc
    _stop_server(proc)


@pytest.fixture
def gdb_exit_emulator():
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    proc = subprocess.Popen(
        [sys.executable, "-c", _EXIT_SERVER_SCRIPT, str(port), config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_port(port, proc)
    yield port, proc
    _stop_server(proc)


def test_gdb_breakpoint_stop_keeps_session_alive(gdb_emulator):
    import capstone

    client = GdbRspClient(gdb_emulator)
    try:
        client.query_halt_reason()
        client.step()
        pc = client.read_x86_registers().eip
        code = bytes.fromhex(client.read_memory(pc, 16))
        instruction = next(iter(capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32).disasm(code, pc)))
        breakpoint = pc + instruction.size

        assert client.query(f"Z0,{breakpoint:x},1") == "OK"
        stop = client.continue_()
        assert stop.startswith("T05")
        assert "swbreak:;" in stop

        # A register query after the stop reply verifies that the native
        # debugger session remains live.
        assert client.read_x86_registers().eip == breakpoint

        assert client.query(f"z0,{breakpoint:x},1") == "OK"
        assert client.continue_().startswith(("T", "W"))
    finally:
        client.close()


def test_gdb_ctrl_c_pauses_running_target(gdb_pause_emulator):
    client = GdbRspClient(gdb_pause_emulator)
    try:
        client.query_halt_reason()
        client.send_no_wait("c")
        time.sleep(0.05)

        stop = client.interrupt()
        assert stop.startswith("T02")
        assert client.read_registers()
    finally:
        client.close()


def test_gdb_x64_target_description_and_registers(gdb_x64_emulator):
    client = GdbRspClient(gdb_x64_emulator)
    try:
        target = client.query("qXfer:features:read:target.xml:0,4000")
        assert target.startswith("l")
        assert "<architecture>i386:x86-64</architecture>" in target
        assert 'name="rip" bitsize="64"' in target
        assert 'name="xmm15" bitsize="128"' in target
        assert len(client.read_registers()) == 1072
    finally:
        client.close()


def test_gdb_detach(gdb_pause_emulator):
    client = GdbRspClient(gdb_pause_emulator)
    try:
        client.query_halt_reason()
        assert client.query("D") == "OK"
    finally:
        client.close()


def test_gdb_reports_target_fault_and_nonzero_termination(gdb_fault_emulator):
    port, proc = gdb_fault_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.continue_().startswith("T0b")
        assert client.read_x86_registers().eip != 0
        assert client.continue_() == "X0b"
        assert proc.wait(timeout=10) == 0
    finally:
        client.close()


def test_gdb_reports_clean_exit(gdb_exit_emulator):
    port, proc = gdb_exit_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.continue_() == "W00"
        assert proc.wait(timeout=10) == 0
    finally:
        client.close()


def test_gdb_single_step(gdb_emulator):
    port = gdb_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()

        previous_eip = client.read_x86_registers().eip

        for _ in range(3):
            response = client.step()
            assert response.startswith(("S", "T"))
            eip = client.read_x86_registers().eip
            assert eip != previous_eip
            previous_eip = eip

        client.continue_()
    finally:
        client.close()


def test_gdb_hardware_breakpoint_large_range(gdb_emulator):
    client = GdbRspClient(gdb_emulator)
    try:
        client.query_halt_reason()
        eip = client.read_x86_registers().eip

        for size in (0x1C000, 0x28000, 0x2D000):
            assert client.query(f"Z1,{eip:x},{size:x}") == "OK"
            assert client.query(f"z1,{eip:x},{size:x}") == "OK"

        assert client.query(f"Z1,{eip:x},2d000") == "OK"
        stop = client.continue_()
        assert stop.startswith("T05")
        assert "hwbreak:;" in stop

        assert client.read_registers()

        assert client.query(f"z1,{eip:x},2d000") == "OK"
        assert client.continue_().startswith(("T", "W"))
    finally:
        client.close()
