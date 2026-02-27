import os
import socket
import struct
import subprocess
import sys
import textwrap
import time

import pytest

if os.environ.get("SPEAKEASY_ENABLE_GDB_TESTS") != "1":
    pytest.skip("Set SPEAKEASY_ENABLE_GDB_TESTS=1 to run GDB integration tests", allow_module_level=True)

pytest.importorskip("udbserver")

TESTS_DIR = os.path.dirname(__file__)


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
        """Decode GDB RSP run-length encoding: x*Y repeats x (ord(Y)-29) times."""
        result = []
        i = 0
        while i < len(data):
            if i + 2 < len(data) and data[i + 1] == "*":
                result.append(data[i] * (ord(data[i + 2]) - 29))
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

    def read_memory(self, addr: int, size: int) -> str:
        return self.send(f"m{addr:x},{size:x}")

    def continue_(self) -> str:
        return self.send("c")

    def step(self) -> str:
        return self.send("s")


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


_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import lzma
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    bin_path = sys.argv[3]

    with open(config_path) as f:
        cfg = json.load(f)
    with lzma.open(bin_path) as f:
        data = f.read()

    se = Speakeasy(config=cfg, gdb_port=port)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)
    se.shutdown()
""")


@pytest.fixture
def gdb_emulator():
    """Start speakeasy with GDB enabled in a subprocess.

    Uses a subprocess instead of a thread because udbserver's Rust FFI layer
    can abort the process on error, which would kill the entire pytest session.
    """
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    bin_path = os.path.join(TESTS_DIR, "bins", "dll_test_x86.dll.xz")

    proc = subprocess.Popen(
        [sys.executable, "-c", _SERVER_SCRIPT, str(port), config_path, bin_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    _wait_for_port(port, proc)

    yield port

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def test_gdb_connect_and_read_registers(gdb_emulator):
    port = gdb_emulator
    client = GdbRspClient(port)
    try:
        reason = client.query_halt_reason()
        assert reason

        regs = client.read_registers()
        assert len(regs) > 0
        assert all(char in "0123456789abcdefxx" for char in regs.lower())

        # x86 GDB register order: eax(0), ecx(8), edx(16), ebx(24),
        # esp(32), ebp(40), esi(48), edi(56), eip(64)
        # Each register is 4 bytes = 8 hex chars.
        eip_hex = regs[64:72].lower()
        assert eip_hex not in ("00000000", "xxxxxxxx")

        client.continue_()
    finally:
        client.close()


@pytest.mark.xfail(reason="udbserver memory read returns E01 for all addresses")
def test_gdb_read_memory(gdb_emulator):
    port = gdb_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()

        regs_hex = client.read_registers()
        sp_hex = regs_hex[32:40]  # esp is at offset 32 (register #4)
        sp = struct.unpack("<I", bytes.fromhex(sp_hex))[0]

        mem = client.read_memory(sp, 4)
        assert len(mem) == 8
        assert all(char in "0123456789abcdef" for char in mem.lower())

        client.continue_()
    finally:
        client.close()


@pytest.mark.xfail(reason="udbserver single-step does not advance EIP")
def test_gdb_single_step(gdb_emulator):
    port = gdb_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()

        regs_before = client.read_registers()
        eip_before = struct.unpack("<I", bytes.fromhex(regs_before[64:72]))[0]

        response = client.step()
        assert response.startswith("S") or response.startswith("T")

        regs_after = client.read_registers()
        eip_after = struct.unpack("<I", bytes.fromhex(regs_after[64:72]))[0]
        assert eip_after != eip_before

        client.continue_()
    finally:
        client.close()
