import copy
import socket
import struct
import threading
import time

import pytest

from speakeasy import Speakeasy

pytest.importorskip("udbserver")


class GdbRspClient:
    """Minimal GDB Remote Serial Protocol client for testing."""

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
            return buf[1:end].decode()
        return buf.decode()

    def query_halt_reason(self) -> str:
        return self.send("?")

    def read_registers(self) -> str:
        return self.send("g")

    def read_memory(self, addr: int, size: int) -> str:
        return self.send(f"m{addr:x},{size:x}")

    def set_breakpoint(self, addr: int) -> str:
        return self.send(f"Z0,{addr:x},1")

    def remove_breakpoint(self, addr: int) -> str:
        return self.send(f"z0,{addr:x},1")

    def continue_(self) -> str:
        return self.send("c")

    def step(self) -> str:
        return self.send("s")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def gdb_emulator(config, load_test_bin):
    """Start speakeasy with GDB enabled in a background thread."""
    port = _find_free_port()
    cfg = copy.deepcopy(config)
    data = load_test_bin("dll_test_x86.dll.xz")

    error = None

    def run():
        nonlocal error
        try:
            se = Speakeasy(config=cfg, gdb_port=port)
            module = se.load_module(data=data)
            se.run_module(module, all_entrypoints=True)
            se.shutdown()
        except Exception as e:
            error = e

    t = threading.Thread(target=run, daemon=True)
    t.start()

    time.sleep(0.5)

    yield port, t

    t.join(timeout=30)
    if error is not None:
        raise error


def test_gdb_connect_and_read_registers(gdb_emulator):
    port, thread = gdb_emulator
    client = GdbRspClient(port)
    try:
        reason = client.query_halt_reason()
        assert reason, "Expected a halt reason response"

        regs = client.read_registers()
        assert len(regs) > 0, "Expected register data"
        assert all(c in "0123456789abcdefxx" for c in regs.lower()), "Expected hex register data"

        # x86 register order in udbserver is: eax, ecx, edx, ebx, esp, ebp, esi, edi, eip, ...
        eip_hex = regs[32:40].lower()
        assert eip_hex not in ("00000000", "xxxxxxxx"), "Expected initial PC to be initialized"

        client.continue_()
    finally:
        client.close()


def test_gdb_read_memory(gdb_emulator):
    port, thread = gdb_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()

        regs_hex = client.read_registers()
        sp_hex = regs_hex[16:24]
        sp_bytes = bytes.fromhex(sp_hex)
        sp = struct.unpack("<I", sp_bytes)[0]

        mem = client.read_memory(sp, 4)
        assert len(mem) == 8, f"Expected 8 hex chars for 4 bytes, got {len(mem)}"
        assert all(c in "0123456789abcdef" for c in mem.lower())

        client.continue_()
    finally:
        client.close()


def test_gdb_single_step(gdb_emulator):
    port, thread = gdb_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()

        regs_before = client.read_registers()
        eip_before_hex = regs_before[32:40]
        eip_before = struct.unpack("<I", bytes.fromhex(eip_before_hex))[0]

        response = client.step()
        assert response.startswith("S") or response.startswith("T"), f"Expected stop reply after step, got: {response}"

        regs_after = client.read_registers()
        eip_after_hex = regs_after[32:40]
        eip_after = struct.unpack("<I", bytes.fromhex(eip_after_hex))[0]

        assert eip_after != eip_before, "Expected PC to advance after single step"

        client.continue_()
    finally:
        client.close()
