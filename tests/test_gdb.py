import json
import os
import socket
import struct
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import capstone
import pytest

from speakeasy import Speakeasy
from tests.guest_harness import get_api, guest_call

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
    def from_rsp(cls, encoded: str) -> "X86Registers":
        # The i386 core feature begins with these sixteen 32-bit registers in
        # the same order as the dataclass fields above.
        core_layout = struct.Struct("<16I")
        return cls(*core_layout.unpack(bytes.fromhex(encoded)[: core_layout.size]))


class GdbRspClient:
    def __init__(self, port: int, timeout: float = 10.0):
        """Connect to the GDB server on port, and try again until the server listens."""
        deadline = time.monotonic() + 15
        while True:
            try:
                self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
                return
            except ConnectionRefusedError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.01)

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

    def kill(self):
        """Send k and wait for its ack, as GDB does. The server does not reply to k."""
        self.send_no_wait("k")
        assert self.sock.recv(1) == b"+"

    def interrupt(self) -> str:
        self.sock.sendall(b"\x03")
        return self._recv()


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


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


_MEMORY_FAULT_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    shellcode = bytes.fromhex(sys.argv[3])
    arch = sys.argv[4]
    with open(config_path) as f:
        cfg = json.load(f)

    se = Speakeasy(config=cfg, gdb_port=port)
    address = se.load_shellcode(data=shellcode, arch=arch)
    print(hex(address), flush=True)
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


_EXIT_PROCESS_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import struct
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    with open(config_path) as f:
        cfg = json.load(f)

    se = Speakeasy(config=cfg, gdb_port=port)
    # push 0; mov eax, ExitProcess; call eax; jmp $
    address = se.load_shellcode(data=b"\\x6a\\x00\\xb8\\x00\\x00\\x00\\x00\\xff\\xd0\\xeb\\xfe", arch="x86")
    exit_process = se.emu.get_proc("kernel32", "ExitProcess")
    se.mem_write(address + 3, struct.pack("<I", exit_process))
    se.run_shellcode(address)
    se.shutdown()
""")


_LIBRARY_LOAD_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    with open(config_path) as f:
        cfg = json.load(f)

    se = Speakeasy(config=cfg, gdb_port=port)
    address = se.load_shellcode(data=b"\\x90\\xeb\\xfe", arch="x86")

    loaded = []

    def load_once(*args, **kwargs):
        if not loaded:
            loaded.append(True)
            se.emu.load_module_by_name("gdbtestlib")

    se.emu.add_code_hook(cb=load_once)
    se.run_shellcode(address)
    se.shutdown()
""")


_WATCHPOINT_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import struct
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    with open(config_path) as f:
        cfg = json.load(f)

    se = Speakeasy(config=cfg, gdb_port=port)
    address = se.load_shellcode(data=b"\\x90" * 12, arch="x86")
    scratch = se.mem_alloc(0x1000)
    se.mem_write(scratch, b"\\0" * 4)
    # inc dword [scratch]; mov eax, 42; ret
    code = b"\\xff\\x05" + struct.pack("<I", scratch) + b"\\xb8\\x2a\\x00\\x00\\x00\\xc3"
    se.mem_write(address, code)
    print(hex(address), hex(scratch), flush=True)
    se.run_shellcode(address)
    se.shutdown()
""")


_SHELLCODE_RESULT_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import struct
    import sys

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    code = bytes.fromhex(sys.argv[3])
    with open(config_path) as f:
        cfg = json.load(f)

    se = Speakeasy(config=cfg, gdb_port=port)
    address = se.load_shellcode(data=b"\\x90" * 0x100, arch="x86")
    scratch = se.mem_alloc(0x1000)
    # The shellcode refers to these addresses through placeholder immediates.
    for marker, value in ((0x11111111, address + 0x40), (0x22222222, scratch)):
        code = code.replace(struct.pack("<I", marker), struct.pack("<I", value))
    se.mem_write(address, code)
    print(hex(address), hex(scratch), flush=True)
    se.run_shellcode(address)
    run = se.get_report().entry_points[0]
    print(json.dumps({
        "error": run.error.type if run.error else None,
        "pc": run.error.pc if run.error else None,
        "events": len(run.events or []),
    }), flush=True)
    se.shutdown()
""")


_MODULE_RESULT_SERVER_SCRIPT = textwrap.dedent("""\
    import json
    import lzma
    import sys

    import pefile

    from speakeasy import Speakeasy

    port = int(sys.argv[1])
    config_path = sys.argv[2]
    bin_path = sys.argv[3]
    entry_code = bytes.fromhex(sys.argv[4])
    with open(config_path) as f:
        cfg = json.load(f)
    with lzma.open(bin_path) as f:
        data = f.read()

    se = Speakeasy(config=cfg, gdb_port=port)
    module = se.load_module(data=data)
    if entry_code:
        se.mem_write(module.base + module.ep, entry_code)
    exports = [module.base + export.address for export in pefile.PE(data=data).DIRECTORY_ENTRY_EXPORT.symbols]
    if sys.argv[5:] == ["export_fault"]:
        se.mem_write(exports[0], bytes.fromhex("a100000000"))  # mov eax, [0]
        se.mem_write(exports[1], b"\\xe9" + (exports[0] - exports[1] - 5).to_bytes(4, "little", signed=True))
    print(json.dumps(exports), flush=True)
    se.run_module(module, all_entrypoints=True)
    print(json.dumps([run.error.type if run.error else None for run in se.get_report().entry_points]), flush=True)
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
    return port, proc


def _stop_server(proc: subprocess.Popen):
    if proc.poll() is None:
        proc.terminate()
    elif proc.returncode != 0 and proc.stderr is not None and not proc.stderr.closed:
        sys.stderr.write(proc.stderr.read().decode(errors="replace"))
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
    yield port, proc
    _stop_server(proc)


@pytest.fixture
def gdb_memory_fault_emulator(request):
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    shellcode, _, arch = request.param.partition(":")
    proc = subprocess.Popen(
        [sys.executable, "-c", _MEMORY_FAULT_SERVER_SCRIPT, str(port), config_path, shellcode, arch or "x86"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    address = int(proc.stdout.readline(), 16)
    yield port, proc, address
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
    yield port, proc
    _stop_server(proc)


@pytest.fixture
def gdb_exit_process_emulator():
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    proc = subprocess.Popen(
        [sys.executable, "-c", _EXIT_PROCESS_SERVER_SCRIPT, str(port), config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    yield port, proc
    _stop_server(proc)


@pytest.fixture
def gdb_library_load_emulator():
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    proc = subprocess.Popen(
        [sys.executable, "-c", _LIBRARY_LOAD_SERVER_SCRIPT, str(port), config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    yield port
    _stop_server(proc)


@pytest.fixture
def gdb_watchpoint_emulator():
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    proc = subprocess.Popen(
        [sys.executable, "-c", _WATCHPOINT_SERVER_SCRIPT, str(port), config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    address, scratch = (int(value, 16) for value in proc.stdout.readline().split())
    yield port, proc, address, scratch
    _stop_server(proc)


def _start_shellcode_server(code: str) -> tuple[int, subprocess.Popen, int, int]:
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    proc = subprocess.Popen(
        [sys.executable, "-c", _SHELLCODE_RESULT_SERVER_SCRIPT, str(port), config_path, code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    address, scratch = (int(value, 16) for value in proc.stdout.readline().split())
    return port, proc, address, scratch


@pytest.fixture
def gdb_shellcode_emulator(request):
    port, proc, address, scratch = _start_shellcode_server(request.param)
    yield port, proc, address, scratch
    _stop_server(proc)


@pytest.fixture
def gdb_module_result_emulator(request):
    """Start dll_test_x86 with its entry point code replaced by request.param, if any."""
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    bin_path = os.path.join(TESTS_DIR, "bins", "dll_test_x86.dll.xz")
    proc = subprocess.Popen(
        [sys.executable, "-c", _MODULE_RESULT_SERVER_SCRIPT, str(port), config_path, bin_path, request.param],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    exports = json.loads(proc.stdout.readline())
    yield port, proc, exports
    _stop_server(proc)


@pytest.fixture
def gdb_export_fault_emulator():
    """Start dll_test_x86 with a fault on the first export and a jump to it from the second."""
    port = _find_free_port()
    config_path = os.path.join(TESTS_DIR, "test.json")
    bin_path = os.path.join(TESTS_DIR, "bins", "dll_test_x86.dll.xz")
    proc = subprocess.Popen(
        [sys.executable, "-c", _MODULE_RESULT_SERVER_SCRIPT, str(port), config_path, bin_path, "", "export_fault"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    exports = json.loads(proc.stdout.readline())
    yield port, proc, exports
    _stop_server(proc)


def _read_server_result(proc: subprocess.Popen):
    stdout, stderr = proc.communicate(timeout=20)
    assert proc.returncode == 0, stderr.decode(errors="replace")
    return json.loads(stdout.decode().splitlines()[-1])


def test_gdb_breakpoint_stop_keeps_session_alive(gdb_emulator):
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


def test_gdb_reports_runtime_library_load(gdb_library_load_emulator):
    client = GdbRspClient(gdb_library_load_emulator)
    try:
        client.query_halt_reason()

        libraries = client.query("qXfer:libraries:read::0,4000")
        assert libraries.startswith("l<library-list")
        assert "gdbtestlib.dll" not in libraries

        stop = client.continue_()
        assert stop.startswith("T05")
        assert "library:;" in stop

        libraries = client.query("qXfer:libraries:read::0,4000")
        assert "gdbtestlib.dll" in libraries

        # The library change was reported; the next stop must not repeat it.
        client.send_no_wait("c")
        time.sleep(0.05)
        stop = client.interrupt()
        assert stop.startswith("T02")
        assert "library:;" not in stop
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


def test_gdb_kill_replies_with_an_exit_before_it_closes(gdb_pause_emulator):
    client = GdbRspClient(gdb_pause_emulator)
    try:
        client.query_halt_reason()
        assert client.query("k") == "X09"
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


@pytest.mark.parametrize(
    ("gdb_memory_fault_emulator", "fault_offset"),
    [
        pytest.param("a110000000c3", 0, id="invalid_read"),
        pytest.param("a310000000c3", 0, id="invalid_write"),
        pytest.param("b810000000ffe0", None, id="invalid_fetch"),
    ],
    indirect=["gdb_memory_fault_emulator"],
)
def test_gdb_stops_at_handled_memory_fault(gdb_memory_fault_emulator, fault_offset):
    port, proc, address = gdb_memory_fault_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.continue_().startswith("T0b")
        expected_pc = 0x10 if fault_offset is None else address + fault_offset
        assert client.read_x86_registers().eip == expected_pc
        assert client.continue_() == "X0b"
        assert proc.wait(timeout=10) == 0
    finally:
        client.close()


@pytest.mark.parametrize("gdb_memory_fault_emulator", ["cc:amd64"], indirect=True)  # int3
def test_gdb_stops_at_unhandled_x64_cpu_exception(gdb_memory_fault_emulator):
    port, proc, address = gdb_memory_fault_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.continue_().startswith("T0b")
        assert client.continue_() == "X0b"
        assert proc.wait(timeout=10) == 0
    finally:
        client.close()


def test_gdb_reports_clean_exit(gdb_exit_emulator):
    port, proc = gdb_exit_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        stop = client.continue_()
        assert stop.startswith("T05")
        assert client.read_memory(client.read_x86_registers().esp, 4)
        assert client.continue_() == "W00"
        assert proc.wait(timeout=10) == 0
    finally:
        client.close()


def test_gdb_stops_after_exit_process_before_exit_reply(gdb_exit_process_emulator):
    port, proc = gdb_exit_process_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        start = client.read_x86_registers().eip

        stop = client.continue_()
        assert stop.startswith("T05")
        assert "swbreak:;" not in stop
        assert "hwbreak:;" not in stop

        # The final stop keeps the state left by ExitProcess: the stack still
        # holds the return address of the call.
        esp = client.read_x86_registers().esp
        assert struct.unpack("<I", bytes.fromhex(client.read_memory(esp, 4)))[0] == start + 9
        assert client.read_memory(start, 2) == "6a00"

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


@pytest.mark.parametrize("resume", ["continue", "step"])
def test_gdb_write_watchpoint_resume_does_not_repeat_guest_side_effect(gdb_watchpoint_emulator, resume):
    port, proc, address, scratch = gdb_watchpoint_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.read_x86_registers().eip == address
        assert client.read_memory(scratch, 4) == "00000000"
        assert client.query(f"Z2,{scratch:x},4") == "OK"
        stop = client.continue_() if resume == "continue" else client.step()
        assert stop.startswith("T05") and f"watch:{scratch:x};" in stop, stop
        # The stop follows the completed write, so resuming does not repeat it.
        assert client.read_x86_registers().eip == address + 6
        assert client.read_memory(scratch, 4) == "01000000"
        assert client.query(f"z2,{scratch:x},4") == "OK"
        ret = address + 11
        assert client.query(f"Z0,{ret:x},1") == "OK"
        stop = client.continue_()
        assert stop.startswith("T05") and "swbreak:;" in stop, stop
        regs = client.read_x86_registers()
        assert (regs.eip, regs.eax) == (ret, 42)
        assert client.read_memory(scratch, 4) == "01000000"
        assert client.query(f"z0,{ret:x},1") == "OK"
        assert client.continue_().startswith("T05")
        assert client.read_memory(scratch, 4) == "01000000"
        assert client.continue_() == "W00"
        assert proc.wait(timeout=10) == 0
    finally:
        client.close()


@pytest.mark.parametrize(
    "gdb_shellcode_emulator", ["b900001000e2fec3"], indirect=True
)  # mov ecx, 0x100000; loop $; ret
def test_gdb_client_disconnect_while_running_detaches(gdb_shellcode_emulator):
    port, proc, address, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    client.query_halt_reason()
    assert client.query(f"Z0,{address + 7:x},1") == "OK"
    client.send_no_wait("c")
    client.close()
    assert _read_server_result(proc)["error"] is None


def _seh_declines(fault: str) -> str:
    # push handler; push fs:[0]; mov fs:[0], esp; <fault>; ret
    code = "6811111111" + "64ff3500000000" + "64892500000000" + fault + "c3"
    # The handler at offset 0x40: mov eax, ExceptionContinueSearch; ret
    return code + "90" * (0x40 - len(code) // 2) + "b801000000c3"


@pytest.mark.parametrize(
    ("gdb_shellcode_emulator", "fault_offset"),
    [
        pytest.param(_seh_declines("a100000000"), 0x13, id="read"),  # mov eax, [0]
        pytest.param(_seh_declines("31c9f7f1"), 0x15, id="divide"),  # xor ecx, ecx; div ecx
    ],
    indirect=["gdb_shellcode_emulator"],
)
def test_gdb_fault_after_declining_seh_handler_stops_at_fault_once(gdb_shellcode_emulator, fault_offset):
    port, proc, address, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.continue_().startswith("T0b")
        assert client.read_x86_registers().eip == address + fault_offset
        assert client.continue_() == "X0b"
    finally:
        client.close()
    result = _read_server_result(proc)
    assert result["pc"] == address + fault_offset
    assert result["events"] == 1


@pytest.mark.parametrize("gdb_module_result_emulator", [""], indirect=True)
def test_gdb_breakpoint_on_later_run_start_hits(gdb_module_result_emulator):
    port, proc, exports = gdb_module_result_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        for address in exports:
            assert client.query(f"Z0,{address:x},1") == "OK"
        for address in exports:
            stop = client.continue_()
            assert stop.startswith("T05") and "swbreak:;" in stop
            assert client.read_x86_registers().eip == address
        assert client.continue_().startswith("T05")
        assert client.continue_() == "W00"
    finally:
        client.close()
    assert _read_server_result(proc) == [None, None, None]


@pytest.mark.parametrize("gdb_module_result_emulator", ["a100000000"], indirect=True)  # mov eax, [0]
def test_gdb_breakpoint_on_run_start_after_a_fault_hits(gdb_module_result_emulator):
    port, proc, exports = gdb_module_result_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        for address in exports:
            assert client.query(f"Z0,{address:x},1") == "OK"
        assert client.continue_().startswith("T0b")
        for address in exports:
            stop = client.continue_()
            assert stop.startswith("T05") and "swbreak:;" in stop
            assert client.read_x86_registers().eip == address
        assert client.continue_().startswith("T05")
        assert client.continue_() == "W00"
    finally:
        client.close()
    assert _read_server_result(proc) == ["invalid_read", None, None]


@pytest.mark.parametrize("gdb_module_result_emulator", ["a100000000"], indirect=True)  # mov eax, [0]
def test_gdb_breakpoint_on_fault_pc_does_not_hide_later_run_starts(gdb_module_result_emulator):
    port, proc, exports = gdb_module_result_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        entry = client.read_x86_registers().eip
        for address in [entry, *exports]:
            assert client.query(f"Z0,{address:x},1") == "OK"
        assert client.continue_().startswith("T0b")
        for address in exports:
            stop = client.continue_()
            assert stop.startswith("T05") and "swbreak:;" in stop
            assert client.read_x86_registers().eip == address
    finally:
        client.close()


def test_gdb_breakpoint_at_fault_pc_hits_in_the_next_run(gdb_export_fault_emulator):
    port, proc, exports = gdb_export_fault_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.query(f"Z0,{exports[0]:x},1") == "OK"
        assert "swbreak:;" in client.continue_()
        assert client.read_x86_registers().eip == exports[0]
        assert client.continue_().startswith("T0b")
        assert client.read_x86_registers().eip == exports[0]
        assert "swbreak:;" in client.continue_()
        assert client.read_x86_registers().eip == exports[0]
    finally:
        client.close()


@pytest.mark.parametrize("gdb_shellcode_emulator", ["b907000000cd29c3"], indirect=True)  # mov ecx, 7; int 0x29; ret
def test_gdb_stops_at_fastfail(gdb_shellcode_emulator):
    port, proc, address, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.continue_().startswith("T0b")
        assert client.read_x86_registers().eip == address + 7
        assert client.continue_() == "X0b"
    finally:
        client.close()
    assert _read_server_result(proc)["error"] == "unhandled_interrupt"


@pytest.mark.parametrize("gdb_module_result_emulator", ["a100000000"], indirect=True)  # mov eax, [0]
def test_gdb_fault_in_first_run_still_gives_final_stop(gdb_module_result_emulator):
    port, proc, _ = gdb_module_result_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.continue_().startswith("T0b")
        assert client.continue_().startswith("T05")
        assert client.continue_() == "W00"
    finally:
        client.close()
    assert _read_server_result(proc) == ["invalid_read", None, None]


@pytest.mark.parametrize("gdb_shellcode_emulator", ["c3"], indirect=True)  # ret
def test_gdb_step_past_last_instruction_exits(gdb_shellcode_emulator):
    port, proc, _, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        # The step completes the only run, so its stop is the final stop.
        assert client.step().startswith("T05")
        assert client.step() == "W00"
    finally:
        client.close()
    assert _read_server_result(proc)["error"] is None


@pytest.mark.parametrize("gdb_shellcode_emulator", ["a322222222c3"], indirect=True)  # mov [scratch], eax; ret
def test_gdb_watch_stop_reports_watched_address(gdb_shellcode_emulator):
    port, proc, _, scratch = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        # The write of [scratch, scratch + 4) begins before the watched range.
        assert client.query(f"Z2,{scratch + 2:x},4") == "OK"
        assert f"watch:{scratch + 2:x};" in client.continue_()
    finally:
        client.close()


# mov ecx, 0x10000000; loop: mov [scratch], ecx; dec ecx; jnz loop; ret
_LONG_SCRATCH_LOOP = "b900000010890d222222224975f7c3"


@pytest.mark.parametrize(
    ("gdb_shellcode_emulator", "insert", "kind"),
    [
        pytest.param(_LONG_SCRATCH_LOOP, "Z0,{loop:x},1", "swbreak:;", id="breakpoint"),
        pytest.param(_LONG_SCRATCH_LOOP, "Z2,{scratch:x},4", "watch:", id="watchpoint"),
    ],
    indirect=["gdb_shellcode_emulator"],
)
def test_gdb_stop_inserted_after_code_ran_hits(gdb_shellcode_emulator, insert, kind):
    port, _, address, scratch = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        # The loop runs without debugger hooks until the interrupt.
        client.send_no_wait("c")
        time.sleep(0.2)
        assert client.interrupt().startswith("T02")
        assert client.query(insert.format(loop=address + 5, scratch=scratch)) == "OK"
        assert kind in client.continue_()
    finally:
        client.close()


@pytest.mark.parametrize("gdb_shellcode_emulator", ["a100000000c3"], indirect=True)  # mov eax, [0]; ret
@pytest.mark.parametrize("resume", ["C0b", "S0b", "vCont;C0b:1", "vCont;S0b:1"])
def test_gdb_resume_with_signal_after_fault(gdb_shellcode_emulator, resume):
    port, proc, address, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert "C" in client.query("vCont?").split(";")
        assert "S" in client.query("vCont?").split(";")
        assert client.continue_().startswith("T0b")
        # A client that passes the fault signal to the target resumes it.
        assert client.query(resume) == "X0b"
    finally:
        client.close()
    assert _read_server_result(proc)["error"] == "invalid_read"


@pytest.mark.parametrize("gdb_shellcode_emulator", ["9090c3"], indirect=True)  # nop; nop; ret
@pytest.mark.parametrize("resume", ["S05;{address:x}", "C05;{address:x}"])
def test_gdb_resume_with_signal_at_address(gdb_shellcode_emulator, resume):
    port, _, address, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.query(f"Z0,{address + 2:x},1") == "OK"
        assert client.query(resume.format(address=address + 1)).startswith("T05")
        assert client.read_x86_registers().eip == address + 2
    finally:
        client.close()


@pytest.mark.parametrize("gdb_shellcode_emulator", ["90f490c3"], indirect=True)  # nop; hlt; nop; ret
@pytest.mark.parametrize("step", [False, True], ids=["continue", "step"])
def test_gdb_stops_at_hlt(gdb_shellcode_emulator, step):
    port, proc, address, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        if step:
            assert client.step().startswith("T05")
            assert client.step().startswith("T0b")
        else:
            assert client.continue_().startswith("T0b")
        assert client.read_x86_registers().eip == address + 1
        assert client.continue_() == "X0b"
    finally:
        client.close()
    assert _read_server_result(proc)["error"] == "privileged_instruction"


# mov eax, address + 0x40; mov byte [eax + 1], 2; nop...; at 0x40: mov al, 1; ret
_PATCH_OWN_PAGE = "b811111111c6400102" + "90" * (0x40 - 9) + "b001c3"


@pytest.mark.parametrize("gdb_shellcode_emulator", [pytest.param(_PATCH_OWN_PAGE, id="patch")], indirect=True)
def test_gdb_step_over_store_into_own_code_page(gdb_shellcode_emulator):
    port, proc, address, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.step().startswith("T05")
        assert client.step().startswith("T05")
        assert client.read_x86_registers().eip == address + 9
        assert client.read_memory(address + 0x40, 3) == "b002c3"
        assert client.continue_().startswith("T05")
        assert client.continue_() == "W00"
    finally:
        client.close()
    assert _read_server_result(proc)["error"] is None


def _load_patch_own_page(se: Speakeasy) -> int:
    address = se.load_shellcode(data=b"\x90" * 0x50, arch="x86")
    code = bytes.fromhex(_PATCH_OWN_PAGE).replace(struct.pack("<I", 0x11111111), struct.pack("<I", address + 0x40))
    se.mem_write(address, code)
    return address


def test_gdb_step_over_store_into_own_code_page_counts_it_as_a_run_does(config):
    config["max_instructions"] = 1000
    with Speakeasy(config=config) as se:
        se.run_shellcode(_load_patch_own_page(se))
        (run,) = se.get_report().entry_points
        assert run.error is None
        count = run.instr_count

    # The limit that the run without a debugger needs exactly
    config["max_instructions"] = count
    port = _find_free_port()
    with Speakeasy(config=config, gdb_port=port) as se:
        address = _load_patch_own_page(se)
        with _serve(se, port, address) as client:
            assert client.step().startswith("T05")
            assert client.step().startswith("T05")
            assert client.read_x86_registers().eip == address + 9
            assert client.continue_().startswith("T05")
            assert client.continue_() == "W00"
        (run,) = se.get_report().entry_points
        assert (run.error, run.instr_count) == (None, count)


# mov ecx, 0x20000; loop: mov [scratch], ecx; dec ecx; jnz loop; ret
@pytest.mark.parametrize("gdb_shellcode_emulator", ["b900000200890d222222224975f7c3"], indirect=True)
def test_gdb_many_breakpoints_keep_execution_fast(gdb_shellcode_emulator):
    port, _, address, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        for i in range(2000):
            assert client.query(f"Z0,{0x60000000 + i * 0x10:x},1") == "OK"
        assert client.query(f"Z0,{address + 14:x},1") == "OK"
        started = time.monotonic()
        assert "swbreak:" in client.continue_()
        assert time.monotonic() - started < 5
    finally:
        client.close()


# mov ecx, 0x20000000; loop: dec ecx; jnz loop; ret
_LONG_LOOP = "b9000000204975fdc3"


def _time_continue(code: str, breakpoint_offset: int | None) -> tuple[float, str, int]:
    port, proc, address, _ = _start_shellcode_server(code)
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        if breakpoint_offset is not None:
            assert client.query(f"Z0,{address + breakpoint_offset:x},1") == "OK"
        started = time.monotonic()
        stop = client.continue_()
        elapsed = time.monotonic() - started
        return elapsed, stop, client.read_x86_registers().eip - address
    finally:
        client.close()
        _stop_server(proc)


def test_gdb_breakpoint_keeps_code_outside_it_fast():
    baseline, stop, _ = _time_continue(_LONG_LOOP, None)
    assert stop.startswith("T05") and "swbreak" not in stop
    elapsed, stop, offset = _time_continue(_LONG_LOOP, 8)
    assert stop.startswith("T05") and "swbreak:;" in stop
    assert offset == 8
    assert elapsed < 3 * baseline, (elapsed, baseline)


def test_gdb_resumes_after_a_timeout_log_it_once(config, caplog):
    config["timeout"] = 0.2
    port = _find_free_port()
    se = Speakeasy(config=config, gdb_port=port)
    try:
        base = se.load_shellcode(data=b"\xeb\xfe", arch="x86")
        server = threading.Thread(target=se.run_shellcode, args=(base,))
        server.start()
        client = GdbRspClient(port)
        try:
            assert client.query_halt_reason().startswith(("S05", "T05"))
            stops = [client.continue_(), client.continue_(), client.step(), client.query("vCont;c")]
            client.send_no_wait("k")
        finally:
            client.close()
        server.join(timeout=10)
        assert not server.is_alive()
    finally:
        se.shutdown()

    assert all(stop.startswith("T05") for stop in stops)
    assert sum("Timeout of" in record.message for record in caplog.records) == 1


@contextmanager
def _serve(se: Speakeasy, port: int, address: int) -> Iterator[GdbRspClient]:
    """Run the shellcode at address in a thread under the GDB server of se, and connect to it."""
    server = threading.Thread(target=se.run_shellcode, args=(address,))
    server.start()
    client = GdbRspClient(port)
    try:
        assert client.query_halt_reason().startswith(("S05", "T05"))
        yield client
    finally:
        client.close()
        server.join(timeout=10)
    assert not server.is_alive()


def test_gdb_breakpoint_instruction_counts_once_toward_the_instruction_limit(config):
    config["max_instructions"] = 6
    port = _find_free_port()
    with Speakeasy(config=config, gdb_port=port) as se:
        # loop: nop; nop; nop; nop; jmp loop
        address = se.load_shellcode(data=bytes.fromhex("90909090ebfa"), arch="x86")
        with _serve(se, port, address) as client:
            assert client.query(f"Z0,{address + 2:x},1") == "OK"
            assert "swbreak:" in client.continue_()
            assert client.read_x86_registers().eip == address + 2
            # nop, nop, then the nop at the breakpoint, nop, jmp, nop: the next one is the seventh.
            stop = client.continue_()
            assert stop.startswith("T05") and "swbreak:" not in stop
            assert client.read_x86_registers().eip == address + 1
            client.kill()


def test_gdb_resume_at_another_pc_runs_the_code_there_instead_of_ending_the_run(config):
    port = _find_free_port()
    with Speakeasy(config=config, gdb_port=port) as se:
        address = se.load_shellcode(data=b"\x90" * 0x20, arch="x86")
        scratch = se.mem_alloc(0x1000)
        code = b"\xc3"  # ret
        code += b"\x90" * 15
        code += b"\xc6\x05" + struct.pack("<I", scratch) + b"\x01"  # mov byte [scratch], 1
        code += b"\x83\xec\x04"  # sub esp, 4
        code += b"\xc3"  # ret
        se.mem_write(address, code)
        with _serve(se, port, address) as client:
            esp = client.read_x86_registers().esp
            assert client.query(f"Z3,{esp:x},4") == "OK"
            # The ret reads the return address and stops at the return hook with the end of the run pending.
            assert f"rwatch:{esp:x}" in client.continue_()
            assert client.query(f"z3,{esp:x},4") == "OK"
            assert client.query(f"P8={struct.pack('<I', address + 0x10).hex()}") == "OK"
            assert client.query(f"Z0,{address + 0x1A:x},1") == "OK"
            assert "swbreak:" in client.continue_()
            assert client.read_memory(scratch, 1) == "01"
            assert client.continue_().startswith("T05")
            assert client.continue_() == "W00"
        (run,) = se.get_report().entry_points
        assert run.error is None


@pytest.mark.parametrize("gdb_shellcode_emulator", ["89e0ffe0"], indirect=True)  # mov eax, esp; jmp eax
def test_gdb_stops_at_fetch_from_non_executable_page(gdb_shellcode_emulator):
    port, proc, _, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        esp = client.read_x86_registers().esp
        assert client.continue_().startswith("T0b")
        assert client.read_x86_registers().eip == esp
        assert client.continue_() == "X0b"
    finally:
        client.close()
    assert _read_server_result(proc)["error"] == "invalid_protect_fetch"


def test_gdb_stops_at_fault_in_api_handler_that_runs_guest_code(config):
    port = _find_free_port()
    with Speakeasy(config=config, gdb_port=port) as se:
        record = 0xDEAD0000
        address = se.load_shellcode(data=b"\xcc" * 0x100, arch="amd64")
        unwind = get_api(se, "ntdll", "RtlUnwindEx")
        se.mem_write(address, guest_call(8, unwind, 0, 0, record, 0, 0, 0) + b"\xb8\x2a\0\0\0\xc3")
        with _serve(se, port, address) as client:
            assert client.continue_().startswith("T0b")
            assert client.continue_() == "X0b"
        (run,) = se.get_report().entry_points
        assert run.error is not None
        assert (run.error.type, run.error.address) == ("invalid_read", record)


@pytest.mark.parametrize(("resume", "reply"), [("c", "W00"), ("D", "OK"), ("k", None)])
def test_gdb_resume_after_total_time_ends_emulation(config, resume, reply):
    config.update(timeout=0, max_total_time=0.2)
    port = _find_free_port()
    with Speakeasy(config=config, gdb_port=port) as se:
        address = se.load_shellcode(data=b"\xeb\xfe", arch="x86")  # jmp $
        with _serve(se, port, address) as client:
            assert client.continue_().startswith("T05")
            assert client.read_x86_registers().eip == address
            if reply is None:
                client.kill()
            else:
                assert client.query(resume) == reply
        (run,) = se.get_report().entry_points
        assert run.error is not None and run.error.type == "max_total_time"


@pytest.mark.parametrize(("resume", "runs"), [("D", 2), ("k", 1)])
def test_gdb_detach_at_api_handler_error_runs_the_next_runs(config, resume, runs):
    port = _find_free_port()
    with Speakeasy(config=config, gdb_port=port) as se:
        address = se.load_shellcode(data=b"\xcc" * 0x100, arch="x86")
        thread = address + 0x80
        code = guest_call(4, get_api(se, "kernel32", "CreateThread"), 0, 0, thread, 0, 0, 0)
        # The handler reads its source at 0x10, which is not mapped.
        code += guest_call(4, get_api(se, "kernel32", "RtlMoveMemory"), 0x1000, 0x10, 4) + b"\xc3"
        se.mem_write(address, code)
        se.mem_write(thread, b"\xb8\x2a\0\0\0\xc3")  # mov eax, 42; ret
        with _serve(se, port, address) as client:
            assert client.continue_().startswith("T0b")
            if resume == "D":
                assert client.query(resume) == "OK"
            else:
                client.kill()
        reported = se.get_report().entry_points
        assert len(reported) == runs
        assert reported[0].error is not None
        if runs == 2:
            assert (reported[1].error, reported[1].ret_val) == (None, 42)


@pytest.mark.parametrize("gdb_shellcode_emulator", ["c3"], indirect=True)  # ret
@pytest.mark.parametrize(("resume", "reply"), [("D", "OK"), ("k", None)])
def test_gdb_leave_at_the_final_stop(gdb_shellcode_emulator, resume, reply):
    port, proc, _, _ = gdb_shellcode_emulator
    client = GdbRspClient(port)
    try:
        client.query_halt_reason()
        assert client.continue_().startswith("T05")
        if reply is None:
            client.send_no_wait(resume)
        else:
            assert client.query(resume) == reply
    finally:
        client.close()
    assert _read_server_result(proc)["error"] is None


def test_gdb_stops_at_read_of_the_api_trap_reservation(config):
    port = _find_free_port()
    with Speakeasy(config=config, gdb_port=port) as se:
        address = se.load_shellcode(data=b"\x90" * 6, arch="x86")
        trap_base = se.emu.api_registry.trap_base
        se.mem_write(address, b"\xa1" + struct.pack("<I", trap_base) + b"\xc3")  # mov eax, [trap_base]; ret
        with _serve(se, port, address) as client:
            assert client.continue_().startswith("T0b")
            assert client.read_x86_registers().eip == address
            assert client.continue_() == "X0b"
        (run,) = se.get_report().entry_points
        assert run.error is not None
        assert (run.error.type, run.error.address) == ("invalid_read", trap_base)


def test_gdb_step_into_an_api_that_uses_up_the_total_time(config):
    config.update(timeout=0, max_total_time=0.05)
    port = _find_free_port()
    with Speakeasy(config=config, gdb_port=port) as se:
        # mov eax, GetTickCount; call eax; ret
        address = se.load_shellcode(data=b"\xb8\0\0\0\0\xff\xd0\xc3", arch="x86")
        se.mem_write(address + 1, se.emu.get_proc("kernel32", "GetTickCount").to_bytes(4, "little"))

        def slow_tick_count(e, api, original, args):
            time.sleep(0.1)
            return 1

        se.add_api_hook(slow_tick_count, "kernel32", "GetTickCount", argc=0)
        with _serve(se, port, address) as client:
            # mov, call, then the API stub: mov edi, edi; push ebp; mov ebp, esp; pop ebp; jmp trap
            for _ in range(7):
                assert client.step().startswith("T05")
            assert client.read_x86_registers().eip == address + 7
            assert client.continue_() == "W00"
        (run,) = se.get_report().entry_points
        assert run.error is not None and run.error.type == "max_total_time"
