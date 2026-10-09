"""Debug GetProcAddress-returned API entries through a real subprocess GDB RSP session."""

import json
import os
import struct
import subprocess
import sys
import textwrap
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.test_gdb import GdbRspClient, _find_free_port, _stop_server, _wait_for_port

_SERVER_SCRIPT = textwrap.dedent(r"""
    import json
    import struct
    import sys
    import threading
    import time
    from pathlib import Path

    from speakeasy import Speakeasy
    from speakeasy.winenv import arch

    port, config_path, architecture, metadata_path, result_path, mode = sys.argv[1:]
    cfg = json.loads(Path(config_path).read_text())
    se = Speakeasy(config=cfg, gdb_port=int(port))
    shutdown = threading.Event()
    hook_thread = None
    try:
        caller = se.load_shellcode(data=b"\x90" * 128, arch=architecture)
        emu = se.emu
        for dll in ("ntdll", "kernel32", "kernelbase"):
            emu.load_module_by_name(dll)
        # GetProcAddress treats pointers below 64 KiB as ordinals.
        counter = se.mem_alloc(0x1000, base=0x20000000)
        se.mem_write(counter, b"\0" * 4)
        name = counter + 16
        dll, api_name = ("gdb_unknown_abi", "SuspendedCall") if mode == "unknown" else ("kernel32", "GetTickCount")
        se.mem_write(name, api_name.encode() + b"\0")
        calls = []

        def handler(_se, api, original, args):
            if mode == "timeout":
                time.sleep(0.2)
            calls.append({"api": api, "args": list(args), "sp": emu.get_stack_ptr()})
            emu.mem_write(counter, struct.pack("<I", len(calls)))
            if mode == "callback":
                emu.api.load_api_handler("user32").setup_callback(callback, [3], caller_argv=args)
            if mode == "handler_fault":
                raise RuntimeError("hook failure")
            return 0x13579

        if mode == "unknown":
            # The test creates the signal file after it observes the
            # unsupported stop; the hook is registered while execution is paused.
            signal = Path(metadata_path).with_suffix(".install")
            ready = Path(metadata_path).with_suffix(".ready")

            def install_when_signalled():
                while not shutdown.wait(0.01):
                    if signal.exists():
                        se.add_api_hook(handler, dll, api_name, argc=1, call_conv=arch.CALL_CONV_CDECL)
                        ready.write_text("ready")
                        return

            hook_thread = threading.Thread(target=install_when_signalled, daemon=True)
            hook_thread.start()
        else:
            se.add_api_hook(handler, dll, api_name, argc=0)
        entry = emu.get_proc(dll, api_name)
        resolver = emu.get_proc("kernel32", "GetProcAddress")
        module = emu.get_mod_by_name(dll)
        if architecture == "x86":
            # push name; push HMODULE; call GetProcAddress; call returned EAX
            code = (b"\x68" + struct.pack("<I", name)
                    + b"\x68" + struct.pack("<I", module.base)
                    + b"\xb8" + struct.pack("<I", resolver) + b"\xff\xd0\xff\xd0")
            stack_adjust = 0
            epilogue = b"\x90\xc3"
        else:
            # Reserve Windows x64 shadow space and maintain call alignment.
            code = (b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", module.base)
                    + b"\x48\xba" + struct.pack("<Q", name)
                    + b"\x48\xb8" + struct.pack("<Q", resolver) + b"\xff\xd0\xff\xd0")
            stack_adjust = 40
            epilogue = b"\x90\x48\x83\xc4\x28\xc3"
        if mode == "unknown":
            # Give the unknown ABI an observable argument.
            argument = 0x2468
            setup = (b"\x68" + struct.pack("<I", argument)) if architecture == "x86" else (
                b"\x48\xb9" + struct.pack("<Q", argument)
            )
            code = code[:-2] + setup + code[-2:]
            if architecture == "x86":
                stack_adjust = 4
                epilogue = b"\x90\x83\xc4\x04\xc3"
        if mode in ("budget", "timeout"):
            # mov eax, entry; call eax; jmp back: call the API forever.
            code = (b"\xb8" + struct.pack("<I", entry)) if architecture == "x86" else (
                b"\x48\xb8" + struct.pack("<Q", entry)
            )
            code += b"\xff\xd0"
            epilogue = b"\xeb" + bytes([(-len(code) - 2) & 0xff])
            stack_adjust = 0
        callback = caller + 64
        se.mem_write(callback, b"\xb8\x63\0\0\0" + (
            b"\xc2\x04\x00" if architecture == "x86" else b"\xc3"
        ))
        redirect = caller + 96
        se.mem_write(redirect, b"\xb8\x2a\0\0\0\xc3")
        return_address = caller + len(code)
        se.mem_write(caller, code + epilogue)
        Path(metadata_path).write_text(json.dumps({
            "caller": caller, "entry": entry, "counter": counter, "return_address": return_address,
            "stack_adjust": stack_adjust, "redirect": redirect, "callback": callback,
        }))
        se.run_shellcode(caller)
        run = se.get_report().entry_points[0]
        Path(result_path).write_text(json.dumps({
            "calls": calls, "counter": int.from_bytes(se.mem_read(counter, 4), "little"),
            "return_value": emu.get_return_val(), "sp": emu.get_stack_ptr(),
            "instructions": run.instr_count,
            "error_type": run.error.type if run.error else None,
        }))
    finally:
        shutdown.set()
        if hook_thread is not None:
            hook_thread.join(timeout=1)
        se.shutdown()
""")


@dataclass
class ApiTarget:
    client: GdbRspClient
    proc: subprocess.Popen
    architecture: str
    metadata: dict
    result_path: Path
    metadata_path: Path

    @property
    def ptr_size(self):
        return 4 if self.architecture == "x86" else 8

    def registers(self):
        """Return PC, SP and accumulator from the RSP core register layout."""
        if self.architecture == "x86":
            regs = self.client.read_x86_registers()
            return regs.eip, regs.esp, regs.eax
        core = struct.unpack("<17Q", bytes.fromhex(self.client.read_registers())[:136])
        return core[16], core[7], core[0]  # RIP, RSP, RAX

    def counter(self):
        return int.from_bytes(bytes.fromhex(self.client.read_memory(self.metadata["counter"], 4)), "little")

    def result(self):
        stdout, stderr = self.proc.communicate(timeout=10)
        assert self.proc.returncode == 0, (stdout.decode(errors="replace"), stderr.decode(errors="replace"))
        return json.loads(self.result_path.read_text())

    def finish(self):
        # Speakeasy reports one final inspectable stop before the exit reply.
        assert self.client.continue_().startswith("T05")
        assert self.client.continue_() == "W00"
        return self.result()

    def kill(self):
        self.client.send_no_wait("k")
        return self.result()


@contextmanager
def _api_target(tmp_path, config, architecture, mode):
    config["timeout"] = 0.5 if mode == "timeout" else 10
    config["max_instructions"] = 17 if mode == "budget" else 1000
    tmp_path.mkdir(parents=True, exist_ok=True)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    metadata_path = tmp_path / "metadata.json"
    result_path = tmp_path / "result.json"
    port = _find_free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _SERVER_SCRIPT,
            str(port),
            str(config_path),
            architecture,
            str(metadata_path),
            str(result_path),
            mode,
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    client = None
    try:
        _wait_for_port(port, proc, timeout=15)
        client = GdbRspClient(port, timeout=5)
        assert client.query_halt_reason().startswith(("S05", "T05"))
        yield ApiTarget(client, proc, architecture, json.loads(metadata_path.read_text()), result_path, metadata_path)
    finally:
        if client is not None:
            client.close()
        _stop_server(proc)
        _, stderr = proc.communicate(timeout=5)
        if stderr:
            print(stderr.decode(errors="replace"))


@pytest.fixture(params=["x86", "x64"])
def api_target(request, tmp_path, config):
    with _api_target(tmp_path, config, request.param, "known") as target:
        yield target


@pytest.fixture(params=["x86", "x64"])
def unknown_api_target(request, tmp_path, config):
    with _api_target(tmp_path, config, request.param, "unknown") as target:
        yield target


@pytest.fixture
def launch(tmp_path, config):
    sessions = iter(range(1 << 16))

    def start(mode, architecture="x86"):
        return _api_target(tmp_path / str(next(sessions)), config, architecture, mode)

    return start


def _break_at_entry(target):
    client = target.client
    entry = target.metadata["entry"]
    pc, initial_sp, _ = target.registers()
    assert pc == target.metadata["caller"]
    assert target.counter() == 0
    assert client.query(f"Z0,{entry:x},1") == "OK"
    stop = client.continue_()
    assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
    pc, entry_sp, returned_entry = target.registers()
    # The accumulator still holds the guest GetProcAddress result.
    assert pc == returned_entry == entry
    assert entry_sp == initial_sp - target.metadata["stack_adjust"] - target.ptr_size
    assert target.counter() == 0
    saved_return = bytes.fromhex(client.read_memory(entry_sp, target.ptr_size))
    assert int.from_bytes(saved_return, "little") == target.metadata["return_address"]
    return initial_sp, entry_sp


def test_gdb_steps_api_entry_before_dispatch_and_returns_once(api_target):
    target = api_target
    client = target.client
    entry = target.metadata["entry"]
    return_address = target.metadata["return_address"]
    initial_sp, entry_sp = _break_at_entry(target)
    # Keep the breakpoint installed: single-step must resume past this stop.
    # Each step stays in the public entry bytes until one step completes the
    # call and stops on the caller's return address.
    for _ in range(8):
        assert client.step().startswith("T05")
        pc, sp, result = target.registers()
        if pc == return_address:
            break
        assert entry < pc < entry + 16 and sp == entry_sp, (hex(pc), hex(entry))
        assert target.counter() == 0
    else:
        pytest.fail("stepping did not complete the API call")
    assert (sp, result) == (entry_sp + target.ptr_size, 0x13579)
    assert target.counter() == 1
    assert client.query(f"z0,{entry:x},1") == "OK"
    report = target.finish()
    assert report["calls"] == [{"api": "kernel32.GetTickCount", "args": [], "sp": entry_sp}]
    assert report["return_value"] == 0x13579
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_host_patch_api_entry_executes_guest_bytes(launch):
    with launch("known") as target:
        client = target.client
        entry = target.metadata["entry"]
        initial_sp, entry_sp = _break_at_entry(target)
        # mov eax, 42; ret replaces the start of the entry.
        patch = bytes.fromhex("b82a000000c3")
        assert client.query(f"M{entry:x},{len(patch):x}:{patch.hex()}") == "OK"
        assert client.query(f"z0,{entry:x},1") == "OK"
        return_address = target.metadata["return_address"]
        assert client.query(f"Z0,{return_address:x},1") == "OK"
        stop = client.continue_()
        assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
        assert target.registers() == (return_address, entry_sp + target.ptr_size, 42)
        assert target.counter() == 0
        assert client.query(f"z0,{return_address:x},1") == "OK"
        report = target.finish()
        assert report["calls"] == []
        assert report["return_value"] == 42
        assert report["sp"] == initial_sp + target.ptr_size


def _read_call_frame(target, sp):
    # x86 return slot + argument; x64 return slot + caller's shadow space.
    size = 8 if target.ptr_size == 4 else 40
    return bytes.fromhex(target.client.read_memory(sp, size))


def _suspend_unknown_call(target):
    initial_sp, entry_sp = _break_at_entry(target)
    entry = target.metadata["entry"]
    assert target.client.query(f"z0,{entry:x},1") == "OK"
    before = target.registers()
    stack = _read_call_frame(target, entry_sp)
    if target.ptr_size == 4:
        assert int.from_bytes(stack[4:8], "little") == 0x2468
    # The unsupported stop puts PC back at the public entry. Repeated resumes
    # must suspend the same call without guessing its ABI or consuming stack.
    for _ in range(2):
        stop = target.client.continue_()
        assert stop.startswith("T05"), (stop, target.registers())
        assert "swbreak:;" not in stop and "hwbreak:;" not in stop
        assert target.registers() == before
        assert _read_call_frame(target, entry_sp) == stack
        assert target.counter() == 0
    return initial_sp, entry_sp


def _install_paused_hook(target):
    target.metadata_path.with_suffix(".install").write_text("install")
    ready = target.metadata_path.with_suffix(".ready")
    deadline = time.monotonic() + 5
    while not ready.exists():
        assert target.proc.poll() is None, "server exited while installing the hook"
        assert time.monotonic() < deadline, "server did not install the hook within 5 seconds"
        time.sleep(0.01)
    assert target.counter() == 0


def test_gdb_unknown_abi_resumes_after_hook_registration(unknown_api_target):
    target = unknown_api_target
    initial_sp, entry_sp = _suspend_unknown_call(target)
    _install_paused_hook(target)
    assert target.client.step().startswith("T05")
    assert target.registers() == (target.metadata["return_address"], entry_sp + target.ptr_size, 0x13579)
    assert target.counter() == 1
    report = target.finish()
    assert report["calls"] == [{"api": "gdb_unknown_abi.SuspendedCall", "args": [0x2468], "sp": entry_sp}]
    assert report["return_value"] == 0x13579
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_pc_redirect_abandons_unknown_abi_call(launch):
    with launch("unknown") as target:
        client = target.client
        initial_sp, entry_sp = _suspend_unknown_call(target)
        # With a hook registered, a stale suspended call would dispatch on
        # resume instead of running the redirected code.
        _install_paused_hook(target)
        redirect = target.metadata["redirect"]
        return_address = target.metadata["return_address"]
        assert client.query(f"Z0,{return_address:x},1") == "OK"
        assert client.query(f"P8={redirect.to_bytes(4, 'little').hex()}") == "OK"
        stop = client.continue_()
        assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
        assert target.registers() == (return_address, entry_sp + target.ptr_size, 42)
        assert target.counter() == 0
        assert client.query(f"z0,{return_address:x},1") == "OK"
        report = target.finish()
        assert report["calls"] == []
        assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_patch_suspended_unknown_api_executes_revised_public_bytes(launch):
    with launch("unknown") as target:
        client = target.client
        initial_sp, entry_sp = _suspend_unknown_call(target)
        entry = target.metadata["entry"]
        # With a hook registered, a stale suspended call would dispatch on
        # resume instead of running the patched bytes.
        _install_paused_hook(target)
        patch = bytes.fromhex("b82a000000c3")
        assert client.query(f"M{entry:x},{len(patch):x}:{patch.hex()}") == "OK"
        assert client.step().startswith("T05")
        assert target.registers() == (entry + 5, entry_sp, 42)
        assert client.step().startswith("T05")
        assert target.registers() == (target.metadata["return_address"], entry_sp + target.ptr_size, 42)
        assert target.counter() == 0
        report = target.finish()
        assert report["calls"] == []
        assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_instruction_budget_ignores_breakpoints_and_persists(launch):
    outcomes = []
    for breakpoints in (False, True):
        with launch("budget") as target:
            client = target.client
            entry = target.metadata["entry"]
            if breakpoints:
                assert client.query(f"Z0,{entry:x},1") == "OK"
                for completed_calls in range(2):
                    stop = client.continue_()
                    assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
                    assert target.counter() == completed_calls
                assert client.query(f"z0,{entry:x},1") == "OK"
            stop = client.continue_()
            assert stop.startswith("T05") and "swbreak:;" not in stop, (stop, target.registers())
            exhausted = (target.registers(), target.counter())
            # An exhausted budget stays exhausted across further debugger actions.
            assert client.continue_().startswith("T05")
            assert client.step().startswith("T05")
            assert (target.registers(), target.counter()) == exhausted
            report = target.kill()
            assert report["instructions"] == 17
            assert report["counter"] == len(report["calls"]) == exhausted[1]
            outcomes.append(exhausted)
    # Breakpoint stops do not consume guest instruction budget.
    assert outcomes[0] == outcomes[1]


def test_gdb_timeout_is_shared_across_resumes_and_excludes_debugger_pause(launch):
    with launch("timeout") as target:
        client = target.client
        return_address = target.metadata["return_address"]
        assert client.query(f"Z0,{return_address:x},1") == "OK"
        for completed_calls in (1, 2):
            stop = client.continue_()
            assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
            assert target.counter() == completed_calls
            if completed_calls == 1:
                # Longer than the entire configured active execution timeout.
                time.sleep(0.6)
        assert client.query(f"z0,{return_address:x},1") == "OK"
        stop = client.continue_()
        assert stop.startswith("T05") and "swbreak:;" not in stop, (stop, target.registers())
        assert target.counter() == 3
        before = target.registers()
        assert client.continue_().startswith("T05")
        assert target.registers() == before
        report = target.kill()
        assert report["counter"] == len(report["calls"]) == 3


def test_gdb_step_callback_return_restores_api_frame(launch):
    with launch("callback") as target:
        client = target.client
        entry = target.metadata["entry"]
        callback = target.metadata["callback"]
        initial_sp, entry_sp = _break_at_entry(target)
        assert client.query(f"z0,{entry:x},1") == "OK"
        assert client.query(f"Z0,{callback:x},1") == "OK"
        stop = client.continue_()
        assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
        pc, callback_sp, _ = target.registers()
        assert pc == callback
        assert callback_sp < entry_sp
        assert target.counter() == 1
        assert client.step().startswith("T05")
        assert target.registers() == (callback + 5, callback_sp, 99)
        # Stepping the callback RET completes the API call in one action.
        assert client.step().startswith("T05")
        assert target.registers() == (target.metadata["return_address"], entry_sp + target.ptr_size, 0x13579)
        assert target.counter() == 1
        assert client.query(f"z0,{callback:x},1") == "OK"
        report = target.finish()
        assert report["counter"] == len(report["calls"]) == 1
        assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_write_watchpoint_resume_does_not_repeat_guest_side_effect(launch):
    with launch("known") as target:
        client = target.client
        entry = target.metadata["entry"]
        initial_sp, entry_sp = _break_at_entry(target)
        scratch = target.metadata["counter"] + 64
        assert client.read_memory(scratch, 4) == "00000000"
        # inc dword [scratch]; mov eax, 42; ret
        patch = b"\xff\x05" + struct.pack("<I", scratch) + bytes.fromhex("b82a000000c3")
        assert client.query(f"M{entry:x},{len(patch):x}:{patch.hex()}") == "OK"
        assert client.query(f"z0,{entry:x},1") == "OK"
        assert client.query(f"Z2,{scratch:x},4") == "OK"
        stop = client.step()
        assert stop.startswith("T05") and f"watch:{scratch:x};" in stop, (stop, target.registers())
        assert client.read_memory(scratch, 4) == "01000000"
        assert target.registers()[0:2] == (entry + 6, entry_sp)
        assert client.query(f"z2,{scratch:x},4") == "OK"
        return_address = target.metadata["return_address"]
        assert client.query(f"Z0,{return_address:x},1") == "OK"
        stop = client.continue_()
        assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
        assert target.registers() == (return_address, entry_sp + target.ptr_size, 42)
        assert client.read_memory(scratch, 4) == "01000000"
        assert client.query(f"z0,{return_address:x},1") == "OK"
        report = target.finish()
        assert report["counter"] == 0
        assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_hook_exception_reports_fault_and_signal_exit(launch):
    with launch("handler_fault") as target:
        client = target.client
        _, entry_sp = _break_at_entry(target)
        entry = target.metadata["entry"]
        frame = _read_call_frame(target, entry_sp)
        assert client.query(f"z0,{entry:x},1") == "OK"
        stop = client.continue_()
        assert stop.startswith("T0b"), (stop, target.registers())
        # The failed dispatch must not fabricate a return or pop the call frame.
        assert target.registers()[1] == entry_sp
        assert _read_call_frame(target, entry_sp) == frame
        assert target.counter() == 1
        assert client.continue_() == "X0b"
        report = target.result()
        assert report["calls"] == [{"api": "kernel32.GetTickCount", "args": [], "sp": entry_sp}]
        assert report["error_type"] is not None
