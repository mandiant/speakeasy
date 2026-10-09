"""Exercise mapped API entries through a real subprocess GDB RSP session."""

import json
import os
import struct
import subprocess
import sys
import textwrap
import time
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
    from speakeasy.windows.common import API_CALLBACK_HANDLER_ADDR

    port, config_path, architecture, metadata_path, result_path, mode = sys.argv[1:]
    cfg = json.loads(Path(config_path).read_text())
    se = Speakeasy(config=cfg, gdb_port=int(port))
    shutdown = threading.Event()
    hook_thread = None
    try:
        # Loading shellcode establishes the architecture before mapping APIs.
        caller = se.load_shellcode(data=b"\x90" * 128, arch=architecture)
        emu = se.emu
        # Finish mapping core images before shellcode process/PEB setup.
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
            if mode in ("callback", "callback_interrupt_budget"):
                emu.api.load_api_handler("user32").setup_callback(callback, [3], caller_argv=args)
            return 0x13579

        if mode not in ("unknown", "handler_fault"):
            se.add_api_hook(handler, dll, api_name, argc=0)
        entry = emu.get_proc(dll, api_name)
        resolver = emu.get_proc("kernel32", "GetProcAddress")
        if mode == "handler_fault":
            assert not emu.get_api_hooks(dll, api_name)
            original_call_api_func = emu.api.call_api_func

            def fail_builtin(module, function, argv, ctx):
                if function.__name__ == "GetTickCount":
                    calls.append({"api": "kernel32.GetTickCount", "args": list(argv), "sp": emu.get_stack_ptr()})
                    emu.mem_write(counter, struct.pack("<I", len(calls)))
                    raise RuntimeError("forced built-in handler failure")
                return original_call_api_func(module, function, argv, ctx)

            emu.api.call_api_func = fail_builtin
        module = emu.get_mod_by_name(dll)
        assert module._image.source == "synthetic"
        if mode != "unknown":
            assert entry == module.get_export_by_name(api_name).address
        else:
            assert not emu.api.get_export_func_handler(dll, api_name)[1]
            assert not emu.get_api_hooks(dll, api_name)
            assert not emu.lookup_api_signature(dll, api_name)
            # This thread registers the queued hook only after the test has
            # observed the unsupported stop. The acknowledgement is published
            # after registration, while model execution is still paused.
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
        if mode in ("interrupt", "callback_interrupt_budget"):
            # Hold the first native yield for this entry after Unicorn has
            # returned, so Ctrl-C arrives before deferred Python dispatch.
            native_start = emu.emu_eng.start
            native_stop = emu.emu_eng.stop
            waiting = threading.Event()
            yielded = []
            trap_ready = Path(metadata_path).with_suffix(".trap")
            release = Path(metadata_path).with_suffix(".release")
            interrupted = Path(metadata_path).with_suffix(".interrupted")

            def gated_start(*args, **kwargs):
                try:
                    return native_start(*args, **kwargs)
                finally:
                    pending = emu._pending_api_entry
                    at_yield = (
                        emu._pending_control == "callback_return" if mode == "callback_interrupt_budget" else
                        pending is not None and pending.address == entry
                    )
                    if not yielded and at_yield:
                        yielded.append(True)
                        waiting.set()
                        trap_ready.write_text("yielded")
                        deadline = time.monotonic() + 5
                        try:
                            while not release.exists():
                                assert time.monotonic() < deadline, "private yield was not released"
                                if shutdown.wait(0.01):
                                    break
                        finally:
                            waiting.clear()

            def observed_stop():
                native_stop()
                if waiting.is_set():
                    interrupted.write_text("interrupted")

            emu.emu_eng.start = gated_start
            emu.emu_eng.stop = observed_stop
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
            # Give the unknown ABI an observable argument. No stack cleanup is
            # allowed until its calling convention becomes known.
            argument = 0x2468
            setup = (b"\x68" + struct.pack("<I", argument)) if architecture == "x86" else (
                b"\x48\xb9" + struct.pack("<Q", argument)
            )
            code = code[:-2] + setup + code[-2:]
            if architecture == "x86":
                stack_adjust = 4
                epilogue = b"\x90\x83\xc4\x04\xc3"
        if mode in ("budget", "timeout"):
            # Six guest instructions per x86 iteration, five per x64: the API
            # entry uses three/two instructions; Python dispatch is not one.
            code = (b"\xb8" + struct.pack("<I", entry)) if architecture == "x86" else (
                b"\x48\xb8" + struct.pack("<Q", entry)
            )
            code += b"\xff\xd0"
            epilogue = b"\xeb" + bytes([(-len(code) - 2) & 0xff])
            stack_adjust = 0
        if mode == "return_budget":
            code, epilogue, stack_adjust = b"\x90", b"\xc3", 0
        if mode == "trap_read":
            # Derive the private destination from the public bytes in guest
            # code, then read it as data rather than executing the API.
            if architecture == "x86":
                code = (b"\xb8" + struct.pack("<I", entry)
                        + b"\x8b\x48\x06\x8d\x40\x0a\x01\xc8")
                probe = b"\x8b\x00"
            else:
                code = b"\x48\xb8" + struct.pack("<Q", entry) + b"\x48\x8b\x40\x08"
                probe = b"\x48\x8b\x00"
            fault_pc = caller + len(code)
            code += probe
            epilogue, stack_adjust = b"\xc3", 0
        callback = caller + 64
        se.mem_write(callback, b"\xb8\x63\0\0\0" + (
            b"\xc2\x04\x00" if architecture == "x86" else b"\xc3"
        ))
        redirect = caller + 96
        se.mem_write(redirect, b"\xb8\x2a\0\0\0\xc3")
        return_address = caller + len(code)
        se.mem_write(caller, code + epilogue)
        Path(metadata_path).write_text(json.dumps({
            "caller": caller, "entry": entry, "counter": counter,
            "return_address": return_address, "stack_adjust": stack_adjust, "redirect": redirect,
            "trap": emu.api_registry.entries[entry].trap, "callback": callback,
            "callback_return": API_CALLBACK_HANDLER_ADDR,
            "fault_pc": fault_pc if mode == "trap_read" else None,
        }))
        se.run_shellcode(caller)
        Path(result_path).write_text(json.dumps({
            "calls": calls, "counter": int.from_bytes(se.mem_read(counter, 4), "little"),
            "return_value": emu.get_return_val(), "sp": emu.get_stack_ptr(),
            "budget_instructions": getattr(emu.curr_run, "_budget_instructions", 0),
            "instructions": emu.curr_run.instr_cnt,
            "execution_elapsed": emu.curr_run.execution_elapsed,
            "callbacks_pending": len(emu.curr_run.api_callbacks),
            "error_type": emu.curr_run.error.type if emu.curr_run.error else None,
            "error_pc": emu.curr_run.error.pc if emu.curr_run.error else None,
            "trap_mapped": emu.get_address_map(emu.api_registry.entries[entry].trap) is not None,
            "reservation_mapped": any(
                start < emu.api_registry.trap_base + emu.api_registry.TRAP_SIZE
                and end >= emu.api_registry.trap_base
                for start, end, _ in emu.get_mem_regions()
            ),
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

    def finish(self):
        # Speakeasy reports one final inspectable stop before the exit reply.
        assert self.client.continue_().startswith("T05")
        assert self.client.continue_() == "W00"
        stdout, stderr = self.proc.communicate(timeout=10)
        assert self.proc.returncode == 0, (stdout.decode(errors="replace"), stderr.decode(errors="replace"))
        return json.loads(self.result_path.read_text())


def _api_target(request, tmp_path, config, mode):
    config["timeout"] = 0.5 if mode == "timeout" else 10
    config["max_instructions"] = {"budget": 17, "return_budget": 2}.get(mode, 1000)
    if mode == "callback_interrupt_budget":
        # Exact guest count through callback RET: thirteen on x86, twelve
        # on x64. Both GetProcAddress and the target execute an API entry.
        config["max_instructions"] = 13 if request.param == "x86" else 12
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
            request.param,
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
        yield ApiTarget(client, proc, request.param, json.loads(metadata_path.read_text()), result_path, metadata_path)
    finally:
        if client is not None:
            client.close()
        _stop_server(proc)
        _, stderr = proc.communicate(timeout=5)
        if stderr:
            print(stderr.decode(errors="replace"))


@pytest.fixture(params=["x86", "x64"])
def api_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "known")


@pytest.fixture(params=["x86", "x64"])
def unknown_api_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "unknown")


@pytest.fixture(params=["x86", "x64"])
def interrupt_api_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "interrupt")


@pytest.fixture(params=["x86", "x64"])
def budget_api_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "budget")


@pytest.fixture(params=["x86", "x64"])
def traced_budget_api_target(request, tmp_path, config):
    config["analysis"]["memory_tracing"] = True
    yield from _api_target(request, tmp_path, config, "budget")


@pytest.fixture(params=["x86", "x64"])
def timeout_api_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "timeout")


@pytest.fixture(params=["x86", "x64"])
def callback_api_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "callback")


@pytest.fixture(params=["x86", "x64"])
def return_budget_api_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "return_budget")


@pytest.fixture(params=["x86", "x64"])
def callback_interrupt_budget_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "callback_interrupt_budget")


@pytest.fixture(params=["x86", "x64"])
def handler_fault_api_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "handler_fault")


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
    initial_sp, entry_sp = _break_at_entry(target)
    prefix = "8bff" if target.ptr_size == 4 else "6690"
    assert client.read_memory(entry, 2) == prefix

    # Keep the breakpoint installed: single-step must resume past this stop.
    assert client.step().startswith("T05")
    pc, sp, _ = target.registers()
    assert pc == entry + 2
    assert sp == entry_sp
    assert target.counter() == 0
    if target.ptr_size == 4:
        assert client.read_memory(pc, 3) == "0f1f00"
        assert client.step().startswith("T05")
        pc, sp, _ = target.registers()
        assert (pc, sp) == (entry + 5, entry_sp)
        assert target.counter() == 0
    assert client.read_memory(pc, 1 if target.ptr_size == 4 else 2) == ("e9" if target.ptr_size == 4 else "ff25")

    # One step over the final jump must include deferred dispatch and return;
    # exposing the private unmapped trap as a debugger stop is a regression.
    assert client.step().startswith("T05")
    pc, sp, result = target.registers()
    assert pc == target.metadata["return_address"]
    assert sp == entry_sp + target.ptr_size
    assert result == 0x13579
    assert target.counter() == 1
    assert client.query(f"z0,{entry:x},1") == "OK"
    report = target.finish()
    assert report["calls"] == [{"api": "kernel32.GetTickCount", "args": [], "sp": entry_sp}]
    assert report["counter"] == 1
    assert report["budget_instructions"] == 13
    assert report["return_value"] == 0x13579
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_host_patch_api_entry_executes_guest_bytes(api_target):
    target = api_target
    client = target.client
    entry = target.metadata["entry"]
    initial_sp, entry_sp = _break_at_entry(target)
    # mov eax, 42; ret replaces both the hotpatch prefix and private jump.
    patch = bytes.fromhex("b82a000000c3")
    assert client.query(f"M{entry:x},{len(patch):x}:{patch.hex()}") == "OK"
    assert client.read_memory(entry, len(patch)) == patch.hex()
    assert client.query(f"z0,{entry:x},1") == "OK"
    return_address = target.metadata["return_address"]
    assert client.query(f"Z0,{return_address:x},1") == "OK"
    stop = client.continue_()
    assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
    pc, sp, result = target.registers()
    assert pc == return_address
    assert sp == entry_sp + target.ptr_size
    assert result == 42
    assert target.counter() == 0
    assert client.query(f"z0,{return_address:x},1") == "OK"
    report = target.finish()
    assert report["calls"] == []
    assert report["counter"] == 0
    assert report["return_value"] == 42
    assert report["sp"] == initial_sp + target.ptr_size


def _read_call_frame(target, sp):
    # x86 return slot + argument; x64 return slot + caller's shadow space.
    size = 8 if target.ptr_size == 4 else 40
    reply = target.client.read_memory(sp, size)
    assert len(reply) == size * 2 and all(c in "0123456789abcdefABCDEF" for c in reply), (
        f"invalid RSP frame reply at {sp:#x} for {size} bytes",
        reply,
    )
    return bytes.fromhex(reply)


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


def _wait_for_signal(target, suffix):
    path = target.metadata_path.with_suffix(suffix)
    deadline = time.monotonic() + 5
    while not path.exists():
        assert target.proc.poll() is None, f"server exited while waiting for {suffix}"
        assert time.monotonic() < deadline, f"server did not acknowledge {suffix} within 5 seconds"
        time.sleep(0.01)


def _install_paused_hook(target):
    target.metadata_path.with_suffix(".install").write_text("install")
    _wait_for_signal(target, ".ready")
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
    assert report["counter"] == 1
    assert report["return_value"] == 0x13579
    assert report["sp"] == initial_sp + target.ptr_size


@pytest.mark.parametrize("redirect_method", ["P", "cADDRESS"])
def test_gdb_pc_redirect_abandons_unknown_abi_call(unknown_api_target, redirect_method):
    target = unknown_api_target
    client = target.client
    initial_sp, entry_sp = _suspend_unknown_call(target)
    # Make the old call dispatchable before redirecting: stale pending state
    # would now invoke this hook rather than merely stop as unsupported again.
    _install_paused_hook(target)
    redirect = target.metadata["redirect"]
    return_address = target.metadata["return_address"]
    assert client.query(f"Z0,{return_address:x},1") == "OK"
    if redirect_method == "P":
        pc_register = 8 if target.ptr_size == 4 else 16
        encoded_pc = redirect.to_bytes(target.ptr_size, "little").hex()
        assert client.query(f"P{pc_register:x}={encoded_pc}") == "OK"
        assert target.registers()[0:2] == (redirect, entry_sp)
        stop = client.continue_()
    else:
        stop = client.query(f"c{redirect:x}")
    assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
    assert target.registers() == (return_address, entry_sp + target.ptr_size, 42)
    assert target.counter() == 0
    assert client.query(f"z0,{return_address:x},1") == "OK"
    report = target.finish()
    assert report["calls"] == []
    assert report["counter"] == 0
    assert report["return_value"] == 42
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_interrupt_private_yield_precedes_handler_dispatch(interrupt_api_target):
    target = interrupt_api_target
    client = target.client
    initial_sp, entry_sp = _break_at_entry(target)
    entry = target.metadata["entry"]
    stack = _read_call_frame(target, entry_sp)
    assert client.query(f"z0,{entry:x},1") == "OK"
    client.send_no_wait("c")
    _wait_for_signal(target, ".trap")
    # Split interrupt() into send/receive so the gate is released only after
    # the real RSP reader has requested the interrupt and stopped the engine.
    client.sock.sendall(b"\x03")
    _wait_for_signal(target, ".interrupted")
    target.metadata_path.with_suffix(".release").write_text("release")
    assert client._recv().startswith("T02")
    assert target.registers()[0:2] == (target.metadata["trap"], entry_sp)
    assert _read_call_frame(target, entry_sp) == stack
    assert target.counter() == 0
    # Resuming the same pending call after Ctrl-C dispatches it exactly once.
    assert client.step().startswith("T05")
    assert target.registers() == (target.metadata["return_address"], entry_sp + target.ptr_size, 0x13579)
    assert target.counter() == 1
    report = target.finish()
    assert report["calls"] == [{"api": "kernel32.GetTickCount", "args": [], "sp": entry_sp}]
    assert report["counter"] == 1
    assert report["return_value"] == 0x13579
    assert report["sp"] == initial_sp + target.ptr_size


def _kill_limited_target(target):
    # A persistent exhausted budget remains inspectable on subsequent resumes.
    # Terminate through RSP rather than detaching into a deliberately endless loop.
    target.client.send_no_wait("k")
    stdout, stderr = target.proc.communicate(timeout=10)
    assert target.proc.returncode == 0, (stdout.decode(errors="replace"), stderr.decode(errors="replace"))
    return json.loads(target.result_path.read_text())


@pytest.mark.parametrize("breakpoints", [False, True])
def test_gdb_instruction_budget_counts_execution_across_api_breakpoints(budget_api_target, breakpoints):
    target = budget_api_target
    client = target.client
    entry = target.metadata["entry"]
    _, initial_sp, _ = target.registers()
    if breakpoints:
        assert client.query(f"Z0,{entry:x},1") == "OK"
        for completed_calls in range(3):
            stop = client.continue_()
            assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
            assert target.registers()[0:2] == (entry, initial_sp - target.ptr_size)
            assert target.counter() == completed_calls
        assert client.query(f"z0,{entry:x},1") == "OK"
    stop = client.continue_()
    assert stop.startswith("T05") and "swbreak:;" not in stop, (stop, target.registers())
    assert target.registers()[0:2] == (entry, initial_sp - target.ptr_size)
    completed = 2 if target.ptr_size == 4 else 3
    assert target.counter() == completed
    # At 17, x86 has executed the third entry's JMP with dispatch pending;
    # x64 has executed the fourth CALL, before its entry prefix.
    # Breakpoint visits must not consume instruction budget.
    assert client.continue_().startswith("T05")
    assert target.registers()[0:2] == (entry, initial_sp - target.ptr_size)
    assert target.counter() == completed
    report = _kill_limited_target(target)
    assert report["budget_instructions"] == report["instructions"] == 17
    assert report["counter"] == len(report["calls"]) == completed


@pytest.mark.parametrize("step", [False, True])
def test_gdb_tracing_stops_at_instruction_budget(traced_budget_api_target, step):
    target = traced_budget_api_target
    client = target.client
    _, initial_sp, _ = target.registers()
    for _ in range(17 if step else 1):
        stop = client.step() if step else client.continue_()
        assert stop.startswith("T05"), (stop, target.registers())
    assert target.registers()[0:2] == (target.metadata["entry"], initial_sp - target.ptr_size)
    completed = 2 if target.ptr_size == 4 else 3
    assert target.counter() == completed
    # Neither resuming nor stepping an exhausted cap may reach tracing again.
    assert client.continue_().startswith("T05")
    assert client.step().startswith("T05")
    report = _kill_limited_target(target)
    assert report["budget_instructions"] == report["instructions"] == 17
    assert report["counter"] == len(report["calls"]) == completed


def test_gdb_timeout_is_shared_across_resumes_and_excludes_debugger_pause(timeout_api_target):
    target = timeout_api_target
    client = target.client
    return_address = target.metadata["return_address"]
    assert client.query(f"Z0,{return_address:x},1") == "OK"
    for completed_calls in (1, 2):
        stop = client.continue_()
        assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
        assert target.registers()[0] == return_address
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
    assert target.counter() == 3
    report = _kill_limited_target(target)
    assert report["execution_elapsed"] >= 0.5
    assert report["counter"] == len(report["calls"]) == 3


@pytest.mark.parametrize("api_target", ["x64"], indirect=True)
def test_gdb_x64_watchpoint_on_api_jump_target_defers_dispatch(api_target):
    target = api_target
    assert target.ptr_size == 8
    client = target.client
    entry = target.metadata["entry"]
    initial_sp, entry_sp = _break_at_entry(target)
    assert client.query(f"z0,{entry:x},1") == "OK"
    assert client.step().startswith("T05")
    assert target.registers()[0:2] == (entry + 2, entry_sp)
    pointer = entry + 8
    assert int.from_bytes(bytes.fromhex(client.read_memory(pointer, 8)), "little") == target.metadata["trap"]
    assert client.query(f"Z3,{pointer:x},8") == "OK"
    stop = client.step()
    assert stop.startswith("T05") and f"rwatch:{pointer:x};" in stop, (stop, target.registers())
    assert target.registers()[0:2] == (target.metadata["trap"], entry_sp)
    assert target.counter() == 0
    assert client.query(f"z3,{pointer:x},8") == "OK"
    assert client.step().startswith("T05")
    assert target.registers() == (target.metadata["return_address"], entry_sp + target.ptr_size, 0x13579)
    assert target.counter() == 1
    report = target.finish()
    assert report["counter"] == len(report["calls"]) == 1
    # Five caller setup instructions, two resolver instructions, CALL, two
    # target instructions and NOP/ADD/RET. A watched read must not charge the
    # retried jump twice toward the run's instruction limit.
    assert report["budget_instructions"] == 13, report
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_step_callback_return_restores_api_frame(callback_api_target):
    target = callback_api_target
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
    # Step the guest RET and its deferred continuation as one debugger action.
    assert client.step().startswith("T05")
    assert target.registers() == (target.metadata["return_address"], entry_sp + target.ptr_size, 0x13579)
    assert target.counter() == 1
    assert client.query(f"z0,{callback:x},1") == "OK"
    report = target.finish()
    assert report["callbacks_pending"] == 0
    assert report["counter"] == len(report["calls"]) == 1
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_return_at_exact_instruction_budget_completes(return_budget_api_target):
    target = return_budget_api_target
    client = target.client
    _, initial_sp, _ = target.registers()
    # NOP; RET uses exactly two guest instructions. Processing the resulting
    # run-return control yield must not require a third instruction of budget.
    stop = client.continue_()
    assert stop.startswith("T05"), (stop, target.registers())
    assert target.registers()[1] == initial_sp + target.ptr_size
    assert target.counter() == 0
    assert client.continue_() == "W00"
    stdout, stderr = target.proc.communicate(timeout=10)
    assert target.proc.returncode == 0, (stdout.decode(errors="replace"), stderr.decode(errors="replace"))
    report = json.loads(target.result_path.read_text())
    assert report["budget_instructions"] == report["instructions"] == 2
    assert report["counter"] == 0


def test_gdb_interrupted_callback_return_finalizes_at_exact_budget(callback_interrupt_budget_target):
    target = callback_interrupt_budget_target
    client = target.client
    _, entry_sp = _break_at_entry(target)
    entry = target.metadata["entry"]
    callback = target.metadata["callback"]
    assert client.query(f"z0,{entry:x},1") == "OK"
    assert client.query(f"Z0,{callback:x},1") == "OK"
    stop = client.continue_()
    assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
    assert target.registers()[0] == callback
    assert client.step().startswith("T05")
    assert target.registers()[0] == callback + 5
    assert target.counter() == 1
    # RET uses the last instruction, then Ctrl-C suspends its pending host
    # continuation. Resume must finalize that return despite zero budget left.
    client.send_no_wait("s")
    _wait_for_signal(target, ".trap")
    client.sock.sendall(b"\x03")
    _wait_for_signal(target, ".interrupted")
    target.metadata_path.with_suffix(".release").write_text("release")
    assert client._recv().startswith("T02")
    assert target.registers()[0] == target.metadata["callback_return"]
    assert target.counter() == 1
    assert client.query(f"z0,{callback:x},1") == "OK"
    assert client.step().startswith("T05")
    assert target.registers() == (target.metadata["return_address"], entry_sp + target.ptr_size, 0x13579)
    report = _kill_limited_target(target)
    assert report["callbacks_pending"] == 0
    assert report["counter"] == len(report["calls"]) == 1
    assert report["budget_instructions"] == (13 if target.ptr_size == 4 else 12)


def test_gdb_write_watchpoint_resume_does_not_repeat_guest_side_effect(api_target):
    target = api_target
    client = target.client
    entry = target.metadata["entry"]
    initial_sp, entry_sp = _break_at_entry(target)
    scratch = target.metadata["counter"] + 64
    assert client.read_memory(scratch, 4) == "00000000"
    # INC dword [scratch]; MOV eax,42; RET. On x64 FF /0 uses RIP-relative
    # addressing, whereas x86 uses the absolute address embedded below.
    operand = scratch if target.ptr_size == 4 else (scratch - entry - 6) & 0xFFFFFFFF
    patch = b"\xff\x05" + struct.pack("<I", operand) + bytes.fromhex("b82a000000c3")
    assert client.query(f"M{entry:x},{len(patch):x}:{patch.hex()}") == "OK"
    assert client.query(f"z0,{entry:x},1") == "OK"
    assert client.query(f"Z2,{scratch:x},4") == "OK"
    stop = client.step()
    assert stop.startswith("T05") and f"watch:{scratch:x};" in stop, (stop, target.registers())
    assert client.read_memory(scratch, 4) == "01000000"
    assert target.registers()[0:2] == (entry + 6, entry_sp)
    assert target.counter() == 0
    assert client.query(f"z2,{scratch:x},4") == "OK"
    return_address = target.metadata["return_address"]
    assert client.query(f"Z0,{return_address:x},1") == "OK"
    stop = client.continue_()
    assert stop.startswith("T05") and "swbreak:;" in stop, (stop, target.registers())
    assert target.registers() == (return_address, entry_sp + target.ptr_size, 42)
    # The watched INC already wrote once. Resuming must not execute it again.
    assert client.read_memory(scratch, 4) == "01000000"
    assert client.query(f"z0,{return_address:x},1") == "OK"
    report = target.finish()
    assert report["counter"] == 0
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_patch_suspended_unknown_api_executes_revised_public_bytes(unknown_api_target):
    target = unknown_api_target
    client = target.client
    initial_sp, entry_sp = _suspend_unknown_call(target)
    entry = target.metadata["entry"]
    # If stale pending dispatch survives the patch, this newly registered hook
    # would run instead of the replacement MOV/RET and be observable below.
    _install_paused_hook(target)
    patch = bytes.fromhex("b82a000000c3")
    assert client.query(f"M{entry:x},{len(patch):x}:{patch.hex()}") == "OK"
    assert client.read_memory(entry, len(patch)) == patch.hex()
    assert client.step().startswith("T05")
    assert target.registers() == (entry + 5, entry_sp, 42)
    assert target.counter() == 0
    assert client.step().startswith("T05")
    assert target.registers() == (target.metadata["return_address"], entry_sp + target.ptr_size, 42)
    assert target.counter() == 0
    report = target.finish()
    assert report["calls"] == []
    assert report["counter"] == 0
    assert report["return_value"] == 42
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_edit_suspended_unknown_api_sp_reexecutes_public_entry(unknown_api_target):
    target = unknown_api_target
    client = target.client
    initial_sp, entry_sp = _suspend_unknown_call(target)
    entry = target.metadata["entry"]
    original_code = client.read_memory(entry, 16)
    original_frame = _read_call_frame(target, entry_sp)
    _install_paused_hook(target)
    new_sp = entry_sp - 0x100
    new_arg = 0x5678
    # Install a real alternate call frame inside the mapped stack. Its return
    # slot points to the caller, and its argument differs from the old call.
    frame = target.metadata["return_address"].to_bytes(target.ptr_size, "little")
    frame += new_arg.to_bytes(4, "little") if target.ptr_size == 4 else b"\0" * 32
    assert client.query(f"M{new_sp:x},{len(frame):x}:{frame.hex()}") == "OK"
    sp_register = 4 if target.ptr_size == 4 else 7
    assert client.query(f"P{sp_register:x}={new_sp.to_bytes(target.ptr_size, 'little').hex()}") == "OK"
    if target.ptr_size == 8:
        # Windows x64 passes the first argument in RCX, RSP register number 7
        # above; RCX is core register number 2 in this RSP target description.
        assert client.query(f"P2={new_arg.to_bytes(8, 'little').hex()}") == "OK"
    assert target.registers()[0:2] == (entry, new_sp)
    assert client.read_memory(entry, 16) == original_code
    # An SP edit alone must invalidate retained dispatch. This step executes
    # the unmodified hotpatch prefix, before the now-callable hook can run.
    assert client.step().startswith("T05")
    assert target.registers()[0:2] == (entry + 2, new_sp)
    assert target.counter() == 0
    if target.ptr_size == 4:
        assert client.step().startswith("T05")
        assert target.registers()[0:2] == (entry + 5, new_sp)
        assert target.counter() == 0
    assert client.step().startswith("T05")
    assert target.registers() == (target.metadata["return_address"], new_sp + target.ptr_size, 0x13579)
    assert target.counter() == 1
    assert _read_call_frame(target, entry_sp) == original_frame
    # Return to the original caller's stack for its normal epilogue; the API
    # dispatch and return above have already been verified on the new frame.
    caller_sp = entry_sp + target.ptr_size
    assert client.query(f"P{sp_register:x}={caller_sp.to_bytes(target.ptr_size, 'little').hex()}") == "OK"
    report = target.finish()
    assert report["calls"] == [{"api": "gdb_unknown_abi.SuspendedCall", "args": [new_arg], "sp": new_sp}]
    assert report["counter"] == 1
    assert report["return_value"] == 0x13579
    assert report["sp"] == initial_sp + target.ptr_size


def test_gdb_builtin_handler_exception_reports_fault_and_signal_exit(handler_fault_api_target):
    target = handler_fault_api_target
    client = target.client
    _, entry_sp = _break_at_entry(target)
    entry = target.metadata["entry"]
    frame = _read_call_frame(target, entry_sp)
    assert client.query(f"z0,{entry:x},1") == "OK"
    stop = client.continue_()
    assert stop.startswith("T0b"), (stop, target.registers())
    # Inspection precedes terminal run cleanup. The failed built-in dispatch
    # must not fabricate an API return, pop the call frame, or execute again.
    assert target.registers()[0:2] == (target.metadata["trap"], entry_sp)
    assert _read_call_frame(target, entry_sp) == frame
    assert target.counter() == 1
    assert client.continue_() == "X0b"
    stdout, stderr = target.proc.communicate(timeout=10)
    assert target.proc.returncode == 0, (stdout.decode(errors="replace"), stderr.decode(errors="replace"))
    report = json.loads(target.result_path.read_text())
    assert report["calls"] == [{"api": "kernel32.GetTickCount", "args": [], "sp": entry_sp}]
    assert report["counter"] == 1
    assert report["error_type"] == "forced built-in handler failure"


@pytest.fixture(params=["x86", "x64"])
def trap_read_target(request, tmp_path, config):
    yield from _api_target(request, tmp_path, config, "trap_read")


def test_gdb_guest_read_of_private_trap_reports_sigsegv_without_dispatch(trap_read_target):
    target = trap_read_target
    client = target.client
    _, initial_sp, _ = target.registers()
    stop = client.continue_()
    assert stop.startswith("T0b"), (stop, target.registers())
    pc, sp, accumulator = target.registers()
    assert (pc, sp) == (target.metadata["fault_pc"], initial_sp)
    assert accumulator == target.metadata["trap"]
    assert target.counter() == 0
    assert client.continue_() == "X0b"
    stdout, stderr = target.proc.communicate(timeout=10)
    assert target.proc.returncode == 0, (stdout.decode(errors="replace"), stderr.decode(errors="replace"))
    report = json.loads(target.result_path.read_text())
    assert report["error_type"] == "invalid_read"
    assert report["error_pc"] == target.metadata["fault_pc"]
    assert report["calls"] == []
    assert report["counter"] == 0
    assert not report["trap_mapped"]
    assert not report["reservation_mapped"]
    assert report["budget_instructions"] == (5 if target.ptr_size == 4 else 3)
