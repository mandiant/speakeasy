"""Speakeasy-native GDB Remote Serial Protocol server.

The server deliberately implements the all-stop subset used by GDB and IDA.
Target operations are performed by the emulation thread; a small reader thread
only parses transport packets and interrupts a running Unicorn instance on
Ctrl-C.
"""

from __future__ import annotations

import html
import logging
import queue
import socket
import threading
from dataclasses import dataclass
from typing import Any

import unicorn.x86_const as ux

from speakeasy.winenv import arch

logger = logging.getLogger(__name__)

_PACKET_SIZE = 0x10000


def _rsp_packet(payload: bytes) -> bytes:
    return b"$" + payload + f"#{sum(payload) & 0xFF:02x}".encode("ascii")


def _rsp_escape(data: bytes) -> bytes:
    result = bytearray()
    for value in data:
        if value in b"$#}*":
            result.extend((ord("}"), value ^ 0x20))
        else:
            result.append(value)
    return bytes(result)


def _rsp_unescape(data: bytes) -> bytes:
    result = bytearray()
    index = 0
    while index < len(data):
        if data[index] == ord("}") and index + 1 < len(data):
            result.append(data[index + 1] ^ 0x20)
            index += 2
        else:
            result.append(data[index])
            index += 1
    return bytes(result)


@dataclass(frozen=True)
class ResumeAction:
    step: bool = False
    detach: bool = False
    kill: bool = False


@dataclass(frozen=True)
class StopReason:
    signal: int = 5
    kind: str = ""
    address: int | None = None


@dataclass(frozen=True)
class RegisterInfo:
    name: str
    unicorn_id: int | None
    size: int
    group: str = ""


class GdbServer:
    """An all-stop RSP server backed directly by a WindowsEmulator."""

    def __init__(self, emu: Any, port: int, host: str):
        self.emu = emu
        self.host = host
        self.port = port
        self._listener: socket.socket | None = None
        self._client: socket.socket | None = None
        self._reader: threading.Thread | None = None
        self._commands: queue.Queue[bytes | None] = queue.Queue()
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._closed = threading.Event()
        self._no_ack = False
        self._last_packet: bytes | None = None
        self._running = False
        self._stop_reason = StopReason()
        self._stop_pending = False
        self._library_list_changed = False
        self._resume_from_breakpoint: int | None = None
        self._exec_breakpoints: dict[tuple[int, int], int] = {}
        self._read_watchpoints: dict[tuple[int, int], int] = {}
        self._write_watchpoints: dict[tuple[int, int], int] = {}
        self._access_watchpoints: dict[tuple[int, int], int] = {}
        self._registers = self._make_registers()
        self._hooks: list[Any] = []
        self._code_hook: Any | None = None
        self._read_hook: Any | None = None
        self._write_hook: Any | None = None

    def __enter__(self) -> GdbServer:
        try:
            self.start()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Transport

    def start(self) -> None:
        if self.host not in ("127.0.0.1", "localhost"):
            logger.warning("GDB RSP is unauthenticated; exposing it on %s permits target modification", self.host)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(1)
        self._listener = listener
        logger.info("Native GDB server listening on %s:%d, waiting for connection...", self.host, self.port)
        client, address = listener.accept()
        self._client = client
        logger.info("GDB client connected from %s:%d", *address[:2])
        self._install_hooks()
        listeners = getattr(self.emu, "module_change_listeners", None)
        if listeners is not None:
            listeners.append(self._on_module_change)
        self._reader = threading.Thread(target=self._read_loop, name="speakeasy-gdb-reader", daemon=True)
        self._reader.start()

    def notify_exit(self, code: int) -> None:
        if not self._closed.is_set():
            try:
                self._reply(f"W{code & 0xFF:02x}".encode("ascii"))
            except OSError:
                pass

    def notify_signal(self, signal: int) -> None:
        if not self._closed.is_set():
            try:
                self._reply(f"X{signal & 0xFF:02x}".encode("ascii"))
            except OSError:
                pass

    def close(self) -> None:
        self._closed.set()
        for sock in (self._client, self._listener):
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
        listeners = getattr(self.emu, "module_change_listeners", None)
        if listeners is not None and self._on_module_change in listeners:
            listeners.remove(self._on_module_change)
        for hook in self._hooks:
            try:
                self._remove_hook(hook)
            except Exception:
                pass
        # Prevent BinaryEmulator.set_hooks() from restoring debugger hooks if
        # emulation is started again after this session closes.
        for registered_hooks in getattr(self.emu, "hooks", {}).values():
            if isinstance(registered_hooks, list):
                registered_hooks[:] = [hook for hook in registered_hooks if hook not in self._hooks]

    @staticmethod
    def _extract_packet(buffer: bytearray) -> tuple[bytes, bytes, bool] | None:
        if not buffer or buffer[0] != ord("$"):
            return None
        marker = buffer.find(b"#", 1)
        if marker < 0 or len(buffer) < marker + 3:
            return None
        raw = bytes(buffer[: marker + 3])
        encoded = bytes(buffer[1:marker])
        try:
            checksum = int(buffer[marker + 1 : marker + 3], 16)
            valid = len(encoded) <= _PACKET_SIZE and not encoded.endswith(b"}") and checksum == (sum(encoded) & 0xFF)
        except ValueError:
            valid = False
        del buffer[: marker + 3]
        return raw, _rsp_unescape(encoded), valid

    def _read_loop(self) -> None:
        assert self._client is not None
        buffer = bytearray()
        try:
            while not self._closed.is_set():
                data = self._client.recv(65536)
                if not data:
                    break
                buffer.extend(data)
                while buffer:
                    value = buffer[0]
                    if value == 3:
                        del buffer[:1]
                        self._interrupt()
                        continue
                    if value in (ord("+"), ord("-")):
                        del buffer[:1]
                        if value == ord("-") and self._last_packet is not None:
                            self._send_raw(self._last_packet)
                        continue
                    if value != ord("$"):
                        del buffer[:1]
                        continue
                    packet = self._extract_packet(buffer)
                    if packet is None:
                        break
                    _raw, payload, valid = packet
                    if not valid:
                        if not self._no_ack:
                            self._send_raw(b"-")
                        continue
                    if not self._no_ack:
                        self._send_raw(b"+")
                    self._commands.put(payload)
                if len(buffer) > _PACKET_SIZE + 4:
                    logger.warning("Closing GDB connection after oversized or incomplete RSP packet")
                    break
        except OSError:
            pass
        finally:
            self._commands.put(None)

    def _send_raw(self, data: bytes) -> None:
        if self._client is None:
            return
        with self._send_lock:
            self._client.sendall(data)

    def _reply(self, payload: bytes, *, binary: bool = False) -> None:
        if binary:
            payload = payload[:1] + _rsp_escape(payload[1:])
        packet = _rsp_packet(payload)
        self._last_packet = packet
        self._send_raw(packet)

    # ------------------------------------------------------------------
    # Execution lifecycle

    def command_loop(self, reason: StopReason | None = None) -> ResumeAction:
        if reason is not None:
            self._stop_reason = reason
            self._reply(self._stop_reply(reason))
        with self._state_lock:
            self._running = False
            self._stop_pending = False

        while not self._closed.is_set():
            payload = self._commands.get()
            if payload is None:
                return ResumeAction(detach=True)
            try:
                action = self._handle_command(payload)
            except OSError:
                return ResumeAction(detach=True)
            except Exception:
                logger.warning("unhandled exception processing GDB command %r", payload, exc_info=True)
                try:
                    self._reply(b"E01")
                except OSError:
                    return ResumeAction(detach=True)
                continue
            if action is not None:
                if not action.detach and not action.kill:
                    # Mark the resume transition so Ctrl-C arriving before
                    # begin_run() becomes a pending interrupt, not a queued '?'.
                    with self._state_lock:
                        self._running = True
                return action
        return ResumeAction(detach=True)

    def begin_run(self, action: ResumeAction) -> bool:
        with self._state_lock:
            self._running = True
            if self._stop_pending:
                return False
            self._stop_reason = StopReason()
            pc = self.emu.get_pc()
            at_breakpoint = any(begin <= pc < begin + size for begin, size in self._exec_breakpoints)
            self._resume_from_breakpoint = pc if at_breakpoint else None
        self._refresh_hooks()
        return True

    def finish_run(self, action: ResumeAction) -> StopReason | None:
        with self._state_lock:
            self._running = False
            if self._stop_pending:
                return self._stop_reason
        if action.step:
            return StopReason(kind="step")
        return None

    def _request_stop(self, reason: StopReason) -> None:
        with self._state_lock:
            if not self._running or self._stop_pending:
                return
            self._stop_reason = reason
            self._stop_pending = True
        if self.emu.emu_eng is not None:
            self.emu.emu_eng.stop()

    def _on_module_change(self) -> None:
        with self._state_lock:
            self._library_list_changed = True
        self._request_stop(StopReason(kind="library"))

    def _interrupt(self) -> None:
        with self._state_lock:
            running = self._running
        if running:
            self._request_stop(StopReason(signal=2, kind="interrupt"))
        else:
            self._commands.put(b"?")

    def _install_hooks(self) -> None:
        self._code_hook = self.emu.add_code_hook(self._on_code)
        self._read_hook = self.emu.add_mem_read_hook(self._on_read)
        self._write_hook = self.emu.add_mem_write_hook(self._on_write)
        self._hooks.extend((self._code_hook, self._read_hook, self._write_hook))
        self._refresh_hooks()

    @staticmethod
    def _remove_hook(hook: Any) -> None:
        if hook.added and hook.native_hook:
            hook.emu_eng.hook_remove(hook.handle)
        hook.handle = 0
        hook.added = False
        hook.enabled = False

    @classmethod
    def _set_hook_enabled(cls, hook: Any | None, enabled: bool) -> None:
        if hook is None:
            return
        if enabled and not hook.added:
            hook.add()
        elif not enabled and hook.added:
            # Hook.disable() still enters Python for every native event. Remove
            # the Unicorn hook entirely to avoid that callback overhead.
            cls._remove_hook(hook)

    def _refresh_hooks(self) -> None:
        self._set_hook_enabled(
            self._code_hook,
            bool(self._exec_breakpoints) or self._resume_from_breakpoint is not None,
        )
        self._set_hook_enabled(self._read_hook, bool(self._read_watchpoints or self._access_watchpoints))
        self._set_hook_enabled(self._write_hook, bool(self._write_watchpoints or self._access_watchpoints))

    def _on_code(self, _emu: Any, address: int, _size: int) -> bool:
        if self._resume_from_breakpoint == address:
            self._resume_from_breakpoint = None
            return True
        for (begin, size), bp_type in tuple(self._exec_breakpoints.items()):
            if begin <= address < begin + size:
                kind = "swbreak" if bp_type == 0 else "hwbreak"
                self._request_stop(StopReason(kind=kind, address=address))
                break
        return True

    def _on_read(self, _emu: Any, _access: int, address: int, size: int, _value: int) -> bool:
        if self._overlaps_watchpoint(self._access_watchpoints, address, size):
            self._request_stop(StopReason(kind="awatch", address=address))
        elif self._overlaps_watchpoint(self._read_watchpoints, address, size):
            self._request_stop(StopReason(kind="rwatch", address=address))
        return True

    def _on_write(self, _emu: Any, _access: int, address: int, size: int, _value: int) -> bool:
        if self._overlaps_watchpoint(self._access_watchpoints, address, size):
            self._request_stop(StopReason(kind="awatch", address=address))
        elif self._overlaps_watchpoint(self._write_watchpoints, address, size):
            self._request_stop(StopReason(kind="watch", address=address))
        return True

    @staticmethod
    def _overlaps_watchpoint(watchpoints: dict[tuple[int, int], int], address: int, size: int) -> bool:
        end = address + size
        return any(begin < end and address < begin + length for begin, length in watchpoints)

    # ------------------------------------------------------------------
    # Commands

    def _handle_command(self, payload: bytes) -> ResumeAction | None:
        if payload.startswith(b"qSupported"):
            self._reply(
                b"PacketSize=10000;qXfer:features:read+;qXfer:libraries:read+;"
                b"qXfer:exec-file:read+;qXfer:threads:read+;qXfer:memory-map:read+;"
                b"QStartNoAckMode+;vContSupported+;swbreak+;hwbreak+"
            )
        elif payload == b"QStartNoAckMode":
            self._reply(b"OK")
            self._no_ack = True
        elif payload == b"?":
            self._reply(self._stop_reply(self._stop_reason))
        elif payload == b"g":
            self._read_registers()
        elif payload.startswith(b"G"):
            self._write_registers(payload[1:])
        elif payload.startswith(b"p"):
            self._read_register(payload[1:])
        elif payload.startswith(b"P"):
            self._write_register(payload[1:])
        elif payload.startswith(b"m"):
            self._read_memory(payload[1:])
        elif payload.startswith(b"M"):
            self._write_memory_hex(payload[1:])
        elif payload.startswith(b"X"):
            self._write_memory_binary(payload[1:])
        elif payload[:1] in (b"Z", b"z"):
            self._change_breakpoint(payload)
        elif payload.startswith(b"qXfer:"):
            response = self._handle_xfer(payload)
            self._reply(response if response is not None else b"", binary=response is not None)
        elif payload in (b"qAttached",) or payload.startswith(b"qAttached:"):
            self._reply(b"1")
        elif payload == b"qC":
            self._reply(b"QC1")
        elif payload == b"qfThreadInfo":
            self._reply(b"m1")
        elif payload == b"qsThreadInfo":
            self._reply(b"l")
        elif payload.startswith(b"qGetTIBAddr:"):
            self._reply(f"{self._teb_address():x}".encode("ascii"))
        elif payload.startswith(b"qSymbol"):
            self._reply(b"OK")
        elif payload.startswith(b"H"):
            self._thread_command(payload)
        elif payload.startswith(b"T"):
            self._reply(b"OK" if payload[1:] in (b"1", b"0", b"-1") else b"E01")
        elif payload == b"vCont?":
            self._reply(b"vCont;c;s")
        elif payload.startswith(b"vCont;"):
            return self._resume_command(payload[6:])
        elif payload[:1] in (b"c", b"s"):
            if len(payload) > 1:
                try:
                    self.emu.set_pc(int(payload[1:], 16))
                except ValueError:
                    self._reply(b"E01")
                    return None
            return ResumeAction(step=payload[:1] == b"s")
        elif payload.startswith(b"D"):
            self._reply(b"OK")
            return ResumeAction(detach=True)
        elif payload[:1] in (b"k",) or payload.startswith(b"vKill"):
            return ResumeAction(kill=True)
        elif payload == b"!":
            self._reply(b"")
        else:
            self._reply(b"")
        return None

    def _resume_command(self, actions: bytes) -> ResumeAction | None:
        action_list = actions.split(b";")
        step = any(item[:1] in (b"s", b"S") for item in action_list if item)
        resume = step or any(item[:1] in (b"c", b"C") for item in action_list if item)
        if not resume:
            self._reply(b"E01")
            return None
        return ResumeAction(step=step)

    def _thread_command(self, payload: bytes) -> None:
        if len(payload) < 3 or payload[1:2] not in (b"g", b"c"):
            self._reply(b"E01")
            return
        self._reply(b"OK" if payload[2:] in (b"0", b"1", b"-1") else b"E01")

    def _change_breakpoint(self, payload: bytes) -> None:
        try:
            set_breakpoint = payload[:1] == b"Z"
            bp_type_text, address_text, size_text = payload[1:].split(b",", 2)
            bp_type = int(bp_type_text, 16)
            address = int(address_text, 16)
            size = int(size_text.split(b";", 1)[0], 16)
            if size <= 0:
                raise ValueError
            key = (address, size)
            if bp_type in (0, 1):
                target = self._exec_breakpoints
            elif bp_type == 2:
                target = self._write_watchpoints
            elif bp_type == 3:
                target = self._read_watchpoints
            elif bp_type == 4:
                target = self._access_watchpoints
            else:
                self._reply(b"")
                return
            if set_breakpoint:
                target[key] = bp_type
            else:
                target.pop(key, None)
            self._refresh_hooks()
            self._reply(b"OK")
        except ValueError:
            self._reply(b"E01")
        except Exception:
            logger.warning("breakpoint command failed: %r", payload, exc_info=True)
            self._reply(b"E01")

    # ------------------------------------------------------------------
    # Registers and memory

    def _make_registers(self) -> list[RegisterInfo]:
        if self.emu.get_arch() == arch.ARCH_AMD64:
            definitions = [
                ("rax", ux.UC_X86_REG_RAX, 8),
                ("rbx", ux.UC_X86_REG_RBX, 8),
                ("rcx", ux.UC_X86_REG_RCX, 8),
                ("rdx", ux.UC_X86_REG_RDX, 8),
                ("rsi", ux.UC_X86_REG_RSI, 8),
                ("rdi", ux.UC_X86_REG_RDI, 8),
                ("rbp", ux.UC_X86_REG_RBP, 8),
                ("rsp", ux.UC_X86_REG_RSP, 8),
                *((f"r{i}", getattr(ux, f"UC_X86_REG_R{i}"), 8) for i in range(8, 16)),
                ("rip", ux.UC_X86_REG_RIP, 8),
                ("eflags", ux.UC_X86_REG_EFLAGS, 4),
            ]
        else:
            definitions = [
                ("eax", ux.UC_X86_REG_EAX, 4),
                ("ecx", ux.UC_X86_REG_ECX, 4),
                ("edx", ux.UC_X86_REG_EDX, 4),
                ("ebx", ux.UC_X86_REG_EBX, 4),
                ("esp", ux.UC_X86_REG_ESP, 4),
                ("ebp", ux.UC_X86_REG_EBP, 4),
                ("esi", ux.UC_X86_REG_ESI, 4),
                ("edi", ux.UC_X86_REG_EDI, 4),
                ("eip", ux.UC_X86_REG_EIP, 4),
                ("eflags", ux.UC_X86_REG_EFLAGS, 4),
            ]
        definitions.extend(
            (name, reg, 4)
            for name, reg in (
                ("cs", ux.UC_X86_REG_CS),
                ("ss", ux.UC_X86_REG_SS),
                ("ds", ux.UC_X86_REG_DS),
                ("es", ux.UC_X86_REG_ES),
                ("fs", ux.UC_X86_REG_FS),
                ("gs", ux.UC_X86_REG_GS),
            )
        )
        definitions.extend((f"st{i}", getattr(ux, f"UC_X86_REG_FP{i}"), 10, "float") for i in range(8))
        # Unicorn does not expose all x87 environment fields independently.
        # Keep their standard RSP slots so clients retain the canonical layout.
        definitions.extend(
            (name, None, 4, "float") for name in ("fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop")
        )
        xmm_count = 16 if self.emu.get_arch() == arch.ARCH_AMD64 else 8
        definitions.extend((f"xmm{i}", getattr(ux, f"UC_X86_REG_XMM{i}"), 16, "vector") for i in range(xmm_count))
        definitions.append(("mxcsr", ux.UC_X86_REG_MXCSR, 4, "vector"))
        return [RegisterInfo(*definition) for definition in definitions]

    @property
    def _uc(self) -> Any:
        return self.emu.emu_eng.emu

    def _read_register_value(self, index: int) -> bytes:
        register = self._registers[index]
        if register.unicorn_id is None:
            return bytes(register.size)
        value = self._uc.reg_read(register.unicorn_id)
        if register.name.startswith("st"):
            mantissa, exponent = value
            return int(mantissa).to_bytes(8, "little") + int(exponent).to_bytes(2, "little")
        return int(value).to_bytes(register.size, "little")

    def _read_registers(self) -> None:
        try:
            data = b"".join(self._read_register_value(index).hex().encode() for index in range(len(self._registers)))
            self._reply(data)
        except Exception:
            self._reply(b"E01")

    def _write_registers(self, encoded: bytes) -> None:
        try:
            data = bytes.fromhex(encoded.decode("ascii"))
            offset = 0
            for register in self._registers:
                register_data = data[offset : offset + register.size]
                if len(register_data) != register.size:
                    raise ValueError
                self._write_register_value(register, register_data)
                offset += register.size
            if offset != len(data):
                raise ValueError
            self._reply(b"OK")
        except Exception:
            self._reply(b"E01")

    def _write_register_value(self, register: RegisterInfo, value: bytes) -> None:
        if register.unicorn_id is None:
            return
        if register.name.startswith("st"):
            mantissa = int.from_bytes(value[:8], "little")
            exponent = int.from_bytes(value[8:], "little")
            self._uc.reg_write(register.unicorn_id, (mantissa, exponent))
        else:
            self._uc.reg_write(register.unicorn_id, int.from_bytes(value, "little"))

    def _read_register(self, encoded_index: bytes) -> None:
        try:
            index = int(encoded_index, 16)
            self._reply(self._read_register_value(index).hex().encode("ascii"))
        except (ValueError, IndexError):
            self._reply(b"E01")

    def _write_register(self, payload: bytes) -> None:
        try:
            index_text, value_text = payload.split(b"=", 1)
            index = int(index_text, 16)
            register = self._registers[index]
            value = bytes.fromhex(value_text.decode("ascii"))
            if len(value) != register.size:
                raise ValueError
            self._write_register_value(register, value)
            self._reply(b"OK")
        except (ValueError, IndexError, UnicodeDecodeError):
            self._reply(b"E01")

    def _read_memory(self, payload: bytes) -> None:
        try:
            address_text, size_text = payload.split(b",", 1)
            address, size = int(address_text, 16), int(size_text, 16)
            if address < 0 or size < 0 or size > (_PACKET_SIZE - 1) // 2:
                raise ValueError
            self._reply(bytes(self.emu.mem_read(address, size)).hex().encode("ascii"))
        except Exception:
            self._reply(b"E01")

    def _write_memory_hex(self, payload: bytes) -> None:
        try:
            info, encoded = payload.split(b":", 1)
            address_text, size_text = info.split(b",", 1)
            address, size = int(address_text, 16), int(size_text, 16)
            data = bytes.fromhex(encoded.decode("ascii"))
            if address < 0 or size < 0 or len(data) != size:
                raise ValueError
            self.emu.mem_write(address, data)
            self._reply(b"OK")
        except Exception:
            self._reply(b"E01")

    def _write_memory_binary(self, payload: bytes) -> None:
        try:
            info, data = payload.split(b":", 1)
            address_text, size_text = info.split(b",", 1)
            address, size = int(address_text, 16), int(size_text, 16)
            if address < 0 or size < 0 or len(data) != size:
                raise ValueError
            self.emu.mem_write(address, data)
            self._reply(b"OK")
        except Exception:
            self._reply(b"E01")

    # ------------------------------------------------------------------
    # XML and process metadata

    def _handle_xfer(self, payload: bytes) -> bytes | None:
        # qXfer packets have the form:
        # qXfer:<object>:<operation>:<annex>:<offset>,<length>
        qxfer_prefix = b"qXfer:"
        try:
            if not payload.startswith(qxfer_prefix):
                raise ValueError
            object_name, operation, annex, position = payload.removeprefix(qxfer_prefix).split(b":", 3)
            if operation != b"read":
                return None
            offset_text, length_text = position.split(b",", 1)
            offset, requested = int(offset_text, 16), int(length_text, 16)
            if offset < 0 or requested <= 0:
                raise ValueError
        except (ValueError, TypeError):
            return b"E01"

        if object_name == b"features" and annex == b"target.xml":
            data = self._target_xml().encode()
        elif object_name == b"libraries" and not annex:
            data = self._library_xml().encode()
        elif object_name == b"exec-file":
            data = self._executable_path().encode()
        elif object_name == b"threads" and not annex:
            data = b'<threads><thread id="1" name="main"/></threads>'
        elif object_name == b"memory-map" and not annex:
            data = self._memory_map_xml().encode()
        else:
            return None

        if offset >= len(data):
            return b"l"
        # Reserve one payload byte for the m/l marker. _reply will escape data.
        chunk = data[offset : offset + min(requested, (_PACKET_SIZE - 1) // 2)]
        marker = b"l" if offset + len(chunk) >= len(data) else b"m"
        return marker + chunk

    def _target_xml(self) -> str:
        architecture = "i386:x86-64" if self.emu.get_arch() == arch.ARCH_AMD64 else "i386"
        core_parts = []
        for reg in self._registers:
            if reg.group == "vector":
                continue
            attrs = f'name="{reg.name}" bitsize="{reg.size * 8}"'
            if reg.name.startswith("st"):
                attrs += ' type="i387_ext" group="float"'
            elif reg.group:
                attrs += f' group="{reg.group}"'
            core_parts.append(f"<reg {attrs}/>")
        core = "".join(core_parts)

        vector_types = (
            '<vector id="v4f" type="ieee_single" count="4"/>'
            '<vector id="v2d" type="ieee_double" count="2"/>'
            '<vector id="v16i8" type="int8" count="16"/>'
            '<vector id="v8i16" type="int16" count="8"/>'
            '<vector id="v4i32" type="int32" count="4"/>'
            '<vector id="v2i64" type="int64" count="2"/>'
            '<union id="vec128"><field name="v4_float" type="v4f"/>'
            '<field name="v2_double" type="v2d"/><field name="v16_int8" type="v16i8"/>'
            '<field name="v8_int16" type="v8i16"/><field name="v4_int32" type="v4i32"/>'
            '<field name="v2_int64" type="v2i64"/><field name="uint128" type="uint128"/></union>'
        )
        vectors = "".join(
            f'<reg name="{reg.name}" bitsize="{reg.size * 8}" '
            f'type="{"vec128" if reg.name.startswith("xmm") else "int"}" group="vector"/>'
            for reg in self._registers
            if reg.group == "vector"
        )
        return (
            '<?xml version="1.0"?><target>'
            f"<architecture>{architecture}</architecture><osabi>Windows</osabi>"
            f'<feature name="org.gnu.gdb.i386.core">{core}</feature>'
            f'<feature name="org.gnu.gdb.i386.sse">{vector_types}{vectors}</feature></target>'
        )

    def _library_xml(self) -> str:
        lines = ['<library-list version="1.0">']
        for module in list(self.emu.modules):
            path = str(getattr(module, "emu_path", "") or getattr(module, "path", ""))
            base = getattr(module, "base", None)
            if path and isinstance(base, int):
                lines.append(
                    f'<library name="{html.escape(path, quote=True)}">'
                    f'<segment address="0x{base + 0x1000:x}"/></library>'
                )
        lines.append("</library-list>")
        return "\n".join(lines)

    def _memory_map_xml(self) -> str:
        lines = ["<memory-map>"]
        if self.emu.emu_eng is not None:
            for begin, end, perms in self.emu.emu_eng.mem_regions():
                # GDB's memory-map DTD has no permissions attribute. IDA maps
                # RAM as RWX and ROM as RX, which is the closest representation.
                memory_type = "ram" if perms & 2 else "rom"
                lines.append(f'<memory type="{memory_type}" start="0x{begin:x}" length="0x{end - begin + 1:x}"/>')
        lines.append("</memory-map>")
        return "".join(lines)

    def _executable_path(self) -> str:
        run = getattr(self.emu, "curr_run", None)
        start = getattr(run, "start_addr", None)
        if isinstance(start, int):
            module = self.emu.get_mod_from_addr(start)
            if module is not None:
                return str(getattr(module, "emu_path", ""))
        modules = list(self.emu.modules)
        return str(getattr(modules[0], "emu_path", "")) if modules else ""

    def _teb_address(self) -> int:
        thread = getattr(self.emu, "curr_thread", None)
        teb = getattr(thread, "teb", None)
        return int(getattr(teb, "address", 0) or 0)

    def _stop_reply(self, reason: StopReason) -> bytes:
        reply = f"T{reason.signal:02x}thread:1;".encode("ascii")
        if reason.kind in ("swbreak", "hwbreak"):
            reply += reason.kind.encode("ascii") + b":;"
        elif reason.kind in ("watch", "rwatch", "awatch") and reason.address is not None:
            reply += f"{reason.kind}:{reason.address:x};".encode("ascii")
        with self._state_lock:
            library_list_changed = self._library_list_changed
            self._library_list_changed = False
        if library_list_changed or reason.kind == "library":
            reply += b"library:;"
        return reply
