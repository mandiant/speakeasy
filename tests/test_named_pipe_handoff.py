"""
A thread that waits on a named pipe runs the thread at the other end, as in the Cobalt Strike Artifact Kit.

In each program, the main thread starts a thread, opens one end of a pipe and reads twice. The thread opens
the other end, writes a message and closes its handle.
"""

import struct

from speakeasy import Speakeasy
from tests.pe_builder import build_pe

IMPORTS = {
    "kernel32.dll": [
        "CreateThread",
        "CreateNamedPipeA",
        "ConnectNamedPipe",
        "CreateFileA",
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "GetLastError",
    ]
}

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
PIPE_ACCESS_INBOUND = 1
PIPE_ACCESS_OUTBOUND = 2
ERROR_BROKEN_PIPE = 109

READER_NAME = 0x00
WRITER_NAME = 0x40
MESSAGE = 0x80
BUFFER = 0x90
READER = 0xD0
WRITER = 0xD4
FIRST_READ = 0xD8
FIRST_COUNT = 0xDC
SECOND_READ = 0xE0
SECOND_COUNT = 0xE4
SECOND_ERROR = 0xE8
WRITTEN = 0xEC

PIPE = b"\\\\.\\pipe\\handoff"


class Mem(int):
    """An argument that the code pushes from memory, not as an immediate."""


def call(iat, name, *args, store=None):
    """Assemble a stdcall call through the IAT, and optionally store EAX."""
    code = b"".join((b"\xff\x35" if isinstance(a, Mem) else b"\x68") + struct.pack("<I", a) for a in reversed(args))
    code += b"\xff\x15" + struct.pack("<I", iat[name])
    if store is not None:
        code += b"\xa3" + struct.pack("<I", store)
    return code


def open_server(iat, data, name, handle, access):
    code = call(iat, "CreateNamedPipeA", data + name, access, 0, 1, 0x100, 0x100, 0, 0, store=data + handle)
    return code + call(iat, "ConnectNamedPipe", Mem(data + handle), 0)


def open_client(iat, data, name, handle, access):
    return call(iat, "CreateFileA", data + name, access, 0, 0, OPEN_EXISTING, 0, 0, store=data + handle)


def build_handoff(main_is_server, reader_name=PIPE, writer_name=PIPE):
    """Build an EXE whose main thread reads from a pipe that a second thread writes to."""

    def text(base, iat_rva):
        iat = {name: base + rva for (_, name), rva in iat_rva.items()}
        data = base + 0x2000
        open_reader, open_writer = (open_server, open_client) if main_is_server else (open_client, open_server)
        reader_access, writer_access = (
            (PIPE_ACCESS_INBOUND, GENERIC_WRITE) if main_is_server else (GENERIC_READ, PIPE_ACCESS_OUTBOUND)
        )

        def main(thread):
            code = call(iat, "CreateThread", 0, 0, thread, 0, 0, 0)
            code += open_reader(iat, data, READER_NAME, READER, reader_access)
            for buffer, count, result in (
                (BUFFER, FIRST_COUNT, FIRST_READ),
                (BUFFER + 0x20, SECOND_COUNT, SECOND_READ),
            ):
                code += call(
                    iat, "ReadFile", Mem(data + READER), data + buffer, 0x20, data + count, 0, store=data + result
                )
            code += call(iat, "GetLastError", store=data + SECOND_ERROR)
            return code + b"\xc3"

        thread = open_writer(iat, data, WRITER_NAME, WRITER, writer_access)
        thread += call(iat, "WriteFile", Mem(data + WRITER), data + MESSAGE, 5, data + WRITTEN, 0)
        thread += call(iat, "CloseHandle", Mem(data + WRITER))
        # xor eax, eax; ret 4
        thread += b"\x31\xc0\xc2\x04\x00"
        return main(base + 0x1000 + len(main(0))) + thread

    data = bytearray(0x100)
    data[READER_NAME : READER_NAME + len(reader_name)] = reader_name
    data[WRITER_NAME : WRITER_NAME + len(writer_name)] = writer_name
    data[MESSAGE : MESSAGE + 5] = b"hello"
    return build_pe(32, text=text, data=bytes(data), imports=IMPORTS)[0]


def run_handoff(config, exe):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=exe)
        se.run_module(module)
        return se.mem_read(module.base + 0x2000, 0x100), se.get_report().entry_points


def read_dword(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def assert_reads_message_then_broken_pipe(data):
    assert read_dword(data, FIRST_READ) == 1
    assert data[BUFFER : BUFFER + read_dword(data, FIRST_COUNT)] == b"hello"
    assert read_dword(data, SECOND_READ) == 0
    assert read_dword(data, SECOND_COUNT) == 0
    assert read_dword(data, SECOND_ERROR) == ERROR_BROKEN_PIPE


def test_client_open_runs_the_server_thread_and_reads_what_it_wrote(config):
    data, (main, *threads) = run_handoff(config, build_handoff(main_is_server=False))

    assert main.error is None
    assert read_dword(data, READER) not in (0, 0xFFFFFFFF)
    assert_reads_message_then_broken_pipe(data)
    assert threads == []


def test_server_read_runs_the_client_thread_and_reads_what_it_wrote(config):
    data, (main, *threads) = run_handoff(config, build_handoff(main_is_server=True))

    assert main.error is None
    assert read_dword(data, WRITER) not in (0, 0xFFFFFFFF)
    assert_reads_message_then_broken_pipe(data)
    assert threads == []


def test_client_opens_the_pipe_with_a_different_case_of_the_name(config):
    data, _ = run_handoff(config, build_handoff(main_is_server=False, reader_name=b"\\\\.\\PIPE\\Handoff"))

    assert data[BUFFER : BUFFER + read_dword(data, FIRST_COUNT)] == b"hello"
