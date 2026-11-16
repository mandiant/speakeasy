"""_CxxThrowException raises the C++ exception that the MSVC runtime raises, and does not return."""

import struct

import pytest

from speakeasy import Speakeasy
from tests.guest_harness import get_api, guest_call

EH_EXCEPTION_NUMBER = 0xE06D7363
EH_MAGIC_NUMBER1 = 0x19930520
EXCEPTION_NONCONTINUABLE = 0x01
EXCEPTION_OBJECT = 0x1234

RETURN_42 = b"\xb8\x2a\x00\x00\x00\xc3"


def copy_record_handler(arch, data):
    """A vectored handler that copies the exception record to ``data`` and continues the search."""
    if arch == "amd64":
        code = b"\x56\x57\x48\x8b\x31"  # push rsi; push rdi; mov rsi, [rcx]
        code += b"\x48\xbf" + struct.pack("<Q", data)  # mov rdi, data
        code += b"\xb9\x98\x00\x00\x00\xf3\xa4"  # mov ecx, sizeof(EXCEPTION_RECORD); rep movsb
        return code + b"\x5f\x5e\x31\xc0\xc3"
    code = b"\x56\x57\x8b\x44\x24\x0c\x8b\x30"  # push esi; push edi; mov eax, [esp + 0xc]; mov esi, [eax]
    code += b"\xbf" + struct.pack("<I", data)  # mov edi, data
    code += b"\xb9\x50\x00\x00\x00\xf3\xa4"  # mov ecx, sizeof(EXCEPTION_RECORD); rep movsb
    return code + b"\x5f\x5e\x31\xc0\xc2\x04\x00"


def read_record(se, arch, data):
    """Return the code, flags and parameters of the record at ``data``."""
    if arch == "amd64":
        code, flags, count = struct.unpack_from("<II16xI", se.mem_read(data, 0x1C))
        return code, flags, list(struct.unpack(f"<{count}Q", se.mem_read(data + 0x20, 8 * count)))
    code, flags, count = struct.unpack_from("<II8xI", se.mem_read(data, 0x14))
    return code, flags, list(struct.unpack(f"<{count}I", se.mem_read(data + 0x14, 4 * count)))


@pytest.mark.parametrize("arch", ["amd64", "x86"])
def test_cxx_throw_raises_the_msvc_exception_and_does_not_return(config, arch):
    ptr_size = 8 if arch == "amd64" else 4
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x2000, arch=arch)
        data = se.mem_alloc(0x1000)
        handler = code + 0x1000
        se.mem_write(handler, copy_record_handler(arch, data))
        throw = get_api(se, "msvcrt", "_CxxThrowException")
        throw_info = get_api(se, "kernel32", "GetLastError")  # any address in a module
        setup = guest_call(ptr_size, get_api(se, "kernel32", "AddVectoredExceptionHandler"), 1, handler)
        se.mem_write(code, setup + guest_call(ptr_size, throw, EXCEPTION_OBJECT, throw_info) + RETURN_42)

        se.run_shellcode(code)

        run = se.get_report().runs[0]
        assert run.error is not None
        assert run.error.type == "unhandled_exception"
        call = next(e for e in run.events if e.event == "api" and e.api_name == "msvcrt._CxxThrowException")
        assert run.error.pc == call.pos.pc
        params = [EH_MAGIC_NUMBER1, EXCEPTION_OBJECT, throw_info]
        if arch == "amd64":
            params.append(se.emu.get_mod_from_addr(throw_info).base)
        assert read_record(se, arch, data) == (EH_EXCEPTION_NUMBER, EXCEPTION_NONCONTINUABLE, params)
