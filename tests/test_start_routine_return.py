"""The entry point of an EXE and the start routine of a thread return into kernel32, as on Windows."""

import struct

import pytest

from speakeasy import Speakeasy
from tests.pe_builder import build_pe

CREATE_THREAD = {"kernel32.dll": ["CreateThread"]}


def find_image_base(arch, step):
    """Code that searches down from its return address, in steps of ``step`` bytes, for MZ and returns the address."""
    mask = struct.pack("<I", -step & 0xFFFFFFFF)
    if arch == 32:
        # mov eax, [esp]; and eax, mask
        # loop: cmp word [eax], 'MZ'; je found; sub eax, step; jmp loop
        # found: ret
        return (
            b"\x8b\x04\x24\x25" + mask + b"\x66\x81\x38\x4d\x5a\x74\x07\x2d" + struct.pack("<I", step) + b"\xeb\xf2\xc3"
        )
    # mov rax, [rsp]; and rax, mask
    # loop: cmp word [rax], 'MZ'; je found; sub rax, step; jmp loop
    # found: ret
    return (
        b"\x48\x8b\x04\x24\x48\x25"
        + mask
        + b"\x66\x81\x38\x4d\x5a\x74\x08\x48\x2d"
        + struct.pack("<I", step)
        + b"\xeb\xf1\xc3"
    )


def start_thread(arch, start_routine):
    """Code that calls CreateThread(NULL, 0, start_routine, NULL, 0, NULL) and returns, followed by start_routine."""

    def text(base, iat):
        if arch == 32:
            start = base + 0x1000 + 22
            code = b"\x6a\x00" * 3 + b"\x68" + struct.pack("<I", start) + b"\x6a\x00" * 2
            code += b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", "CreateThread"]) + b"\xc3"
        else:
            # sub rsp, 0x38; xor ecx, ecx; xor edx, edx; lea r8, [rip + start]; xor r9d, r9d
            code = b"\x48\x83\xec\x38\x31\xc9\x31\xd2\x4c\x8d\x05" + struct.pack("<i", 32) + b"\x45\x31\xc9"
            # mov qword [rsp + 0x20], 0; mov qword [rsp + 0x28], 0
            code += b"\x48\xc7\x44\x24\x20\0\0\0\0\x48\xc7\x44\x24\x28\0\0\0\0"
            # call [rip + CreateThread]; add rsp, 0x38; ret
            code += b"\xff\x15" + struct.pack("<i", iat["kernel32.dll", "CreateThread"] - (0x1000 + 42))
            code += b"\x48\x83\xc4\x38\xc3"
        return code + start_routine

    return text


def run_exe(config, data):
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=data))
        return se.get_report().runs


def get_kernel32_base(entry):
    assert entry.memory is not None
    return next(module.base for module in entry.memory.modules if module.name == "kernel32.dll")


def api_names(entry):
    return [event.api_name for event in entry.events if event.event == "api"]


@pytest.mark.parametrize("arch", [32, 64])
@pytest.mark.parametrize("step", [0x10000, 0x1000])
def test_entry_point_finds_kernel32_below_its_return_address(config, arch, step):
    data, _ = build_pe(arch, text=find_image_base(arch, step))

    (entry,) = run_exe(config, data)

    assert entry.error is None
    assert entry.return_value == get_kernel32_base(entry)
    assert api_names(entry) == []


@pytest.mark.parametrize("arch", [32, 64])
@pytest.mark.parametrize("step", [0x10000, 0x1000])
def test_thread_start_routine_finds_kernel32_below_its_return_address(config, arch, step):
    data, _ = build_pe(arch, text=start_thread(arch, find_image_base(arch, step)), imports=CREATE_THREAD)

    main, thread = run_exe(config, data)

    assert main.error is None
    assert api_names(main) == ["kernel32.CreateThread"]
    assert thread.type == "thread"
    assert thread.error is None
    assert thread.return_value == get_kernel32_base(thread)
    assert api_names(thread) == []
