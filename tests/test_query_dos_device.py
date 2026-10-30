import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, start_process


def _query(se: Speakeasy, wide: bool, device: str | None, count: int) -> tuple[int, bytes, int]:
    name = alloc(se, (device + "\0").encode("utf-16le" if wide else "ascii")) if device is not None else 0
    buf = alloc(se, b"\xcc" * 128)
    rv, _ = call(se, "kernel32", "QueryDosDeviceW" if wide else "QueryDosDeviceA", [name, buf, count])
    return rv, se.mem_read(buf, 128), se.emu.get_last_error()


@pytest.mark.parametrize("wide", [False, True])
def test_query_dos_device_mapping_and_exact_capacity(dll_emu: Speakeasy, wide: bool) -> None:
    start_process(dll_emu)
    expected = "\\Device\\HarddiskVolume1\0\0".encode("utf-16le" if wide else "ascii")
    count = len(expected) // (2 if wide else 1)
    rv, data, _ = _query(dll_emu, wide, "c:", count)
    assert (rv, data[: len(expected) + 1]) == (count, expected + b"\xcc")
    rv, data, error = _query(dll_emu, wide, "c:", count - 1)
    assert (rv, data, error) == (0, b"\xcc" * 128, 122)


@pytest.mark.parametrize("wide", [False, True])
def test_query_dos_device_enumerates_names(dll_emu: Speakeasy, wide: bool) -> None:
    start_process(dll_emu)
    expected = "C:\0\0".encode("utf-16le" if wide else "ascii")
    rv, data, _ = _query(dll_emu, wide, None, 4)
    assert (rv, data[: len(expected) + 1]) == (4, expected + b"\xcc")


@pytest.mark.parametrize("device", ["", "Z:", "C:\\"])
@pytest.mark.parametrize("wide", [False, True])
def test_query_dos_device_unknown_name_leaves_buffer_untouched(dll_emu: Speakeasy, device: str, wide: bool) -> None:
    start_process(dll_emu)
    assert _query(dll_emu, wide, device, 100) == (0, b"\xcc" * 128, 2)


def test_query_dos_device_rejects_null_output(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    rv, _ = call(dll_emu, "kernel32", "QueryDosDeviceA", [0, 0, 100])
    assert (rv, dll_emu.emu.get_last_error()) == (0, 87)
