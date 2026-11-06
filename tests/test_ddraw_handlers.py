"""DirectDraw reports that the computer has no DirectDraw hardware."""

import uuid

import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call

DDERR_NODIRECTDRAWHW = 0x88760233
DDCREATE_HARDWAREONLY = 1
IID_IDIRECTDRAW7 = uuid.UUID("15e65ec0-3b9c-11d2-b92f-00609797ea5b")


@pytest.mark.parametrize("emu_fixture, ptr_size", [("dll_emu", 4), ("dll64_emu", 8)])
@pytest.mark.parametrize("guid", [0, DDCREATE_HARDWAREONLY])
def test_direct_draw_create_reports_no_hardware(
    request: pytest.FixtureRequest, emu_fixture: str, ptr_size: int, guid: int
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_fixture)
    out = alloc(se, b"\xcc" * 8)
    rv, _ = call(se, "ddraw", "DirectDrawCreate", [guid, out, 0])
    assert rv == DDERR_NODIRECTDRAWHW
    assert se.mem_read(out, 8) == bytes(ptr_size) + b"\xcc" * (8 - ptr_size)


@pytest.mark.parametrize("emu_fixture, ptr_size", [("dll_emu", 4), ("dll64_emu", 8)])
def test_direct_draw_create_ex_reports_no_hardware(
    request: pytest.FixtureRequest, emu_fixture: str, ptr_size: int
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_fixture)
    out = alloc(se, b"\xcc" * 8)
    iid = alloc(se, IID_IDIRECTDRAW7.bytes_le)
    rv, _ = call(se, "ddraw", "DirectDrawCreateEx", [0, out, iid, 0])
    assert rv == DDERR_NODIRECTDRAWHW
    assert se.mem_read(out, 8) == bytes(ptr_size) + b"\xcc" * (8 - ptr_size)
