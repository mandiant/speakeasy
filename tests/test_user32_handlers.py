"""
User32 handlers return what Windows returns and write only what the caller owns.
"""

import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, start_process


@pytest.mark.parametrize("fixture, size", [("dll_emu", 28), ("dll64_emu", 48)])
def test_get_message_writes_one_msg(request: pytest.FixtureRequest, fixture: str, size: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    call(se, "user32", "SetTimer", [0, 1, 10, 0])
    buf = alloc(se, b"\xcc" * 0x40)
    rv, _ = call(se, "user32", "GetMessageA", [buf, 0x1234, 0, 0])
    assert rv
    data = se.mem_read(buf, 0x40)
    assert data[size:] == b"\xcc" * (0x40 - size)
    assert int.from_bytes(data[se.emu.get_ptr_size() : se.emu.get_ptr_size() + 4], "little") == 0x113

    rv, _ = call(se, "user32", "DispatchMessageA", [buf])
    assert rv == 0
