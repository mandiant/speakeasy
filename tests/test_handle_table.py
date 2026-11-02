"""Handle values identify one object, and a bad handle fails the call like on Windows."""

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import call, start_process

PAGE_READWRITE = 0x04


def test_handles_of_different_types_have_different_values(dll_emu: Speakeasy) -> None:
    # Each handle type had its own counter, and the kernel object counter reached the
    # first file mapping value after 24 handles.
    start_process(dll_emu)
    events = [call(dll_emu, "kernel32", "CreateEventA", [0, 1, 0, 0])[0] for _ in range(40)]
    hmap, _ = call(
        dll_emu, "kernel32", "CreateFileMappingA", [windefs.INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0]
    )
    assert len(set(events + [hmap])) == 41
