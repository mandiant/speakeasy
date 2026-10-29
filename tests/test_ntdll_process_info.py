import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.usermode.kernel32 import PROCESSOR_COUNT


@pytest.mark.parametrize(
    "arch, start, stop, offset",
    [
        ("x86", 0x4613, 0x4626, 0x64),
        ("x64", 0x4212, 0x422F, 0xB8),
    ],
    ids=["x86", "x64"],
)
def test_peb_number_of_processors_matches_get_system_info(
    config: dict, load_test_bin, arch: str, start: int, stop: int, offset: int
) -> None:
    """
    al-khaser reads NumberOfProcessors from the PEB, at eax/rax + offset, and reports a
    virtual machine when it is less than 2: cl = NumberOfProcessors < 2, then a call to its
    report function.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(f"al-khaser_{arch}.exe.xz"))
        seen = []

        def at_report(emu, address, size):
            peb = se.reg_read("eax" if arch == "x86" else "rax")
            processors = int.from_bytes(se.mem_read(peb + offset, 4), "little")
            seen.append((processors, se.reg_read("ecx") & 0xFF))
            se.stop()

        se.add_code_hook(at_report, begin=module.base + stop, end=module.base + stop)
        se.run_module(module, entry_point=start)
        run = next(e for e in se.get_report().entry_points if e.ep_type == "module_entry")

    assert run.error is None
    assert seen == [(PROCESSOR_COUNT, 0)]
