"""The layout, the errors and the stack slots name a memory region with the same fields."""

import copy
import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler import Run
from speakeasy.report import ErrorType, RegionInfo, Report, RunType
from tests.pe_builder import build_pe

DATA_RVA = 0x2000
TEXT_RVA = 0x1000


@pytest.fixture(scope="module")
def text_write(base_config) -> tuple[Report, int]:
    """A PE that pushes a pointer to its .data section and then writes to its own .text section."""

    def text(base, iat):
        code = b"\x68" + struct.pack("<I", base + DATA_RVA)  # push .data
        code += b"\xa3" + struct.pack("<I", base + TEXT_RVA)  # mov [.text], eax
        return code + b"\xc3"

    data, _ = build_pe(32, text=text, data=b"payload")
    with Speakeasy(config=copy.deepcopy(base_config)) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        return se.get_report(), module.base


def get_region_info(region) -> RegionInfo:
    return RegionInfo.model_validate(region.model_dump(include=set(RegionInfo.model_fields)))


def test_the_parts_of_a_module_image_have_the_module_and_the_section(text_write):
    report, base = text_write
    memory = report.runs[0].memory
    name = memory.modules[0].name

    parts = {region.section: region for region in memory.layout if region.module == name}

    assert name.endswith(".exe")
    assert {"headers", ".text", ".data"} <= set(parts)
    assert {region.tag for region in parts.values()} == {"emu.module"}
    assert (parts["headers"].base, parts[".text"].base, parts[".data"].base) == (base, base + TEXT_RVA, base + DATA_RVA)
    assert any(region.module == "kernel32.dll" and region.section == ".text" for region in memory.layout)


def test_a_tag_does_not_repeat_the_base_address(text_write):
    report, _ = text_write
    layout = report.runs[0].memory.layout

    assert not [region.tag for region in layout if region.tag and region.tag.endswith(f".0x{region.base:x}")]
    assert {"emu.stack", "emu.struct.PEB"} <= {region.tag for region in layout}


def test_the_pc_module_of_an_error_is_the_file_name_of_the_module(text_write):
    report, base = text_write
    run = report.runs[0]

    assert run.error.pc_module == run.memory.modules[0].name
    assert run.error.pc_offset == run.error.pc - base


def test_the_region_of_an_error_is_the_section_of_the_layout(text_write):
    report, base = text_write
    run = report.runs[0]
    [text] = [region for region in run.memory.layout if region.base == base + TEXT_RVA]

    assert run.error.type == ErrorType.INVALID_PROTECT_WRITE
    assert run.error.address_region == get_region_info(text)
    assert run.error.address_region.section == ".text"


def test_a_stack_slot_names_the_base_of_the_section_that_its_value_points_into(text_write):
    report, base = text_write
    run = report.runs[0]
    regions = {region.base: region for region in run.memory.layout}

    slot = run.error.stack[0]

    assert (slot.value, slot.region) == (base + DATA_RVA, base + DATA_RVA)
    assert regions[slot.region].section == ".data"
    assert all(entry.region in regions for entry in run.error.stack if entry.region is not None)


def test_a_kernel_mode_error_names_the_section_of_a_driver_module(driver_emu: Speakeasy) -> None:
    emu = driver_emu.emu
    ntoskrnl = next(module for module in emu.modules if module.get_base_name() == "ntoskrnl.exe")
    text = next(section for section in ntoskrnl.sections if section.name == ".text")
    text_base = ntoskrnl.base + text.virtual_address
    code = emu.mem_map(0x1000, tag="region_identity.code")
    emu.mem_write(code, b"\x68" + struct.pack("<I", text_base + 0x10) + b"\xa3" + struct.pack("<I", text_base))
    run = Run()
    run.type = RunType.CALL
    run.start_addr = code
    run.args = []
    emu.add_run(run)

    emu.start()

    assert run.error is not None
    assert run.error.stack[0].region == text_base
    assert run.error.address_region == RegionInfo(
        base=text_base, size=text.virtual_size, perms="r-x", tag="emu.module", module="ntoskrnl.exe", section=".text"
    )
