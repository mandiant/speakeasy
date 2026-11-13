import copy
import struct

import pytest

from speakeasy import Speakeasy
from tests.pe_builder import build_pe


@pytest.fixture(scope="module")
def tracing_report(base_config, load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")
    cfg = copy.deepcopy(base_config)
    cfg["memory"]["accesses"] = True
    se = Speakeasy(config=cfg)
    try:
        module = se.load_module(data=data)
        se.run_module(module)
        return se.get_report()
    finally:
        se.shutdown()


def get_section_accesses(run):
    """Get the access counts of each part of the input image, by section name."""
    name = run.memory.modules[0].name
    sections = {region.base: region.section for region in run.memory.layout if region.module == name}
    return {sections[access.region]: access for access in run.accesses.regions if access.region in sections}


def run_tracing(base_config, data):
    cfg = copy.deepcopy(base_config)
    cfg["memory"]["accesses"] = True
    with Speakeasy(config=cfg) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        return se.get_report(), module


def test_text_section_has_execs(tracing_report):
    sections = get_section_accesses(tracing_report.runs[0])
    assert sections[".text"].execs > 0


def test_section_stats_not_identical(tracing_report):
    sections = get_section_accesses(tracing_report.runs[0])
    assert len(sections) >= 2
    assert len({(access.reads, access.writes, access.execs) for access in sections.values()}) > 1


def test_each_counted_region_is_a_used_region_of_the_layout(tracing_report):
    for run in tracing_report.runs:
        bases = [access.region for access in run.accesses.regions]
        assert bases
        assert bases == sorted(set(bases))
        assert set(bases) <= {region.base for region in run.memory.layout}
        assert all(access.reads or access.writes or access.execs for access in run.accesses.regions)


def test_untouched_section_has_no_accesses(base_config):
    # mov eax, [image base]; ret: the run reads the headers and does not touch .data.
    data, _ = build_pe(32, text=lambda base, iat: b"\xa1" + struct.pack("<I", base) + b"\xc3")
    report, _ = run_tracing(base_config, data)

    sections = get_section_accesses(report.runs[0])

    assert sections["headers"].reads > 0
    assert ".data" not in sections


def test_a_symbol_counts_only_the_accesses_at_its_address(base_config):
    def text(base, iat):
        code = b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", "GetProcessHeap"])  # call [GetProcessHeap]
        code += b"\xa1" + struct.pack("<I", base + iat["kernel32.dll", "GetProcessHeap"])  # mov eax, [IAT slot]
        code += b"\x8b\x00"  # mov eax, [eax]: read the code at the export
        return code + b"\xc3"

    data, _ = build_pe(32, text=text, imports={"kernel32.dll": ["GetProcessHeap"]})
    report, _ = run_tracing(base_config, data)

    symbols = {access.symbol: access for access in report.runs[0].accesses.symbols}

    assert not [symbol for symbol in symbols if "+" in symbol]
    assert (symbols["kernel32.GetProcessHeap"].reads, symbols["kernel32.GetProcessHeap"].execs) == (1, 1)


def test_no_accesses_without_the_option(config):
    data, _ = build_pe(32, text=b"\xc3")
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=data))
        assert se.get_report().runs[0].accesses is None
