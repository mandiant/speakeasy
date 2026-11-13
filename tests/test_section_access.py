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


def get_primary_sections(report):
    for ep in report.entry_points:
        if ep.memory is None:
            continue

        primary = max(
            (m for m in ep.memory.modules if m.segments),
            key=lambda m: len(m.segments),
            default=None,
        )
        if not primary:
            continue

        region_by_addr = {r.base: r for r in ep.memory.layout}
        sections = {}
        for seg in primary.segments:
            region = region_by_addr.get(seg.base)
            if region:
                sections[seg.name.lstrip(".")] = region
        if sections:
            return sections
    return {}


def test_text_section_has_execs(tracing_report):
    sections = get_primary_sections(tracing_report)
    assert "text" in sections
    text = sections["text"]
    assert text.accesses is not None
    assert text.accesses.execs > 0


def test_section_stats_not_identical(tracing_report):
    sections = get_primary_sections(tracing_report)
    assert len(sections) >= 2

    stats = {}
    for name, region in sections.items():
        if region.accesses is not None:
            stats[name] = (region.accesses.reads, region.accesses.writes, region.accesses.execs)

    assert len(set(stats.values())) > 1


def test_untouched_section_has_no_accesses(base_config):
    # mov eax, [image base]; ret: the run reads the headers and does not touch .data.
    data, _ = build_pe(32, text=lambda base, iat: b"\xa1" + struct.pack("<I", base) + b"\xc3")
    cfg = copy.deepcopy(base_config)
    cfg["memory"]["accesses"] = True
    with Speakeasy(config=cfg) as se:
        module = se.load_module(data=data)
        se.run_module(module)
        report = se.get_report()

    image = range(module.base, module.base + module.image_size)
    layout = {r.tag.split(".")[-2]: r for r in report.entry_points[0].memory.layout if r.base in image}
    assert layout["headers"].accesses is not None
    assert layout["headers"].accesses.reads > 0
    assert layout["data"].accesses is None
