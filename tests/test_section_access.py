import copy

import pytest

from speakeasy import Speakeasy


@pytest.fixture(scope="module")
def tracing_report(base_config, load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")
    cfg = copy.deepcopy(base_config)
    cfg["analysis"] = dict(cfg.get("analysis", {}))
    cfg["analysis"]["memory_tracing"] = True
    se = Speakeasy(config=cfg)
    try:
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        return se.get_report()
    finally:
        se.shutdown()


def _get_primary_sections(report):
    """Return {section_name: MemoryRegion} for the primary module.

    Uses the loaded modules list to find the primary module (the one with
    the most segments, excluding system decoys), then matches memory regions
    by address to get per-section access stats.
    """
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

        region_by_addr = {r.address: r for r in ep.memory.layout}
        sections = {}
        for seg in primary.segments:
            region = region_by_addr.get(seg.address)
            if region:
                name = seg.name.lstrip(".")
                sections[name] = region
        if sections:
            return sections
    return {}


def test_text_section_has_execs(tracing_report):
    """The .text section of the emulated DLL should record execution counts."""
    sections = _get_primary_sections(tracing_report)
    assert "text" in sections, f"No .text section found; got sections: {list(sections)}"
    text = sections["text"]
    assert text.accesses is not None, ".text section has no access stats"
    assert text.accesses.execs > 0, ".text section should have execs > 0"


def test_rdata_section_no_execs(tracing_report):
    """The .rdata section should not have execution counts (it's not executable)."""
    sections = _get_primary_sections(tracing_report)
    if "rdata" not in sections:
        pytest.skip("No .rdata section in primary module")
    rdata = sections["rdata"]
    if rdata.accesses is None:
        return
    assert rdata.accesses.execs == 0, f".rdata should have 0 execs, got {rdata.accesses.execs}"


def test_section_stats_not_identical(tracing_report):
    """Different sections should have different access stats, not the same module-level aggregate."""
    sections = _get_primary_sections(tracing_report)
    assert len(sections) >= 2, "Need at least 2 sections to compare"

    stats = {}
    for name, region in sections.items():
        if region.accesses is not None:
            stats[name] = (region.accesses.reads, region.accesses.writes, region.accesses.execs)

    unique_stats = set(stats.values())
    assert len(unique_stats) > 1, f"All sections have identical access stats — tracking is still module-level: {stats}"


def test_non_module_regions_still_tracked(tracing_report):
    """Non-module memory (stack, heap) should still get access stats via MemMap fallback."""
    for ep in tracing_report.entry_points:
        if ep.memory is None:
            continue
        for region in ep.memory.layout:
            if region.tag.startswith("emu.stack") and region.accesses is not None:
                assert region.accesses.reads + region.accesses.writes > 0
                return
    pytest.skip("No stack region with access stats found")
