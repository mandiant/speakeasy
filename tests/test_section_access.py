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

        region_by_addr = {r.address: r for r in ep.memory.layout}
        sections = {}
        for seg in primary.segments:
            region = region_by_addr.get(seg.address)
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
