# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


import pytest

from speakeasy import Speakeasy


@pytest.mark.parametrize(
    "bin_file",
    [
        "dll_test_x86.dll.xz",
    ],
)
class TestMemoryCapture:
    def test_memory_layout_exists(self, config, load_test_bin, bin_file):
        data = load_test_bin(bin_file)
        se = Speakeasy(config=config)
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()

        eps = report.entry_points
        assert len(eps) > 0

        eps_with_memory = [ep for ep in eps if ep.memory is not None]
        assert len(eps_with_memory) > 0, "Expected at least one entry point with memory layout"

    def test_memory_layout_has_regions(self, config, load_test_bin, bin_file):
        data = load_test_bin(bin_file)
        se = Speakeasy(config=config)
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()

        for ep in report.entry_points:
            if ep.memory is None:
                continue
            layout = ep.memory.layout
            assert isinstance(layout, list)
            assert len(layout) > 0, "Expected at least one memory region"

            for region in layout:
                assert region.tag is not None
                assert region.address is not None
                assert region.address > 0
                assert region.size is not None
                assert region.size > 0
                assert region.prot in ("---", "r--", "-w-", "--x", "rw-", "r-x", "-wx", "rwx", "???")

    def test_memory_layout_has_modules(self, config, load_test_bin, bin_file):
        data = load_test_bin(bin_file)
        se = Speakeasy(config=config)
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()

        for ep in report.entry_points:
            if ep.memory is None:
                continue
            modules = ep.memory.modules
            assert isinstance(modules, list)
            assert len(modules) > 0, "Expected at least one loaded module"

            for mod in modules:
                assert mod.name is not None
                assert len(mod.name) > 0
                assert mod.path is not None
                assert mod.base is not None
                assert mod.base > 0
                assert mod.size is not None
                assert mod.size > 0

    def test_modules_have_segments(self, config, load_test_bin, bin_file):
        """Modules should have segments populated from PE sections."""
        data = load_test_bin(bin_file)
        se = Speakeasy(config=config)
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()

        for ep in report.entry_points:
            if ep.memory is None:
                continue
            modules = ep.memory.modules
            assert len(modules) > 0

            modules_with_segments = [m for m in modules if len(m.segments) > 0]
            assert len(modules_with_segments) > 0, "Expected at least one module with segments"

            for mod in modules_with_segments:
                for seg in mod.segments:
                    assert seg.name is not None
                    assert seg.address is not None
                    assert seg.address > 0
                    assert seg.size is not None
                    assert seg.prot in ("---", "r--", "-w-", "--x", "rw-", "r-x", "-wx", "rwx", "???")

    def test_module_segments_within_module_bounds(self, config, load_test_bin, bin_file):
        """Module segments should fall within the module's base address and size."""
        data = load_test_bin(bin_file)
        se = Speakeasy(config=config)
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()

        for ep in report.entry_points:
            if ep.memory is None:
                continue
            for mod in ep.memory.modules:
                for seg in mod.segments:
                    assert seg.address >= mod.base, (
                        f"Segment {seg.name} address {hex(seg.address)} is below module base {hex(mod.base)}"
                    )
                    seg_end = seg.address + seg.size
                    mod_end = mod.base + mod.size
                    assert seg_end <= mod_end, (
                        f"Segment {seg.name} end {hex(seg_end)} exceeds module end {hex(mod_end)}"
                    )
