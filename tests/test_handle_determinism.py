import pytest


@pytest.mark.parametrize("bin_file", ["argv_test_x86.exe.xz"])
def test_sequential_runs_are_deterministic(config, load_test_bin, bin_file):
    """Running the same sample twice in one process must produce identical pid/tid."""
    from speakeasy import Speakeasy

    data = load_test_bin(bin_file)

    def run_once():
        se = Speakeasy(config=config, argv=[])
        try:
            module = se.load_module(data=data)
            se.run_module(module, all_entrypoints=True)
            return se.get_report()
        finally:
            se.shutdown()

    r1 = run_once()
    r2 = run_once()

    for ep1, ep2 in zip(r1.entry_points, r2.entry_points):
        assert ep1.pid == ep2.pid
        assert ep1.tid == ep2.tid


@pytest.mark.parametrize("bin_file", ["argv_test_x86.exe.xz"])
def test_instances_are_isolated(config, load_test_bin, bin_file):
    """Two Speakeasy objects must not share handle sequences."""
    from speakeasy import Speakeasy
    from speakeasy.windows.objman import HandleAllocator

    data = load_test_bin(bin_file)

    se1 = Speakeasy(config=config, argv=[])
    se2 = Speakeasy(config=config, argv=[])
    se1.load_module(data=data)
    se2.load_module(data=data)

    assert se1.emu.handle_allocator is not se2.emu.handle_allocator
    assert isinstance(se1.emu.handle_allocator, HandleAllocator)
    assert isinstance(se2.emu.handle_allocator, HandleAllocator)

    se1.shutdown()
    se2.shutdown()
