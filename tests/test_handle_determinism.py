import pytest

from speakeasy import Speakeasy


@pytest.mark.parametrize("bin_file", ["argv_test_x86.exe.xz"])
def test_sequential_runs_are_deterministic(config, load_test_bin, bin_file):
    """Running the same sample twice in one process must produce identical pid/tid."""
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
