import copy
import shutil
from pathlib import Path

from speakeasy import Speakeasy


def test_map_view_of_file_uses_readable_protections(base_config, tmp_path):
    src = Path(__file__).resolve().parent / "capa-testfiles"
    exe_src = src / "Practical Malware Analysis Lab 01-01.exe_"
    dll_src = src / "Practical Malware Analysis Lab 01-01.dll_"
    k32_src = src / "kernel32.dll_"

    exe_path = tmp_path / exe_src.name
    shutil.copy2(exe_src, exe_path)
    shutil.copy2(dll_src, tmp_path / "Lab01-01.dll")
    shutil.copy2(k32_src, tmp_path / "Kernel32.dll")

    cfg = copy.deepcopy(base_config)
    se = Speakeasy(config=cfg, argv=["WARNING_THIS_WILL_DESTROY_YOUR_MACHINE"])
    try:
        module = se.load_module(path=str(exe_path))
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
    finally:
        se.shutdown()

    ep = report.entry_points[0]
    assert ep.memory is not None

    map_views = [region for region in ep.memory.layout if region.tag.startswith("api.MapViewOfFile.")]
    assert len(map_views) >= 2

    for region in map_views:
        assert region.prot in {"r--", "rw-", "r-x", "rwx"}

    if ep.error is not None:
        assert ep.error.type != "Read from non-readable memory (UC_ERR_READ_PROT)"
