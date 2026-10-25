"""Export runs of a DLL start with the arguments that its exports expect."""

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.win32 import THISCALL_MEMBER

TAEF_COMMON = "0e718f955bbb13241e50cd6be867f0bc9674d4ae38dbd71803718420d23b309a.dll.xz"


@pytest.fixture(scope="module")
def taef_common_exports(base_config, load_test_bin) -> set[str]:
    with Speakeasy(config=base_config) as se:
        module = se.load_module(data=load_test_bin(TAEF_COMMON))
        return {exp.name for exp in module.get_exports()}


def test_x86_thiscall_export_starts_with_this_in_ecx(config, load_test_bin):
    """
    0e718f95 is an x86 C++ DLL whose first ten exports are TestDataArray<T> constructors,
    such as ??0?$TestDataArray@H@TestExecution@WEX@@QAE@XZ. Each one writes the two fields
    of the object at ECX and returns ECX.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(TAEF_COMMON))
        se.run_module(module, all_entrypoints=True)
        runs = [ep for ep in se.get_report().entry_points if ep.ep_type.startswith("export.")]

    assert len(runs) == 10
    assert all(run.ep_type.startswith("export.??0?$TestDataArray@") for run in runs)
    assert [run.error for run in runs] == [None] * 10
    assert runs[0].ret_val
    assert {run.ret_val for run in runs} == {runs[0].ret_val}


@pytest.mark.parametrize(
    "name, thiscall",
    [
        ("??0?$TestDataArray@H@TestExecution@WEX@@QAE@XZ", True),
        ("??0ResourceList@TestExecution@WEX@@AAE@XZ", True),
        ("?GetSize@?$TestDataArray@H@TestExecution@WEX@@QBE?BIXZ", True),
        ("?Count@Resources@TestExecution@WEX@@SGKXZ", False),
        ("?AbortApplication@TestExecution@WEX@@YGXK@Z", False),
        ("DllGetClassObject", False),
    ],
)
def test_x86_export_names_that_take_this_in_ecx(taef_common_exports, name, thiscall):
    """
    Exports of 0e718f95: public and private non-static members, also const ones (QBE),
    take this in ECX; static members (SG), free functions (YG) and C names do not.
    """
    assert name in taef_common_exports
    assert bool(THISCALL_MEMBER.match(name)) == thiscall
