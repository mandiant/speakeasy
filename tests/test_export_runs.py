"""Export runs of a DLL start with the arguments that its exports expect."""

import pefile
import pytest

from speakeasy import Speakeasy
from speakeasy.windows.win32 import THISCALL_MEMBER

TAEF_COMMON = "0e718f955bbb13241e50cd6be867f0bc9674d4ae38dbd71803718420d23b309a.dll.xz"


@pytest.fixture(scope="module")
def taef_common_exports(base_config, load_test_bin) -> set[str]:
    with Speakeasy(config=base_config) as se:
        module = se.load_module(data=load_test_bin(TAEF_COMMON))
        return {exp.name for exp in module.get_exports()}


@pytest.mark.parametrize(("exports", "types"), [(True, ["dll_entry", "export", "export"]), (False, ["dll_entry"])])
def test_exports_run_only_if_runs_exports_is_true(config, load_test_bin, exports, types):
    config["runs"] = {"exports": exports}
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=load_test_bin("dll_test_x86.dll.xz")))
        assert [ep.type for ep in se.get_report().runs] == types


def test_export_without_a_name_runs_with_its_ordinal_as_name(config, load_test_bin):
    """dll_test_x86.dll exports emu_test_one and emu_test_two. With NumberOfNames 0, they have only ordinals 1 and 2."""
    data = bytearray(load_test_bin("dll_test_x86.dll.xz"))
    pe = pefile.PE(data=bytes(data))
    offset = pe.DIRECTORY_ENTRY_EXPORT.struct.get_field_absolute_offset("NumberOfNames")
    data[offset : offset + 4] = bytes(4)
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=bytes(data)))
        runs = [ep for ep in se.get_report().runs if ep.type == "export"]

    assert [run.name for run in runs] == ["#1", "#2"]


def test_x86_thiscall_export_starts_with_this_in_ecx(config, load_test_bin):
    """
    0e718f95 is an x86 C++ DLL whose first ten exports are TestDataArray<T> constructors.

    An example is ``??0?$TestDataArray@H@TestExecution@WEX@@QAE@XZ``. Each one writes the two fields of
    the object at ECX and returns ECX.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(TAEF_COMMON))
        se.run_module(module)
        runs = [ep for ep in se.get_report().runs if ep.type == "export"]

    assert len(runs) == 10
    assert all(run.name.startswith("??0?$TestDataArray@") for run in runs)
    assert [run.error for run in runs] == [None] * 10
    assert runs[0].return_value
    assert {run.return_value for run in runs} == {runs[0].return_value}


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
    Exports of 0e718f95 take ``this`` in ECX only if they are non-static members.

    Public and private members, also const ones (QBE), take it. Static members (SG), free functions (YG)
    and C names do not.
    """
    assert name in taef_common_exports
    assert bool(THISCALL_MEMBER.match(name)) == thiscall
