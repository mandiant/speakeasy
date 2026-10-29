import struct

import pytest

from speakeasy import Speakeasy

VTK_GEO_DLL = "0921d98a5aaf2c73bd8a9e93636b2e3d2de74fb09f9f8731e0a3dba080dbf136.dll.xz"

# Bits of the return value of float_cases.c, one per case
FLOAT_CASES = {
    0x01: "pow(2, 10) is 1024",
    0x02: "floor(-2.5) is -3",
    0x04: "ceil(-2.5) is -2",
    0x08: "ceil(2.25) is 3",
    0x10: "ceil(inf) is inf",
    0x20: "floor(-inf) is -inf",
    0x40: "sin(0) is 0",
    0x80: "fmod(5.5, 2) is 1.5",
}

FLOAT_CASES_X64 = {
    0x100: "ceilf(2.25f) is 3.0f",
    0x200: "floorf(-2.5f) is -3.0f",
}

CI_FMOD_CASES_X86 = {
    0x100: "_CIfmod of 7.5 and 2 is 1.5",
    0x200: "_CIfmod of -7.5 and 2 is -1.5",
    0x400: "_CIfmod of 7.5 and -2 is 1.5",
}


def get_failed_cases(config, load_test_bin, run_test, arch: str, cases: dict[int, str]) -> list[str]:
    report = run_test(config, load_test_bin(f"float_cases_{arch}.exe.xz"))
    ep = report.entry_points[0]
    assert ep.error is None
    return [case for bit, case in cases.items() if not ep.ret_val & bit]


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_float_functions_take_and_return_values_per_architecture(config, load_test_bin, run_test, arch):
    cases = FLOAT_CASES | FLOAT_CASES_X64 if arch == "x64" else FLOAT_CASES
    assert not get_failed_cases(config, load_test_bin, run_test, arch, cases)


def test_fmod_takes_and_returns_doubles_in_xmm_registers_on_amd64(config, load_test_bin):
    """
    0921d98a is a VTK DLL. Its export vtkGeoTransform::ComputeUTMZone(double*) brings a
    longitude and latitude into range with fmod(lon + 180, 360) - 180 and
    fmod(lat + 90, 180) - 90, then returns the UTM zone of the point.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(VTK_GEO_DLL))
        se.run_module(module)
        compute_utm_zone = module.get_export_by_name("?ComputeUTMZone@vtkGeoTransform@vtk96@@SAHPEAN@Z").address
        point = se.mem_alloc(0x1000)
        zones = []
        for lon, lat in [(13.4, 52.5), (190.0, 10.0), (13.4, 232.5)]:
            se.mem_write(point, struct.pack("<dd", lon, lat))
            se.call(compute_utm_zone, [point])
            run = se.get_report().entry_points[-1]
            assert run.error is None
            assert [event.api_name for event in run.events if event.event == "api"] == ["msvcrt.fmod"] * 2
            zones.append(run.ret_val)

    assert zones == [33, 2, 33]


def test_ci_fmod_takes_operands_on_the_x87_stack(config, load_test_bin, run_test):
    assert not get_failed_cases(config, load_test_bin, run_test, "x86", CI_FMOD_CASES_X86)
