import struct

import pytest

from speakeasy import Speakeasy

VTK_GEO_DLL = "0921d98a5aaf2c73bd8a9e93636b2e3d2de74fb09f9f8731e0a3dba080dbf136.dll.xz"

CASES = [
    ("pow", (2.0, 10.0), 1024.0),
    ("floor", (-2.5,), -3.0),
    ("ceil", (-2.5,), -2.0),
    ("ceil", (2.25,), 3.0),
    ("ceil", (float("inf"),), float("inf")),
    ("floor", (float("-inf"),), float("-inf")),
    ("sin", (0.0,), 0.0),
    ("fmod", (5.5, 2.0), 1.5),
]


@pytest.fixture(params=["x86", "amd64"])
def session(request, config):
    config["timeout"] = 2
    config["max_api_count"] = 200
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=b"\xc3", arch=request.param)
        se.run_shellcode(base)
        yield se
    finally:
        se.shutdown()


def write_code(se: Speakeasy, code: bytes) -> int:
    addr = se.mem_alloc(0x1000)
    se.mem_write(addr, code)
    return addr


def call_x86(se: Speakeasy, function: int, args: tuple[float, ...], out: int) -> bytes:
    pushes = b""
    for value in reversed(args):
        lo, hi = struct.unpack("<II", struct.pack("<d", value))
        pushes += b"\x68" + struct.pack("<I", hi) + b"\x68" + struct.pack("<I", lo)
    return (
        b"\x89\xe6"
        + pushes
        + b"\xb8"
        + struct.pack("<I", function)
        + b"\xff\xd0"
        + b"\x83\xc4"
        + bytes([8 * len(args)])
        + b"\xdd\x1d"
        + struct.pack("<I", out)
        + b"\x29\xe6\x89\x35"
        + struct.pack("<I", out + 8)
        + b"\xc3"
    )


def call_amd64(se: Speakeasy, function: int, args: tuple[float, ...], out: int) -> bytes:
    se.mem_write(out, b"".join(struct.pack("<d", value) for value in args))
    loads = b"\xf2\x0f\x10\x00"
    if len(args) > 1:
        loads += b"\xf2\x0f\x10\x48\x08"
    return (
        b"\x48\xb8"
        + struct.pack("<Q", out)
        + loads
        + b"\x48\x83\xec\x28\x48\xb8"
        + struct.pack("<Q", function)
        + b"\xff\xd0\x48\x83\xc4\x28\x48\xb8"
        + struct.pack("<Q", out)
        + b"\xf2\x0f\x11\x00\x48\xc7\x40\x08\x00\x00\x00\x00\xc3"
    )


@pytest.mark.parametrize(("api", "args", "expected"), CASES)
def test_float_functions_take_and_return_doubles_per_architecture(session, api, args, expected):
    se = session
    out = se.mem_alloc(0x1000)
    function = se.emu.get_proc("msvcrt", api)
    build = call_x86 if se.emu.get_ptr_size() == 4 else call_amd64

    se.call(write_code(se, build(se, function, args, out)))

    assert se.get_report().entry_points[-1].error is None
    result, stack_change = struct.unpack("<dI", se.mem_read(out, 12))
    assert result == expected
    assert stack_change == 0


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


@pytest.mark.parametrize(("x", "y", "expected"), [(7.5, 2.0, 1.5), (-7.5, 2.0, -1.5), (7.5, -2.0, 1.5)])
def test_ci_fmod_takes_operands_on_the_x87_stack(config, x, y, expected):
    config["timeout"] = 2
    config["max_api_count"] = 200
    se = Speakeasy(config=config)
    try:
        se.run_shellcode(se.load_shellcode(data=b"\xc3", arch="x86"))
        out = se.mem_alloc(0x1000)
        se.mem_write(out + 16, struct.pack("<dd", x, y))
        function = se.emu.get_proc("msvcrt", "_CIfmod")
        code = (
            b"\xdf\xe0\x66\xa3"
            + struct.pack("<I", out + 8)
            + b"\xdd\x05"
            + struct.pack("<I", out + 16)
            + b"\xdd\x05"
            + struct.pack("<I", out + 24)
            + b"\xb8"
            + struct.pack("<I", function)
            + b"\xff\xd0\xdd\x1d"
            + struct.pack("<I", out)
            + b"\xdf\xe0\x66\xa3"
            + struct.pack("<I", out + 10)
            + b"\xc3"
        )
        se.call(write_code(se, code))
        assert se.get_report().entry_points[-1].error is None
        result, sw_before, sw_after = struct.unpack("<dHH", se.mem_read(out, 12))
        assert result == expected
        assert sw_after & 0x3800 == sw_before & 0x3800
    finally:
        se.shutdown()
