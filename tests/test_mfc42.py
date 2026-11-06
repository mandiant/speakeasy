"""MFC 4.2 programs that import mfc42.dll and mfc42u.dll by ordinal."""

import struct

import pytest

from speakeasy import Speakeasy
from tests.pe_builder import build_pe

AFX_GET_MODULE_STATE = 1168


def call_ordinals(dll: str, ordinals: list[int]):
    """Call each ordinal import of ``dll`` and store each return value in .data."""

    def text(base: int, iat: dict) -> bytes:
        code = b""
        for index, ordinal in enumerate(ordinals):
            code += b"\xff\x15" + struct.pack("<I", base + iat[dll, ordinal])
            code += b"\xa3" + struct.pack("<I", base + 0x2000 + index * 4)
        return code + b"\xc3"

    return text


def build_program(dll: str, ordinals: list[int]) -> bytes:
    data, _ = build_pe(
        32, text=call_ordinals(dll, ordinals), data=bytes(4 * len(ordinals)), imports={dll: sorted(set(ordinals))}
    )
    return data


@pytest.mark.parametrize(
    "dll, ordinal, name",
    [
        ("mfc42.dll", 1575, "?AfxWinInit@@YGHPAUHINSTANCE__@@0PADH@Z"),
        ("mfc42u.dll", 1568, "?AfxWinInit@@YGHPAUHINSTANCE__@@0PAGH@Z"),
    ],
)
def test_unsupported_ordinal_import_shows_the_export_name(config: dict, dll: str, ordinal: int, name: str) -> None:
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=build_program(dll, [ordinal])))
        error = se.get_report().entry_points[0].error
    module = dll.removesuffix(".dll")
    assert error.type == "unsupported_api"
    assert error.api_name == f"{module}.{name}"
    assert error.instruction == f"api_trap {module}.{name}"


def test_afx_get_module_state_returns_one_state_with_the_instance_handle(config: dict) -> None:
    with Speakeasy(config=config) as se:
        module = se.load_module(data=build_program("mfc42.dll", [AFX_GET_MODULE_STATE, AFX_GET_MODULE_STATE]))
        base = module.base
        se.run_module(module)
        assert se.get_report().entry_points[0].error is None
        first, second = struct.unpack("<II", se.mem_read(base + 0x2000, 8))
        assert first and first == second
        instance, resource = struct.unpack("<II", se.mem_read(first + 8, 8))
    assert instance == resource == base


def test_x64_ordinal_import_does_not_run_the_x86_handler(config: dict) -> None:
    def text(base: int, iat: dict) -> bytes:
        call = b"\xff\x15" + struct.pack("<i", iat["mfc42.dll", AFX_GET_MODULE_STATE] - (0x1000 + 4 + 6))
        return b"\x48\x83\xec\x28" + call + b"\x48\x83\xc4\x28\xc3"

    data, _ = build_pe(64, text=text, imports={"mfc42.dll": [AFX_GET_MODULE_STATE]})
    with Speakeasy(config=config) as se:
        se.run_module(se.load_module(data=data))
        error = se.get_report().entry_points[0].error
    assert error.type == "unsupported_api"
    assert error.api_name == f"mfc42.ordinal_{AFX_GET_MODULE_STATE}"
