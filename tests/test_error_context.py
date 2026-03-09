"""Tests for enriched exception context in ErrorInfo and error dict parsing."""

import copy

import pytest

from speakeasy import Speakeasy
from speakeasy.report import ErrorInfo

# -- x86 shellcode fragments ------------------------------------------------
# mov eax, 0xdeadbeef; mov eax, [eax]   -> invalid read from 0xdeadbeef
_SC_INVALID_READ = b"\xb8\xef\xbe\xad\xde\x8b\x00"
# mov eax, 0xdeadbeef; mov [eax], ebx   -> invalid write to 0xdeadbeef
_SC_INVALID_WRITE = b"\xb8\xef\xbe\xad\xde\x89\x18"


@pytest.fixture(scope="module")
def _read_error(base_config):
    cfg = copy.deepcopy(base_config)
    se = Speakeasy(config=cfg)
    try:
        addr = se.load_shellcode(data=_SC_INVALID_READ, arch="x86")
        se.run_shellcode(addr)
        report = se.get_report()
        ep = report.entry_points[0]
        assert ep.error is not None, "shellcode should trigger invalid_read"
        return ep.error
    finally:
        se.shutdown()


@pytest.fixture(scope="module")
def _write_error(base_config):
    cfg = copy.deepcopy(base_config)
    se = Speakeasy(config=cfg)
    try:
        addr = se.load_shellcode(data=_SC_INVALID_WRITE, arch="x86")
        se.run_shellcode(addr)
        report = se.get_report()
        ep = report.entry_points[0]
        assert ep.error is not None, "shellcode should trigger invalid_write"
        return ep.error
    finally:
        se.shutdown()


def test_invalid_read_error_fields(_read_error):
    e = _read_error
    assert e.type == "invalid_read"
    assert e.access_type == "read"
    assert e.address == 0xDEADBEEF
    assert e.pc is not None
    assert e.instr is not None
    assert "mov" in e.instr.lower()
    assert e.pc_module is not None
    assert e.thread_id is not None
    assert e.process_id is not None


def test_invalid_read_has_register_state(_read_error):
    e = _read_error
    assert e.regs is not None
    assert "eax" in e.regs
    assert e.regs["eax"] == "0xdeadbeef"
    for reg in ("esp", "ebp", "eip"):
        assert reg in e.regs


def test_invalid_read_has_stack_trace(_read_error):
    e = _read_error
    assert e.stack is not None
    assert len(e.stack) > 0
    assert "sp+" in e.stack[0]


def test_invalid_read_context_summary(_read_error):
    """Verify the one-line triage summary is present and structured.

    Expected format:
        read of 0xdeadbeef; from <module>+0x5; in unknown [0xdeadb000-0xdeadbfff]
    """
    e = _read_error
    assert e.context_summary is not None
    assert "read" in e.context_summary
    assert "0xdeadbeef" in e.context_summary


def test_invalid_write_error_fields(_write_error):
    e = _write_error
    assert e.type == "invalid_write"
    assert e.access_type == "write"
    assert e.address == 0xDEADBEEF


def test_invalid_write_context_summary(_write_error):
    """Verify the write summary reports the correct access type.

    Expected format:
        write of 0xdeadbeef; from <module>+0x5; in unknown [0xdeadb000-0xdeadbfff]
    """
    e = _write_error
    assert e.context_summary is not None
    assert "write" in e.context_summary
    assert "0xdeadbeef" in e.context_summary


def test_error_info_round_trips_through_json(_read_error):
    """ErrorInfo -> JSON -> ErrorInfo preserves all fields."""
    e = _read_error
    data = e.model_dump()

    assert isinstance(data["pc"], str) and data["pc"].startswith("0x")
    assert isinstance(data["address"], str) and data["address"].startswith("0x")

    restored = ErrorInfo.model_validate(data)
    assert restored.type == e.type
    assert restored.pc == e.pc
    assert restored.address == e.address
    assert restored.access_type == e.access_type
    assert restored.context_summary == e.context_summary
    assert restored.regs == e.regs
