from pathlib import Path

import pytest

from speakeasy import Speakeasy, WinKernelEmulator
from speakeasy.config import SpeakeasyConfig
from speakeasy.errors import WindowsEmuError

SAMPLE_PATH = Path(__file__).resolve().parent / "capa-testfiles" / "Practical Malware Analysis Lab 10-03.sys_"


def test_kernel_current_process_requires_bootstrap_phase(config):
    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))

    with pytest.raises(WindowsEmuError, match="bootstrap phase"):
        emu.get_current_process()


def test_kernel_import_data_allocation_uses_system_process_context(config):
    se = Speakeasy(config=config)

    try:
        se.load_module(str(SAMPLE_PATH))
        emu = se.emu
        address = emu.get_proc("ntoskrnl", "KeTickCount")
        entry = emu.api_registry.entries[address]
        assert entry.export.kind == "data"
        assert entry.trap is None
        assert entry.module.get_export_by_name("KeTickCount").address == address
        proc = emu.get_address_map(address).process
        assert proc is not None
        assert proc.pid == 4
    finally:
        se.shutdown()
