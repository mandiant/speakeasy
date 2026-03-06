from pathlib import Path

import pytest

from speakeasy import Speakeasy, WinKernelEmulator
from speakeasy.config import SpeakeasyConfig
from speakeasy.errors import WindowsEmuError
from speakeasy.windows.winemu import BootstrapPhase

SAMPLE_PATH = Path(__file__).resolve().parent / "capa-testfiles" / "Practical Malware Analysis Lab 10-03.sys_"


def test_kernel_current_process_requires_bootstrap_phase(config):
    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))

    with pytest.raises(WindowsEmuError, match="bootstrap phase"):
        emu.get_current_process()


def test_kernel_bootstrap_rejects_out_of_order_transition(config):
    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))

    with pytest.raises(WindowsEmuError, match="invalid bootstrap transition"):
        emu.advance_bootstrap_phase(BootstrapPhase.FULL_SETUP_READY)


def test_kernel_import_data_allocation_uses_system_process_context(config):
    se = Speakeasy(config=config)

    try:
        se.load_module(str(SAMPLE_PATH))
        emu = se.emu
        maps = [mm for mm in emu.get_mem_maps() if mm.tag and mm.tag.startswith("api.ntoskrnl.KeTickCount.")]

        assert maps
        proc = maps[0].process
        assert proc is not None
        assert proc.get_pid() == 4
    finally:
        se.shutdown()
