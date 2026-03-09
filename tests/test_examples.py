import importlib.util
import json
import logging
import subprocess
import sys
from pathlib import Path
from types import ModuleType

from speakeasy import Speakeasy

ROOT_DIR = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = ROOT_DIR / "examples"
UPX_SAMPLE_PATH = ROOT_DIR / "tests" / "capa-testfiles" / "Practical Malware Analysis Lab 01-02.exe_"


def load_example_module(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"test_example_{name}", EXAMPLES_DIR / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_unpacked_bin(tmp_path: Path, load_test_bin, archive_name: str) -> Path:
    path = tmp_path / archive_name.removesuffix(".xz")
    path.write_bytes(load_test_bin(archive_name))
    return path


def test_dbgview_example_runs(load_test_bin, tmp_path):
    sample_path = write_unpacked_bin(tmp_path, load_test_bin, "wdm_test_x86.sys.xz")
    proc = subprocess.run(
        [sys.executable, str(EXAMPLES_DIR / "dbgview.py"), "-f", str(sample_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert proc.returncode == 0
    lines = proc.stdout.strip().splitlines()
    assert "Inside IRP_MJ_CREATE handler" in lines
    assert "Inside IRP_MJ_DEVICE_CONTROL handler" in lines
    assert "Inside IRP_MJ_CLOSE handler" in lines
    assert lines.count("Inside default handler") == 3
    assert not proc.stderr


def test_emu_dll_example_exercises_hooks(config, load_test_bin, caplog):
    example = load_example_module("emu_dll")
    caplog.set_level(logging.INFO, logger=example.logger.name)

    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        se.run_module(module, all_entrypoints=False)
        se.add_api_hook(example.hook_messagebox, "user32", "MessageBox*")
        se.add_mem_write_hook(example.hook_mem_write)

        for export in module.get_exports():
            if export.name == "emu_test_one":
                se.call(export.address, [0x0, 0x1])
            elif export.name == "emu_test_two":
                se.call(export.address, [0x0, 0x1])

        report = se.get_report()
    finally:
        se.shutdown()

    assert any(message.startswith("Stack written to:") for message in caplog.messages)
    assert "user32.MessageBoxA text: Inside emu_test_one" in caplog.messages
    assert "user32.MessageBoxW text: Inside emu_test_two" in caplog.messages
    assert len(report.entry_points) == 3
    assert report.entry_points[1].ret_val == 0x41414141
    assert report.entry_points[2].ret_val == 0x42424242


def test_emu_exe_example_modifies_ntreadfile_buffer(config, load_test_bin, caplog):
    example = load_example_module("emu_exe")
    caplog.set_level(logging.INFO, logger=example.logger.name)

    se = Speakeasy(config=config)
    try:
        se.add_api_hook(example.hook_ntreadfile, "ntdll", "NtReadFile")
        module = se.load_module(data=load_test_bin("file_access_test_x86.exe.xz"))
        se.run_module(module)
        report = se.get_report()
    finally:
        se.shutdown()

    assert any(message.startswith("b'") and "\\x90" in message for message in caplog.messages)
    printfs = [
        event
        for event in report.entry_points[0].events or []
        if event.event == "api" and "__stdio_common_vfprintf" in event.api_name
    ]
    assert printfs[-1].args[2].strip() == "File contained: 0x4141414141414141"


def test_upx_unpack_example_runs_and_dumps_file(tmp_path):
    output_path = tmp_path / "unpacked.exe"
    proc = subprocess.run(
        [sys.executable, str(EXAMPLES_DIR / "upx_unpack.py"), "-f", str(UPX_SAMPLE_PATH), "-o", str(output_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert proc.returncode == 0
    assert "[*] Unpacking module with section hop" in proc.stdout
    assert "[*] Section hop signature hit, dumping module" in proc.stdout
    data = output_path.read_bytes()
    assert data[:2] == b"MZ"
    assert len(data) > 0x1000


def test_usb_emu_example_runs_and_emits_report(load_test_bin):
    example = load_example_module("usb_emu")

    usb = example.UsbEmu()
    try:
        usb.add_api_hook(usb.wdf_driver_create_hook, "wdfldr", "WdfDriverCreate")
        usb.add_api_hook(usb.wdf_queue_create_hook, "wdfldr", "WdfIoQueueCreate")
        usb.add_api_hook(usb.wdf_device_set_pnp_hooks, "wdfldr", "WdfDeviceInitSetPnpPowerEventCallbacks")
        usb.add_api_hook(usb.wdf_get_usb_device_descriptor, "wdfldr", "WdfUsbTargetDeviceGetDeviceDescriptor")
        usb.add_api_hook(usb.wdf_get_usb_config_descriptor, "wdfldr", "WdfUsbTargetDeviceRetrieveConfigDescriptor")
        usb.add_api_hook(usb.wdf_get_usb_info, "wdfldr", "WdfUsbTargetDeviceRetrieveInformation")
        usb.add_api_hook(usb.iof_call_driver, "ntoskrnl", "IofCallDriver")
        usb.init_usb_descriptors()
        descriptor = usb.emit_config_descriptor()
        module = usb.load_module(data=load_test_bin("wdm_test_x86.sys.xz"))
        usb.run_module(module)
        param_key = usb.get_registry_key(path="HKLM\\System\\CurrentControlSet\\Services\\*\\Parameters")
        param_key.create_value("MaximumTransferSize", example.reg.REG_DWORD, 65536)
        report = json.loads(usb.get_json_report())
    finally:
        usb.shutdown()

    assert len(descriptor) == 39
    assert usb.ddesc.idVendor == 0x0547
    assert [endpoint.bEndpointAddress for endpoint in usb.endpoints] == [0x81, 0x06, 0x88]
    assert param_key.get_value("MaximumTransferSize").get_data() == 65536
    assert report["entry_points"]
    assert report["entry_points"][0]["ep_type"] == "entry_point"
