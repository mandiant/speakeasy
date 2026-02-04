# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import pytest

DEV_NAME = "\\Device\\wdm_test"
SYM_LINK = "\\DosDevices\\wdm_test"


def get_api_calls(ep, api_name):
    return [evt for evt in ep.get("events", []) if evt.get("event") == "api" and evt["api_name"] == api_name]


@pytest.mark.parametrize(
    "bin_file",
    [
        "wdm_test_x86.sys.xz",
        "wdm_test_x64.sys.xz",
    ],
)
def test_wdm_driver_load_unload(config, load_test_bin, run_test, bin_file):
    data = load_test_bin(bin_file)
    report = run_test(config, data)
    eps = report["entry_points"]

    driver_entry = eps[0]

    create_dev = get_api_calls(driver_entry, "ntoskrnl.IoCreateDeviceSecure")
    assert len(create_dev) == 1
    create_dev = create_dev[0]
    assert create_dev["args"][2] == DEV_NAME

    create_sym = get_api_calls(driver_entry, "ntoskrnl.IoCreateSymbolicLink")
    assert len(create_sym) == 1
    create_sym = create_sym[0]
    assert create_sym["args"][0] == SYM_LINK
    assert create_sym["args"][1] == DEV_NAME

    assert driver_entry["ret_val"] == "0x0"

    driver_unload = eps[-1]
    delete_sym = get_api_calls(driver_unload, "ntoskrnl.IoDeleteSymbolicLink")
    assert len(delete_sym) == 1
    delete_sym = delete_sym[0]
    assert delete_sym["args"][0] == SYM_LINK

    delete_dev = get_api_calls(driver_unload, "ntoskrnl.IoDeleteDevice")
    assert len(delete_dev) == 1
    delete_dev = delete_dev[0]
    assert delete_dev["args"][0] != "0x0"


@pytest.mark.parametrize(
    "bin_file",
    [
        "wdm_test_x86.sys.xz",
        "wdm_test_x64.sys.xz",
    ],
)
def test_wdm_irp_handlers(config, load_test_bin, run_test, bin_file):
    data = load_test_bin(bin_file)
    report = run_test(config, data)
    eps = report["entry_points"]

    irp_handlers = [ep for ep in eps if ep["ep_type"].startswith("irp_")]
    assert len(irp_handlers) == 6

    for ih in irp_handlers:
        if ih["ep_type"] == "irp_mj_create":
            dprint = get_api_calls(ih, "ntoskrnl.DbgPrint")
            assert len(dprint) == 1
            dprint = dprint[0]
            assert dprint["args"][0] == "Inside IRP_MJ_CREATE handler"
            assert ih["ret_val"] == "0x0"
        elif ih["ep_type"] == "irp_mj_device_control":
            dprint = get_api_calls(ih, "ntoskrnl.DbgPrint")
            assert len(dprint) == 1
            dprint = dprint[0]
            assert dprint["args"][0] == "Inside IRP_MJ_DEVICE_CONTROL handler"
            assert ih["ret_val"] == "0x0"
        elif ih["ep_type"] == "irp_mj_close":
            dprint = get_api_calls(ih, "ntoskrnl.DbgPrint")
            assert len(dprint) == 1
            dprint = dprint[0]
            assert dprint["args"][0] == "Inside IRP_MJ_CLOSE handler"
            assert ih["ret_val"] == "0x0"
        else:
            dprint = get_api_calls(ih, "ntoskrnl.DbgPrint")
            assert len(dprint) == 1
            dprint = dprint[0]
            assert dprint["args"][0] == "Inside default handler"
            assert ih["ret_val"] == "0xc00000bb"
