# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import pytest


def get_api_calls(ep, api_name):
    return [evt for evt in ep.events or [] if evt.event == "api" and evt.api_name == api_name]


@pytest.mark.parametrize(
    "bin_file",
    [
        "file_access_test_x86.exe.xz",
        "file_access_test_x64.exe.xz",
    ],
)
def test_file_access(config, load_test_bin, run_test, bin_file):
    data = load_test_bin(bin_file)
    report = run_test(config, data)
    eps = report.entry_points

    driver_entry = eps[0]

    create_file = get_api_calls(driver_entry, "ntdll.NtCreateFile")
    assert len(create_file) == 1
    create_file = create_file[0]
    assert create_file.args[3] == "\\??\\c:\\myfile.txt"

    read_file = get_api_calls(driver_entry, "ntdll.NtReadFile")
    assert len(read_file) == 1

    printf = get_api_calls(driver_entry, "api-ms-win-crt-stdio-l1-1-0.__stdio_common_vfprintf")
    assert len(printf) == 5
    printf = printf[-1]

    assert "File contained:" in printf.args[2]
