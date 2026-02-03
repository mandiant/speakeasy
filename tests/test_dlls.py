# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import pytest


def get_api_calls(ep, api_name):
    return [api for api in ep['apis'] if api['api_name'] == api_name]


@pytest.mark.parametrize("bin_file", [
    "dll_test_x86.dll.xz",
    "dll_test_x64.dll.xz",
])
def test_dll_emu(config, load_test_bin, run_test, bin_file):
    data = load_test_bin(bin_file)
    report = run_test(config, data)
    eps = report['entry_points']
    assert len(eps) == 3

    dll_entry = eps[0]

    msgbox = get_api_calls(dll_entry, 'USER32.MessageBoxA')
    assert len(msgbox) == 1
    msgbox = msgbox[0]
    assert msgbox['args'][1] == 'Inside process attach'
    assert msgbox['args'][2] == 'My caption'
    assert dll_entry['ret_val'] == '0x1'

    ep = eps[1]
    msgbox = get_api_calls(ep, 'USER32.MessageBoxA')
    assert len(msgbox) == 1
    msgbox = msgbox[0]
    assert msgbox['args'][1] == 'Inside emu_test_one'
    assert msgbox['args'][2] == 'First export'
    assert ep['ret_val'] == '0x41414141'

    ep = eps[2]
    msgbox = get_api_calls(ep, 'USER32.MessageBoxW')
    assert len(msgbox) == 1
    msgbox = msgbox[0]
    assert msgbox['args'][1] == 'Inside emu_test_two'
    assert msgbox['args'][2] == 'Second export'
    assert ep['ret_val'] == '0x42424242'
