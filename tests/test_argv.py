# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import pytest


@pytest.mark.parametrize("bin_file", [
    "argv_test_x86.exe.xz",
    "argv_test_x64.exe.xz",
])
def test_argv_exe(config, load_test_bin, run_test, bin_file):
    argv_len = 10
    argv = ['argument_%d' % (i + 1) for i in range(argv_len)]
    data = load_test_bin(bin_file)
    report = run_test(config, data, argv=argv)
    ep = report['entry_points']
    printfs = []
    for api in ep[0]['apis']:
        if '__stdio_common_vfprintf' in api['api_name']:
            printfs.append(api)

    assert len(printfs) - 2 == argv_len
    for i, p in enumerate(printfs[2:]):
        i += 1
        args = p['args']
        fmt_str = args[2]
        test_str = "argv[%d] = argument_%d\n" % (i, i)
        assert test_str == fmt_str
