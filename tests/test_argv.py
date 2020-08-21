# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import unittest

import util


class TestArgvEmulation(unittest.TestCase):

    def setUp(self):
        self.config = util.get_config()

    def _test_argv_exe(self, fpath):
        argv_len = 10
        argv = ['argument_%d' % (i+1) for i in range(argv_len)]
        data = util.get_test_bin_data(fpath)
        report = util.run_test(self.config, data, argv=argv)
        ep = report['entry_points']
        printfs = []
        for api in ep[0]['apis']:
            if '__stdio_common_vfprintf' in api['api_name']:
                printfs.append(api)

        self.assertEqual(len(printfs) - 2, argv_len)
        for i, p in enumerate(printfs[2:]):
            i += 1
            args = p['args']
            fmt_str = args[2]
            test_str = "argv[%d] = argument_%d\n" % (i, i)
            self.assertEqual(test_str, fmt_str)

    def test_x86_argv_exe(self):
        self._test_argv_exe('argv_test_x86.exe.xz')

    def test_x64_argv_exe(self):
        self._test_argv_exe('argv_test_x64.exe.xz')


if __name__ == '__main__':
    unittest.main()
