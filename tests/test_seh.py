# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import unittest

import util


class TestSehEmulation(unittest.TestCase):

    def setUp(self):
        self.config = util.get_config()

        self.dispatch_script = ['Hello emulator\n',
                                'First access violation\r\n',
                                'First nested access violation\r\n',
                                'Second nested access violation\r\n',
                                'After access violations\r\n',
                                'In finally\r\n',
                                'Returning...\n']

    def test_seh_dispatch(self):
        self.config['exceptions']['dispatch_handlers'] = True
        data = util.get_test_bin_data('seh_test_x86.exe.xz')
        report = util.run_test(self.config, data)

        ep = report['entry_points']
        printfs = []
        for api in ep[0]['apis']:
            if '__stdio_common_vfprintf' in api['api_name']:
                printfs.append(api)

        fmt_strings = [p['args'][2] for p in printfs]
        self.assertEqual(len(fmt_strings), len(self.dispatch_script))
        for i, s in enumerate(fmt_strings):
            self.assertEqual(s, self.dispatch_script[i])

    def test_seh_without_dispatch(self):
        self.config['exceptions']['dispatch_handlers'] = False

        data = util.get_test_bin_data('seh_test_x86.exe.xz')
        report = util.run_test(self.config, data)

        ep = report['entry_points']
        printfs = []
        for api in ep[0]['apis']:
            if '__stdio_common_vfprintf' in api['api_name']:
                printfs.append(api)
                break

        self.assertEqual(1, len(printfs))
        error = ep[0]['error']

        self.assertEqual(error['type'], 'invalid_write')
        self.assertEqual(error['address'], '0x0')
        self.assertEqual(error['instr'], 'mov dword ptr [0], 0x14')


if __name__ == '__main__':
    unittest.main()
