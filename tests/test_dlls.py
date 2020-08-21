# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import unittest

import util


class TestDllEmulation(unittest.TestCase):

    def setUp(self):
        self.config = util.get_config()
        self.report = None

    def _get_api_calls(self, ep, api_name):
        return [api for api in ep['apis'] if api['api_name'] == api_name]

    def _test_dll_emu(self, fpath):
        data = util.get_test_bin_data(fpath)
        self.report = util.run_test(self.config, data)
        eps = self.report['entry_points']
        self.assertEqual(len(eps), 3)

        dll_entry = eps[0]

        msgbox = self._get_api_calls(dll_entry, 'USER32.MessageBoxA')
        self.assertEqual(1, len(msgbox))
        msgbox = msgbox[0]
        self.assertEqual(msgbox['args'][1], 'Inside process attach')
        self.assertEqual(msgbox['args'][2], 'My caption')
        self.assertEqual(dll_entry['ret_val'], '0x1')

        ep = eps[1]
        msgbox = self._get_api_calls(ep, 'USER32.MessageBoxA')
        self.assertEqual(1, len(msgbox))
        msgbox = msgbox[0]
        self.assertEqual(msgbox['args'][1], 'Inside emu_test_one')
        self.assertEqual(msgbox['args'][2], 'First export')
        self.assertEqual(ep['ret_val'], '0x41414141')

        ep = eps[2]
        msgbox = self._get_api_calls(ep, 'USER32.MessageBoxW')
        self.assertEqual(1, len(msgbox))
        msgbox = msgbox[0]
        self.assertEqual(msgbox['args'][1], 'Inside emu_test_two')
        self.assertEqual(msgbox['args'][2], 'Second export')
        self.assertEqual(ep['ret_val'], '0x42424242')

    def test_x86_dll(self):
        self._test_dll_emu('dll_test_x86.dll.xz')

    def test_x64_dll(self):
        self._test_dll_emu('dll_test_x64.dll.xz')


if __name__ == '__main__':
    unittest.main()
