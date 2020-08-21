# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


import unittest

import util


class TestFileAccess(unittest.TestCase):

    def setUp(self):
        self.config = util.get_config()
        self.report = None

    def _get_api_calls(self, ep, api_name):
        return [api for api in ep['apis'] if api['api_name'] == api_name]

    def _test_file_access(self, fpath):
        data = util.get_test_bin_data(fpath)
        self.report = util.run_test(self.config, data)
        eps = self.report['entry_points']

        driver_entry = eps[0]

        create_file = self._get_api_calls(driver_entry, 'ntdll.NtCreateFile')
        self.assertEqual(1, len(create_file))
        create_file = create_file[0]
        self.assertEqual(create_file['args'][3], '\\??\\c:\\myfile.txt')

        read_file = self._get_api_calls(driver_entry, 'ntdll.NtReadFile')
        self.assertEqual(1, len(read_file))

        printf = self._get_api_calls(driver_entry,
                                     'api-ms-win-crt-stdio-l1-1-0.__stdio_common_vfprintf')
        self.assertEqual(5, len(printf))
        printf = printf[-1]

        self.assertIn('File contained:', printf['args'][2])

    def test_file_access_x86(self):
        self._test_file_access('file_access_test_x86.exe.xz')

    def test_file_access_x64(self):
        self._test_file_access('file_access_test_x64.exe.xz')


if __name__ == '__main__':
    unittest.main()
