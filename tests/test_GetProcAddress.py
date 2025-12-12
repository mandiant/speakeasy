# test call to GetProcAddress by using a not exported function

import unittest

import util


class TestDllEmulation(unittest.TestCase):

    def setUp(self):
        self.config = util.get_config()
        self.report = None

    def _get_api_calls(self, ep, api_name):
        return [api for api in ep['apis'] if api['api_name'] == api_name]

    def test_GetProcAddress_on_not_existing_function_fails(self):
        fpath = 'GetProcAddress.exe.xz'
        data = util.get_test_bin_data(fpath)
        self.report = util.run_test(self.config, data)
        eps = self.report['entry_points']

        get_proc_addr = self._get_api_calls(eps[0], 'KERNEL32.GetProcAddress')

        self.assertEqual(get_proc_addr[2]['args'][1], 'AreFileApisANSI')
        self.assertNotEqual(get_proc_addr[2]['ret_val'], '0x0')

        self.assertEqual(get_proc_addr[3]['args'][1], 'ThisFunctionIsNotExportedByKernel32')
        self.assertEqual(get_proc_addr[3]['ret_val'], '0x0')

if __name__ == '__main__':
    unittest.main()
