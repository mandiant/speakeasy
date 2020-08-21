# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import unittest

import util


class TestWdmEmulation(unittest.TestCase):

    def setUp(self):
        self.config = util.get_config()
        self.dev_name = '\\Device\\wdm_test'
        self.sym_link = '\\DosDevices\\wdm_test'
        self.report = None

    def _get_api_calls(self, ep, api_name):
        return [api for api in ep['apis'] if api['api_name'] == api_name]

    def _test_driver_load_unload(self):
        eps = self.report['entry_points']

        driver_entry = eps[0]

        create_dev = self._get_api_calls(driver_entry, 'ntoskrnl.IoCreateDeviceSecure')
        self.assertEqual(1, len(create_dev))
        create_dev = create_dev[0]
        self.assertEqual(create_dev['args'][2], self.dev_name)

        create_sym = self._get_api_calls(driver_entry, 'ntoskrnl.IoCreateSymbolicLink')
        self.assertEqual(1, len(create_sym))
        create_sym = create_sym[0]
        self.assertEqual(create_sym['args'][0], self.sym_link)
        self.assertEqual(create_sym['args'][1], self.dev_name)

        self.assertEqual(driver_entry['ret_val'], '0x0')

        driver_unload = eps[-1]
        delete_sym = self._get_api_calls(driver_unload, 'ntoskrnl.IoDeleteSymbolicLink')
        self.assertEqual(1, len(delete_sym))
        delete_sym = delete_sym[0]
        self.assertEqual(delete_sym['args'][0], self.sym_link)

        delete_dev = self._get_api_calls(driver_unload, 'ntoskrnl.IoDeleteDevice')
        self.assertEqual(1, len(delete_dev))
        delete_dev = delete_dev[0]
        self.assertNotEqual(delete_dev['args'][0], "0x0")

    def _test_irp_handlers(self):
        eps = self.report['entry_points']
        irp_handlers = [ep for ep in eps if ep['ep_type'].startswith('irp_')]
        self.assertEqual(len(irp_handlers), 6)
        for ih in irp_handlers:
            if ih['ep_type'] == 'irp_mj_create':
                dprint = self._get_api_calls(ih, 'ntoskrnl.DbgPrint')
                self.assertEqual(1, len(dprint))
                dprint = dprint[0]
                self.assertEqual(dprint['args'][0], 'Inside IRP_MJ_CREATE handler')
                self.assertEqual(ih['ret_val'], '0x0')
            elif ih['ep_type'] == 'irp_mj_device_control':
                dprint = self._get_api_calls(ih, 'ntoskrnl.DbgPrint')
                self.assertEqual(1, len(dprint))
                dprint = dprint[0]
                self.assertEqual(dprint['args'][0], 'Inside IRP_MJ_DEVICE_CONTROL handler')
                self.assertEqual(ih['ret_val'], '0x0')
            elif ih['ep_type'] == 'irp_mj_close':
                dprint = self._get_api_calls(ih, 'ntoskrnl.DbgPrint')
                self.assertEqual(1, len(dprint))
                dprint = dprint[0]
                self.assertEqual(dprint['args'][0], 'Inside IRP_MJ_CLOSE handler')
                self.assertEqual(ih['ret_val'], '0x0')
            else:
                dprint = self._get_api_calls(ih, 'ntoskrnl.DbgPrint')
                self.assertEqual(1, len(dprint))
                dprint = dprint[0]
                self.assertEqual(dprint['args'][0], 'Inside default handler')
                self.assertEqual(ih['ret_val'], '0xc00000bb')

    def _test_emu_wdm_driver(self, fpath):
        data = util.get_test_bin_data(fpath)
        self.report = util.run_test(self.config, data)

    def test_x86_wdm_driver_entry(self):
        self._test_emu_wdm_driver('wdm_test_x86.sys.xz')
        self._test_driver_load_unload()

    def test_x64_wdm_driver_entry(self):
        self._test_emu_wdm_driver('wdm_test_x64.sys.xz')
        self._test_driver_load_unload()

    def test_x86_wdm_irp_handlers(self):
        self._test_emu_wdm_driver('wdm_test_x86.sys.xz')
        self._test_irp_handlers()

    def test_x64_wdm_irp_handlers(self):
        self._test_emu_wdm_driver('wdm_test_x64.sys.xz')
        self._test_irp_handlers()


if __name__ == '__main__':
    unittest.main()
