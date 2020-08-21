import argparse

import speakeasy
import speakeasy.winenv.defs.wdf as wdf
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.usb as usbdefs
import speakeasy.winenv.defs.nt.ntoskrnl as ntos

import speakeasy.winenv.defs.registry.reg as reg


IOCTL_IS_SUPER_SPEED_SUPPORTED = 0x49104b


class UsbEmu(speakeasy.Speakeasy):
    '''
    WDF USB Emulator
    '''

    def __init__(self, debug=False):
        super(UsbEmu, self).__init__(debug=debug)
        self.device_add_func = None
        self.prepare_hardware_func = None
        self.dev_handle = None
        self.ddesc = usbdefs.USB_DEVICE_DESCRIPTOR()
        self.cdesc = usbdefs.USB_CONFIGURATION_DESCRIPTOR()
        self.idesc = usbdefs.USB_INTERFACE_DESCRIPTOR()
        self.endpoints = [usbdefs.USB_ENDPOINT_DESCRIPTOR() for i in range(3)]

        self.pEvtIoRead = 0
        self.pEvtIoWrite = 0

    def init_usb_descriptors(self):

        for i, ep in enumerate(self.endpoints):
            ep.bLength = 7
            ep.bDescriptorType = 5

        self.endpoints[0].bEndpointAddress = 0x01 | usbdefs.USB_DIR_IN
        self.endpoints[0].bmAttributes = usbdefs.USB_ENDPOINT_TYPE_INTERRUPT
        self.endpoints[0].wMaxPacketSize = 1
        self.endpoints[0].bInterval = 2

        self.endpoints[1].bEndpointAddress = 0x06 | usbdefs.USB_DIR_OUT
        self.endpoints[1].bmAttributes = usbdefs.USB_ENDPOINT_TYPE_BULK
        self.endpoints[1].wMaxPacketSize = 512
        self.endpoints[1].bInterval = 2

        self.endpoints[2].bEndpointAddress = 0x08 | usbdefs.USB_DIR_IN
        self.endpoints[2].bmAttributes = usbdefs.USB_ENDPOINT_TYPE_BULK
        self.endpoints[2].wMaxPacketSize = 512
        self.endpoints[2].bInterval = 2

        ifd = self.idesc
        ifd.bLength = 9
        ifd.bDescriptorType = usbdefs.USB_INTERFACE_DESCRIPTOR_TYPE
        ifd.bInterfaceNumber = 0
        ifd.bAlternateSetting = 0
        ifd.bNumEndpoints = len(self.endpoints)
        ifd.bInterfaceClass = 255

        cd = self.cdesc
        cd.bLength = 9
        cd.bDescriptorType = usbdefs.USB_CONFIGURATION_DESCRIPTOR_TYPE
        cd.wTotalLength = ifd.sizeof() + (self.endpoints[0].sizeof() * len(self.endpoints))
        cd.bNumInterfaces = 1
        cd.bConfigurationValue = 1
        cd.MaxPower = 250

        dd = self.ddesc
        dd.bLength = 18
        dd.bDescriptorType = usbdefs.USB_DEVICE_DESCRIPTOR_TYPE
        dd.idVendor = 0x0547
        dd.idProduct = 0x1002
        dd.bNumConfigurations = 1

    def emit_config_descriptor(self):
        data = self.cdesc.get_bytes()
        data += self.idesc.get_bytes()
        for ep in self.endpoints:
            data += ep.get_bytes()
        return data

    def wdf_driver_create_hook(self, emu, api_name, func, params):
        DriverGlobals, DriverObject, RegistryPath, DriverAttributes, DriverConfig, Driver = params

        config = self.mem_cast(wdf.WDF_DRIVER_CONFIG(emu.get_ptr_size()), DriverConfig)
        self.device_add_func = config.EvtDriverDeviceAdd

        rv = func(params)

        return rv

    def wdf_device_set_pnp_hooks(self, emu, api_name, func, params):
        DriverGlobals, DeviceInit, PnpPowerEventCallbacks = params

        rv = func(params)

        callbacks = wdf.WDF_PNPPOWER_EVENT_CALLBACKS(emu.get_ptr_size())
        callbacks = self.mem_cast(callbacks, PnpPowerEventCallbacks)
        self.prepare_hardware_func = callbacks.EvtDevicePrepareHardware

        return rv

    def wdf_get_usb_config_descriptor(self, emu, api_name, func, params):
        DriverGlobals, UsbDevice, ConfigDescriptor, ConfigDescriptorLength = params

        rv = ddk.STATUS_BUFFER_TOO_SMALL
        buf_len = self.mem_read(ConfigDescriptorLength, 2)
        buf_len = int.from_bytes(buf_len, 'little')

        cfg = self.emit_config_descriptor()
        if buf_len < len(cfg):
            self.mem_write(ConfigDescriptorLength, (len(cfg)).to_bytes(2, 'little'))
            return rv

        if ConfigDescriptor:
            self.mem_write(ConfigDescriptor, cfg)
            self.mem_write(ConfigDescriptorLength, (len(cfg)).to_bytes(2, 'little'))

        rv = func(params)

        return rv

    def wdf_get_usb_device_descriptor(self, emu, api_name, func, params):
        DriverGlobals, UsbDevice, UsbDeviceDescriptor = params

        self.mem_write(UsbDeviceDescriptor, self.ddesc.get_bytes())
        return

    def wdf_get_usb_info(self, emu, api_name, func, params):
        DriverGlobals, UsbDevice, Information = params

        info = wdf.WDF_USB_DEVICE_INFORMATION(emu.get_ptr_size())
        info = self.mem_cast(info, Information)

        # Set the traits to inform the driver we are a highspeed device
        info.Traits |= wdf.WDF_USB_DEVICE_TRAIT_AT_HIGH_SPEED
        self.mem_write(Information, info.get_bytes())

        rv = func(params)
        return rv

    def wdf_queue_create_hook(self, emu, api_name, func, params):
        DriverGlobals, Device, Config, QueueAttributes, Queue = params

        rv = func(params)

        queue_config = wdf.WDF_IO_QUEUE_CONFIG(emu.get_ptr_size())
        queue_config = self.mem_cast(queue_config, Config)

        if not self.pEvtIoRead:
            self.pEvtIoRead = queue_config.EvtIoRead

        if not self.pEvtIoWrite:
            self.pEvtIoWrite = queue_config.EvtIoWrite

        return rv

    def iof_call_driver(self, emu, api_name, func, params):
        DeviceObject, pIrp = params

        rv = ddk.STATUS_SUCCESS

        _irp = ntos.IRP(emu.get_ptr_size())
        _irp = self.mem_cast(_irp, pIrp)

        stack = _irp.Tail.Overlay.CurrentStackLocation
        csl = ntos.IO_STACK_LOCATION(emu.get_ptr_size())
        csl = self.mem_cast(csl, stack - csl.sizeof())

        if IOCTL_IS_SUPER_SPEED_SUPPORTED == csl.Parameters.DeviceIoControl.IoControlCode:
            rv = ddk.STATUS_NOT_SUPPORTED
            _irp.IoStatus.Status = rv
            self.mem_write(pIrp, _irp.get_bytes())
        else:
            # Call the API handler
            rv = func(params)
            _irp.IoStatus.Status = 0
            self.mem_write(pIrp, _irp.get_bytes())
        return rv


def main(args):

    usb = UsbEmu()

    # Load the module
    module = usb.load_module(args.file)

    # Set the API hooks so we initialize everything
    usb.add_api_hook(usb.wdf_driver_create_hook,
                     'wdfldr',
                     'WdfDriverCreate'
                     )

    usb.add_api_hook(usb.wdf_queue_create_hook,
                     'wdfldr',
                     'WdfIoQueueCreate'
                     )

    usb.add_api_hook(usb.wdf_device_set_pnp_hooks,
                     'wdfldr',
                     'WdfDeviceInitSetPnpPowerEventCallbacks'
                     )

    usb.add_api_hook(usb.wdf_get_usb_device_descriptor,
                     'wdfldr',
                     'WdfUsbTargetDeviceGetDeviceDescriptor'
                     )

    usb.add_api_hook(usb.wdf_get_usb_config_descriptor,
                     'wdfldr',
                     'WdfUsbTargetDeviceRetrieveConfigDescriptor'
                     )

    usb.add_api_hook(usb.wdf_get_usb_info,
                     'wdfldr',
                     'WdfUsbTargetDeviceRetrieveInformation'
                     )

    usb.add_api_hook(usb.iof_call_driver,
                     'ntoskrnl',
                     'IofCallDriver'
                     )

    # Setup out USB descriptors
    usb.init_usb_descriptors()

    # Emulate the module
    usb.run_module(module)

    param_key = usb.get_registry_key(path='HKLM\\System\\CurrentControlSet\\Services\\*\\Parameters') # noqa
    param_key.create_value('MaximumTransferSize', reg.REG_DWORD, 65536)

    # Call the AddDevice function to get us setup

    if usb.device_add_func:
        usb.call(usb.device_add_func, [0x41414142, 0x42424242])

    # Call the prepare hardware callback
    if usb.prepare_hardware_func:
        usb.call(usb.prepare_hardware_func, [0, 0x42424242, 0x43434343])

    profile = usb.get_json_report()
    print(profile)

    # TODO: call the EvtRead/Write
    print('Found EvtIoRead at 0x%x' % (usb.pEvtIoRead))
    print('Found EvtIoWrite at 0x%x' % (usb.pEvtIoWrite))


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='USB driver emulator')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of USB driver to emulate')
    args = parser.parse_args()
    main(args)
