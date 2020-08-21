# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import uuid
import speakeasy.winenv.arch as e_arch

import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.wdf as wdf
import speakeasy.winenv.defs.usb as usbdefs

import speakeasy.winenv.defs.nt.ntoskrnl as ntos

from .. import api


class WdfDriver(object):
    def __init__(self):
        self.reg_path = None
        self.typed_context_worker = None
        self.queues = {}
        self.driver_object_addr = None
        self.driver_object = None


class WdfDevice(object):
    def __init__(self):
        self.device_object_addr = None
        self.device_object = None


class WdfUsbDevice(object):
    def __init__(self):
        self.num_interfaces = 0
        self.config_desc = None


class WdfUsbInterface(object):
    def __init__(self):
        self.config_desc = 0
        self.iface_index = 0
        self.setting_index = 0


class WdfUsbPipe(object):
    def __init__(self):
        self.interface = None
        self.index = 0


class Wdfldr(api.ApiHandler):
    """
    Implements the Windows Driver Framework (WDK)
    """

    name = 'wdfldr'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Wdfldr, self).__init__(emu)

        self.funcs = {}
        self.curr_handle = 4
        self.pnp_device = None
        self.data = {}
        self.emu = emu
        self.wdf_drivers = {}
        self.wdf_devices = {}
        self.usb_devices = {}
        self.usb_pipes = {}
        self.usb_interfaces = {}
        self.handles = {}
        self.types = wdf
        self.func_table = self.types.WDFFUNCTIONS(emu.get_ptr_size())
        self.func_table_ptr = None
        self.component_globals = None
        super(Wdfldr, self).__get_hook_attrs__(self)

    def get_handle(self):
        self.curr_handle += 4
        return self.curr_handle

    def set_func_table(self, emu):

        addr = emu.add_callback(Wdfldr.name, self.WdfDriverCreate.__apihook__[0])
        self.func_table.pfnWdfDriverCreate = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDeviceInitSetPnpPowerEventCallbacks.__apihook__[0])
        self.func_table.pfnWdfDeviceInitSetPnpPowerEventCallbacks = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDeviceInitSetRequestAttributes.__apihook__[0])
        self.func_table.pfnWdfDeviceInitSetRequestAttributes = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDeviceInitSetFileObjectConfig.__apihook__[0])
        self.func_table.pfnWdfDeviceInitSetFileObjectConfig = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDeviceInitSetIoType.__apihook__[0])
        self.func_table.pfnWdfDeviceInitSetIoType = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDeviceCreate.__apihook__[0])
        self.func_table.pfnWdfDeviceCreate = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfObjectGetTypedContextWorker.__apihook__[0])
        self.func_table.pfnWdfObjectGetTypedContextWorker = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDriverOpenParametersRegistryKey.__apihook__[0])
        self.func_table.pfnWdfDriverOpenParametersRegistryKey = addr

        addr = emu.add_callback(Wdfldr.name, self.WdfRegistryQueryULong.__apihook__[0])
        self.func_table.pfnWdfRegistryQueryULong = addr

        addr = emu.add_callback(Wdfldr.name, self.WdfRegistryClose.__apihook__[0])
        self.func_table.pfnWdfRegistryClose = addr

        addr = emu.add_callback(Wdfldr.name, self.WdfDeviceSetPnpCapabilities.__apihook__[0])
        self.func_table.pfnWdfDeviceSetPnpCapabilities = addr

        addr = emu.add_callback(Wdfldr.name, self.WdfIoQueueCreate.__apihook__[0])
        self.func_table.pfnWdfIoQueueCreate = addr

        addr = emu.add_callback(Wdfldr.name, self.WdfIoQueueReadyNotify.__apihook__[0])
        self.func_table.pfnWdfIoQueueReadyNotify = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDeviceCreateDeviceInterface.__apihook__[0])
        self.func_table.pfnWdfDeviceCreateDeviceInterface = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDeviceWdmGetAttachedDevice.__apihook__[0])
        self.func_table.pfnWdfDeviceWdmGetAttachedDevice = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfDeviceWdmGetDeviceObject.__apihook__[0])
        self.func_table.pfnWdfDeviceWdmGetDeviceObject = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbTargetDeviceCreateWithParameters.__apihook__[0])
        self.func_table.pfnWdfUsbTargetDeviceCreateWithParameters = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbTargetDeviceGetDeviceDescriptor.__apihook__[0])
        self.func_table.pfnWdfUsbTargetDeviceGetDeviceDescriptor = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbTargetDeviceRetrieveConfigDescriptor.__apihook__[0])
        self.func_table.pfnWdfUsbTargetDeviceRetrieveConfigDescriptor = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfMemoryCreate.__apihook__[0])
        self.func_table.pfnWdfMemoryCreate = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbTargetDeviceSelectConfig.__apihook__[0])
        self.func_table.pfnWdfUsbTargetDeviceSelectConfig = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbTargetDeviceGetNumInterfaces.__apihook__[0])
        self.func_table.pfnWdfUsbTargetDeviceGetNumInterfaces = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbTargetDeviceRetrieveInformation.__apihook__[0])
        self.func_table.pfnWdfUsbTargetDeviceRetrieveInformation = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbInterfaceGetNumSettings.__apihook__[0])
        self.func_table.pfnWdfUsbInterfaceGetNumSettings = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbInterfaceSelectSetting.__apihook__[0])
        self.func_table.pfnWdfUsbInterfaceSelectSetting = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbInterfaceGetNumConfiguredPipes.__apihook__[0])
        self.func_table.pfnWdfUsbInterfaceGetNumConfiguredPipes = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbInterfaceGetConfiguredPipe.__apihook__[0])
        self.func_table.pfnWdfUsbInterfaceGetConfiguredPipe = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbTargetPipeGetInformation.__apihook__[0])
        self.func_table.pfnWdfUsbTargetPipeGetInformation = addr

        addr = emu.add_callback(Wdfldr.name,
                                self.WdfUsbInterfaceGetInterfaceNumber.__apihook__[0])
        self.func_table.pfnWdfUsbInterfaceGetInterfaceNumber = addr

        self.mem_write(self.func_table_ptr, self.func_table.get_bytes())

    def parse_usb_config(self, data):

        interfaces = []

        # Get the USB config descriptor
        cd = usbdefs.USB_CONFIGURATION_DESCRIPTOR().cast(data)
        ifaces = cd.bNumInterfaces
        data = data[cd.bLength:]

        for i in range(ifaces):
            endpoints = []
            _id = usbdefs.USB_INTERFACE_DESCRIPTOR().cast(data)

            data = data[_id.bLength:]
            for j in range(_id.bNumEndpoints):
                ep = usbdefs.USB_ENDPOINT_DESCRIPTOR().cast(data)
                data = data[ep.bLength:]
                endpoints.append(ep)

            interfaces.append([_id, endpoints])

        return interfaces

    @apihook('WdfVersionBind', argc=4)
    def WdfVersionBind(self, emu, argv, ctx={}):
        '''
        NTSTATUS
        WdfVersionBind(
        __in PDRIVER_OBJECT DriverObject,
        __in PUNICODE_STRING RegistryPath,
        __inout PWDF_BIND_INFO BindInfo,
        __out PWDF_COMPONENT_GLOBALS* ComponentGlobals
        );
        '''
        rv = ddk.STATUS_SUCCESS
        drv, reg_path, BindInfo, comp_globals = argv

        wbi = self.types.WDF_BIND_INFO(emu.get_ptr_size())
        wbi = self.mem_cast(wbi, BindInfo)

        if not self.func_table_ptr:
            size = self.func_table.sizeof()
            self.func_table_ptr = self.mem_alloc(size, tag='api.struct.WDFFUNCTIONS')

            self.mem_write(wbi.FuncTable, (self.func_table_ptr).to_bytes(emu.get_ptr_size(),
                                                                         'little'))

        if not self.component_globals:
            components = self.types.WDF_COMPONENT_GLOBALS(emu.get_ptr_size())
            self.component_globals = self.mem_alloc(components.sizeof(),
                                                    tag='api.struct.WDF_COMPONENT_GLOBALS')
            self.mem_write(comp_globals, (self.component_globals).to_bytes(emu.get_ptr_size(),
                                                                           'little'))

        self.set_func_table(emu)

        # For now, just leave the handle open so we can reference it later
        return rv

    @apihook('WdfDriverCreate', argc=6)
    def WdfDriverCreate(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfDriverCreate(
          PWDF_DRIVER_GLOBALS DriverGlobals,
          PDRIVER_OBJECT         DriverObject,
          PCUNICODE_STRING       RegistryPath,
          PWDF_OBJECT_ATTRIBUTES DriverAttributes,
          PWDF_DRIVER_CONFIG     DriverConfig,
          WDFDRIVER              *Driver
        );
        '''
        DriverGlobals, DriverObject, RegistryPath, DriverAttributes, DriverConfig, Driver = argv

        driver = WdfDriver()
        driver.reg_path = self.read_unicode_string(RegistryPath)
        driver.driver_object_addr = DriverObject
        driver.driver_object = self.mem_cast(ntos.DRIVER_OBJECT(emu.get_ptr_size()),
                                             DriverObject)

        self.wdf_drivers.update({DriverGlobals: driver})

        if DriverConfig:
            config = self.mem_cast(self.types.WDF_DRIVER_CONFIG(emu.get_ptr_size()),  # noqa
                                   DriverConfig)
        rv = 0

        return rv

    @apihook('WdfDeviceInitSetPnpPowerEventCallbacks', argc=3)
    def WdfDeviceInitSetPnpPowerEventCallbacks(self, emu, argv, ctx={}):
        '''
        void WdfDeviceInitSetPnpPowerEventCallbacks(
          PWDFDEVICE_INIT               DeviceInit,
          PWDF_PNPPOWER_EVENT_CALLBACKS PnpPowerEventCallbacks
        );
        '''
        DriverGlobals, DeviceInit, PnpPowerEventCallbacks = argv

        return

    @apihook('WdfDeviceInitSetRequestAttributes', argc=3)
    def WdfDeviceInitSetRequestAttributes(self, emu, argv, ctx={}):
        '''
        void WdfDeviceInitSetRequestAttributes(
          PWDFDEVICE_INIT        DeviceInit,
          PWDF_OBJECT_ATTRIBUTES RequestAttributes
        );
        '''
        DriverGlobals, DeviceInit, RequestAttributes = argv

        return

    @apihook('WdfDeviceInitSetFileObjectConfig', argc=4)
    def WdfDeviceInitSetFileObjectConfig(self, emu, argv, ctx={}):
        '''
        void WdfDeviceInitSetFileObjectConfig(
          PWDFDEVICE_INIT        DeviceInit,
          PWDF_FILEOBJECT_CONFIG FileObjectConfig,
          PWDF_OBJECT_ATTRIBUTES FileObjectAttributes
        );
        '''
        DriverGlobals, DeviceInit, FileObjectConfig, FileObjectAttributes = argv

        return

    @apihook('WdfDeviceInitSetIoType', argc=3)
    def WdfDeviceInitSetIoType(self, emu, argv, ctx={}):
        '''
        void WdfDeviceInitSetIoType(
          PWDFDEVICE_INIT    DeviceInit,
          WDF_DEVICE_IO_TYPE IoType
        );
        '''
        DriverGlobals, DeviceInit, IoType = argv

        return

    @apihook('WdfDeviceCreate', argc=4)
    def WdfDeviceCreate(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfDeviceCreate(
          PWDFDEVICE_INIT        *DeviceInit,
          PWDF_OBJECT_ATTRIBUTES DeviceAttributes,
          WDFDEVICE              *Device
        );
        '''
        DriverGlobals, DeviceInit, DeviceAttributes, Device = argv
        rv = ddk.STATUS_SUCCESS

        if Device:
            handle = self.get_handle()
            dev = WdfDevice()
            self.wdf_devices.update({handle: dev})
            self.mem_write(Device, (handle).to_bytes(emu.get_ptr_size(), 'little'))

            do = ntos.DEVICE_OBJECT(emu.get_ptr_size())
            dev.device_object_addr = self.mem_alloc(do.sizeof(), tag='api.struct.DEVICE_OBJECT')
            dev.device_object = do

            driver = self.wdf_drivers.get(DriverGlobals)
            if driver:
                dev.device_object.DriverObject = driver.driver_object_addr
                self.mem_write(dev.device_object_addr, dev.device_object.get_bytes())

        return rv

    @apihook('WdfObjectGetTypedContextWorker', argc=3, conv=e_arch.CALL_CONV_FASTCALL)
    def WdfObjectGetTypedContextWorker(self, emu, argv, ctx={}):
        '''
        PVOID WdfObjectGetTypedContextWorker(
          WDFOBJECT                      Handle,
          PCWDF_OBJECT_CONTEXT_TYPE_INFO TypeInfo
        );
        '''
        DriverGlobals, Handle, TypeInfo = argv

        driver = self.wdf_drivers.get(DriverGlobals)

        if not driver.typed_context_worker:
            size = self.types.WDF_COMPONENT_GLOBALS(emu.get_ptr_size()).sizeof()
            driver.typed_context_worker = self.mem_alloc(size,
                                                         tag='api.struct.WDF_TYPED_CONTEXT_WORKER')
        rv = driver.typed_context_worker

        return rv

    @apihook('WdfDriverOpenParametersRegistryKey', argc=5)
    def WdfDriverOpenParametersRegistryKey(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfDriverOpenParametersRegistryKey(
          WDFDRIVER              Driver,
          ACCESS_MASK            DesiredAccess,
          PWDF_OBJECT_ATTRIBUTES KeyAttributes,
          WDFKEY                 *Key
        );
        '''
        DriverGlobals, Driver, DesiredAccess, KeyAttributes, pKey = argv

        rv = ddk.STATUS_OBJECT_NAME_NOT_FOUND

        driver = self.wdf_drivers.get(DriverGlobals)
        hnd = emu.reg_open_key(driver.reg_path + '\\Parameters')
        if hnd:
            rv = ddk.STATUS_SUCCESS

        if pKey:
            self.mem_write(pKey, (hnd).to_bytes(emu.get_ptr_size(), 'little'))

        return rv

    @apihook('WdfRegistryQueryULong', argc=4)
    def WdfRegistryQueryULong(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfRegistryQueryULong(
          WDFKEY           Key,
          PCUNICODE_STRING ValueName,
          PULONG           Value
        );
        '''
        DriverGlobals, Key, ValueName, Value = argv

        rv = ddk.STATUS_OBJECT_NAME_NOT_FOUND
        wkey = emu.reg_get_key(Key)
        if wkey:

            val_name = self.read_unicode_string(ValueName)
            argv[2] = val_name
            value = wkey.get_value(val_name)
            if value:
                ulong = value.get_data()
                self.mem_write(Value, (ulong).to_bytes(4, 'little'))
                rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('WdfRegistryClose', argc=2)
    def WdfRegistryClose(self, emu, argv, ctx={}):
        '''
        void WdfRegistryClose(
          WDFKEY Key
        );
        '''
        DriverGlobals, Key = argv
        return

    @apihook('WdfDeviceSetPnpCapabilities', argc=3)
    def WdfDeviceSetPnpCapabilities(self, emu, argv, ctx={}):
        '''
        void WdfDeviceSetPnpCapabilities(
          WDFDEVICE                    Device,
          PWDF_DEVICE_PNP_CAPABILITIES PnpCapabilities
        );
        '''
        DriverGlobals, Device, PnpCapabilities = argv
        return

    @apihook('WdfIoQueueReadyNotify', argc=4)
    def WdfIoQueueReadyNotify(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfIoQueueReadyNotify(
          WDFQUEUE               Queue,
          PFN_WDF_IO_QUEUE_STATE QueueReady,
          WDFCONTEXT             Context
        );
        '''
        DriverGlobals, Queue, QueueReady, Context = argv
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('WdfDeviceCreateDeviceInterface', argc=4)
    def WdfDeviceCreateDeviceInterface(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfDeviceCreateDeviceInterface(
          WDFDEVICE        Device,
          const GUID       *InterfaceClassGUID,
          PCUNICODE_STRING ReferenceString
        );
        '''
        DriverGlobals, Device, InterfaceClassGUID, ReferenceString = argv
        rv = ddk.STATUS_SUCCESS

        if InterfaceClassGUID:
            guid = self.mem_read(InterfaceClassGUID, 16)
            guid = uuid.UUID(bytes_le=guid)
            argv[2] = str(guid)

        if ReferenceString:
            ref = self.read_unicode_string(ReferenceString)
            argv[3] = ref

        return rv

    @apihook('WdfIoQueueCreate', argc=5)
    def WdfIoQueueCreate(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfIoQueueCreate(
          WDFDEVICE              Device,
          PWDF_IO_QUEUE_CONFIG   Config,
          PWDF_OBJECT_ATTRIBUTES QueueAttributes,
          WDFQUEUE               *Queue
        );
        '''
        DriverGlobals, Device, Config, QueueAttributes, Queue = argv
        rv = ddk.STATUS_SUCCESS

        queue_config = self.types.WDF_IO_QUEUE_CONFIG(emu.get_ptr_size())
        queue_config = self.mem_cast(queue_config, Config)

        hnd = self.get_handle()
        driver = self.wdf_drivers.get(DriverGlobals)
        driver.queues.update({hnd: queue_config})

        if Queue:
            self.mem_write(Queue, (hnd).to_bytes(emu.get_ptr_size(), 'little'))

        return rv

    @apihook('WdfDeviceWdmGetAttachedDevice', argc=2)
    def WdfDeviceWdmGetAttachedDevice(self, emu, argv, ctx={}):
        '''
        PDEVICE_OBJECT WdfDeviceWdmGetAttachedDevice(
          WDFDEVICE Device
        );
        '''
        DriverGlobals, Device = argv

        if not self.pnp_device:
            do = ntos.DEVICE_OBJECT(emu.get_ptr_size())
            self.pnp_device = self.mem_alloc(do.sizeof(), tag='api.struct.DEVICE_OBJECT')
        rv = self.pnp_device

        return rv

    @apihook('WdfUsbTargetDeviceCreateWithParameters', argc=5)
    def WdfUsbTargetDeviceCreateWithParameters(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfUsbTargetDeviceCreateWithParameters(
          WDFDEVICE                     Device,
          PWDF_USB_DEVICE_CREATE_CONFIG Config,
          PWDF_OBJECT_ATTRIBUTES        Attributes,
          WDFUSBDEVICE                  *UsbDevice
        );
        '''
        DriverGlobals, Device, Config, Attributes, UsbDevice = argv

        rv = ddk.STATUS_SUCCESS
        handle = self.get_handle()
        usb = WdfUsbDevice()
        self.usb_devices.update({handle: usb})

        self.mem_write(UsbDevice, (handle).to_bytes(emu.get_ptr_size(), 'little'))

        return rv

    @apihook('WdfDeviceWdmGetDeviceObject', argc=2)
    def WdfDeviceWdmGetDeviceObject(self, emu, argv, ctx={}):
        '''
        PDEVICE_OBJECT WdfDeviceWdmGetDeviceObject(
          WDFDEVICE Device
        );
        '''
        DriverGlobals, Device = argv
        rv = 0

        dev = self.wdf_devices.get(Device)
        if dev:
            rv = dev.device_object_addr
        return rv

    @apihook('WdfUsbTargetDeviceGetDeviceDescriptor', argc=3)
    def WdfUsbTargetDeviceGetDeviceDescriptor(self, emu, argv, ctx={}):
        '''
        void WdfUsbTargetDeviceGetDeviceDescriptor(
          WDFUSBDEVICE           UsbDevice,
          PUSB_DEVICE_DESCRIPTOR UsbDeviceDescriptor
        );
        '''
        DriverGlobals, UsbDevice, UsbDeviceDescriptor = argv

        dev = self.usb_devices.get(UsbDevice)
        if dev:
            dd = usbdefs.USB_DEVICE_DESCRIPTOR(emu.get_ptr_size())
            self.mem_write(UsbDeviceDescriptor, dd.get_bytes())
        return

    @apihook('WdfMemoryCreate', argc=7)
    def WdfMemoryCreate(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfMemoryCreate(
          PWDF_OBJECT_ATTRIBUTES Attributes,
          POOL_TYPE              PoolType,
          ULONG                  PoolTag,
          size_t                 BufferSize,
          WDFMEMORY              *Memory,
          PVOID                  *Buffer
        );
        '''
        DriverGlobals, Attributes, PoolType, PoolTag, BufferSize, Mem, Buf = argv

        rv = ddk.STATUS_SUCCESS

        ptr = self.mem_alloc(BufferSize, tag='api.struct.WDFMEMORY')

        if Mem:
            self.mem_write(Mem, (ptr).to_bytes(emu.get_ptr_size(), 'little'))
        if Buf:
            self.mem_write(Buf, (ptr).to_bytes(emu.get_ptr_size(), 'little'))

        return rv

    @apihook('WdfUsbTargetDeviceSelectConfig', argc=4)
    def WdfUsbTargetDeviceSelectConfig(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfUsbTargetDeviceSelectConfig(
          WDFUSBDEVICE                         UsbDevice,
          PWDF_OBJECT_ATTRIBUTES               PipeAttributes,
          PWDF_USB_DEVICE_SELECT_CONFIG_PARAMS Params
        );
        '''
        DriverGlobals, UsbDevice, PipeAttributes, Params = argv

        rv = ddk.STATUS_SUCCESS
        cfg_params = self.types.WDF_USB_DEVICE_SELECT_CONFIG_PARAMS(emu.get_ptr_size())
        cfg_params = self.mem_cast(cfg_params, Params)

        dev = self.usb_devices.get(UsbDevice)

        enum = self.types.WdfUsbTargetDeviceSelectConfigType
        if cfg_params.Type == enum.WdfUsbTargetDeviceSelectConfigTypeSingleInterface:
            dev.num_interfaces = 1
            hnd = self.get_handle()
            uf = WdfUsbInterface()
            uf.config_desc = dev.config_desc
            uf.iface_index = 0
            self.usb_interfaces.update({hnd: uf})
            cfg_params.Types.SingleInterface.ConfiguredUsbInterface = hnd
        elif cfg_params.Type == enum.WdfUsbTargetDeviceSelectConfigTypeMultiInterface:
            dev.num_interfaces = cfg_params.Types.MultiInterface.NumberInterfaces
        elif cfg_params.Type == enum.WdfUsbTargetDeviceSelectConfigTypeInterfacesDescriptor:
            dev.num_interfaces = cfg_params.Types.Descriptor.NumInterfaceDescriptors

        self.mem_write(Params, cfg_params.get_bytes())

        return rv

    @apihook('WdfUsbTargetDeviceRetrieveConfigDescriptor', argc=4)
    def WdfUsbTargetDeviceRetrieveConfigDescriptor(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfUsbTargetDeviceRetrieveConfigDescriptor(
          WDFUSBDEVICE UsbDevice,
          PVOID        ConfigDescriptor,
          PUSHORT      ConfigDescriptorLength
        );
        '''
        DriverGlobals, UsbDevice, ConfigDescriptor, ConfigDescriptorLength = argv
        rv = ddk.STATUS_BUFFER_TOO_SMALL

        buf_len = self.mem_read(ConfigDescriptorLength, 2)
        buf_len = int.from_bytes(buf_len, 'little')
        # For now, we basically assume this function is hooked since it has extremely specific
        # value
        cd = usbdefs.USB_CONFIGURATION_DESCRIPTOR()
        if ConfigDescriptor:
            cd = self.mem_cast(cd, ConfigDescriptor)
            dev = self.usb_devices.get(UsbDevice)
            if dev:
                if cd.bLength == 0:
                    self.mem_write(ConfigDescriptorLength, (cd.sizeof()).to_bytes(2,
                                                                                  'little'))
                    self.mem_write(ConfigDescriptor, cd.get_bytes())

                dev.config_desc = self.mem_read(ConfigDescriptor, buf_len)

                rv = ddk.STATUS_SUCCESS
            else:
                self.mem_write(ConfigDescriptorLength, (cd.sizeof()).to_bytes(2, 'little'))

        return rv

    @apihook('WdfUsbInterfaceSelectSetting', argc=4)
    def WdfUsbInterfaceSelectSetting(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfUsbInterfaceSelectSetting(
          WDFUSBINTERFACE                          UsbInterface,
          PWDF_OBJECT_ATTRIBUTES                   PipesAttributes,
          PWDF_USB_INTERFACE_SELECT_SETTING_PARAMS Params
        );
        '''
        DriverGlobals, UsbInterface, PipesAttributes, Params = argv

        rv = ddk.STATUS_INVALID_HANDLE
        uif = self.usb_interfaces.get(UsbInterface)
        if uif:
            ifparams = self.types.WDF_USB_INTERFACE_SELECT_SETTING_PARAMS(emu.get_ptr_size())
            ifparams = self.mem_cast(ifparams, Params)

            enum = self.types.WdfUsbTargetDeviceSelectSettingType
            if ifparams.Type == enum.WdfUsbInterfaceSelectSettingTypeSetting:
                uif.setting_index = ifparams.Types.Interface.SettingIndex
            rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('WdfUsbTargetDeviceGetNumInterfaces', argc=2)
    def WdfUsbTargetDeviceGetNumInterfaces(self, emu, argv, ctx={}):
        '''
        UCHAR WdfUsbTargetDeviceGetNumInterfaces(
          WDFUSBDEVICE UsbDevice
        );
        '''
        DriverGlobals, UsbDevice = argv

        rv = 0
        dev = self.usb_devices.get(UsbDevice)
        if dev:
            rv = dev.num_interfaces

        return rv

    @apihook('WdfUsbInterfaceGetNumConfiguredPipes', argc=2)
    def WdfUsbInterfaceGetNumConfiguredPipes(self, emu, argv, ctx={}):
        '''
        BYTE WdfUsbInterfaceGetNumConfiguredPipes(
          WDFUSBINTERFACE UsbInterface
        );
        '''
        DriverGlobals, UsbInterface = argv

        rv = 0
        uif = self.usb_interfaces.get(UsbInterface)

        if uif:
            interfaces = self.parse_usb_config(uif.config_desc)
            for i, eps in interfaces:
                if uif.iface_index == i.bInterfaceNumber:
                    rv = len(eps)
                    break

        return rv

    @apihook('WdfUsbInterfaceGetNumSettings', argc=2)
    def WdfUsbInterfaceGetNumSettings(self, emu, argv, ctx={}):
        '''
        BYTE WdfUsbInterfaceGetNumSettings(
          WDFUSBINTERFACE UsbInterface
        );
        '''
        DriverGlobals, UsbInterface = argv

        rv = 0
        uif = self.usb_interfaces.get(UsbInterface)

        interfaces = self.parse_usb_config(uif.config_desc)

        for i in interfaces:
            if uif.iface_index == i[0].bInterfaceNumber:
                rv += 1

        return rv

    @apihook('WdfUsbTargetDeviceRetrieveInformation', argc=3)
    def WdfUsbTargetDeviceRetrieveInformation(self, emu, argv, ctx={}):
        '''
        NTSTATUS WdfUsbTargetDeviceRetrieveInformation(
          WDFUSBDEVICE                UsbDevice,
          PWDF_USB_DEVICE_INFORMATION Information
        );
        '''
        DriverGlobals, UsbDevice, Information = argv

        rv = ddk.STATUS_INVALID_HANDLE
        dev = self.usb_devices.get(UsbDevice)
        if dev:
            info = self.types.WDF_USB_DEVICE_INFORMATION(emu.get_ptr_size())
            info = self.mem_cast(info, Information)
            info.Size = info.sizeof()
            info.UsbdVersionInformation.USBDI_Version = 0x600
            self.mem_write(Information, info.get_bytes())
            rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('WdfUsbInterfaceGetConfiguredPipe', argc=4)
    def WdfUsbInterfaceGetConfiguredPipe(self, emu, argv, ctx={}):
        '''
        WDFUSBPIPE WdfUsbInterfaceGetConfiguredPipe(
          WDFUSBINTERFACE           UsbInterface,
          UCHAR                     PipeIndex,
          PWDF_USB_PIPE_INFORMATION PipeInfo
        );
        '''
        DriverGlobals, UsbInterface, PipeIndex, PipeInfo = argv

        rv = 0
        uif = self.usb_interfaces.get(UsbInterface)

        interfaces = self.parse_usb_config(uif.config_desc)
        if PipeInfo:
            for i, eps in interfaces:
                if uif.iface_index == i.bInterfaceNumber:
                    if PipeIndex > len(eps):
                        break
                    ep = eps[PipeIndex]
                    info = self.types.WDF_USB_PIPE_INFORMATION(emu.get_ptr_size())
                    info = self.mem_cast(info, PipeInfo)
                    info.Size = info.sizeof()
                    info.MaximumPacketSize = ep.wMaxPacketSize
                    info.EndpointAddress = ep.bEndpointAddress
                    info.Interval = ep.bInterval
                    if ep.bmAttributes & usbdefs.USB_ENDPOINT_TYPE_ISOCHRONOUS:
                        info.PipeType = wdf.WdfUsbPipeTypeIsochronous
                    if ep.bmAttributes & usbdefs.USB_ENDPOINT_TYPE_BULK:
                        info.PipeType = wdf.WdfUsbPipeTypeBulk
                    if ep.bmAttributes & usbdefs.USB_ENDPOINT_TYPE_INTERRUPT:
                        info.PipeType = wdf.WdfUsbPipeTypeInterrupt
                    info.PipeType = ep.bmAttributes
                    self.mem_write(PipeInfo, info.get_bytes())

        if uif:
            hnd = self.get_handle()
            up = WdfUsbPipe()
            up.interface = uif
            up.index = PipeIndex
            self.usb_pipes.update({hnd: up})
            rv = hnd

        return rv

    @apihook('WdfUsbTargetPipeGetInformation', argc=3)
    def WdfUsbTargetPipeGetInformation(self, emu, argv, ctx={}):
        '''
        void WdfUsbTargetPipeGetInformation(
          WDFUSBPIPE                Pipe,
          PWDF_USB_PIPE_INFORMATION PipeInformation
        );
        '''
        DriverGlobals, Pipe, PipeInfo = argv

        _pipe = self.usb_pipes.get(Pipe)
        if _pipe:
            uif = _pipe.interface

            interfaces = self.parse_usb_config(uif.config_desc)

            if PipeInfo:
                for i, eps in interfaces:
                    if uif.iface_index == i.bInterfaceNumber:
                        if _pipe.index > len(eps):
                            break
                        ep = eps[_pipe.index]
                        info = self.types.WDF_USB_PIPE_INFORMATION(emu.get_ptr_size())
                        info = self.mem_cast(info, PipeInfo)
                        info.Size = info.sizeof()
                        info.MaximumPacketSize = ep.wMaxPacketSize
                        info.EndpointAddress = ep.bEndpointAddress
                        info.Interval = ep.bInterval
                        if ep.bmAttributes & usbdefs.USB_ENDPOINT_TYPE_ISOCHRONOUS:
                            info.PipeType = wdf.WDF_USB_PIPE_TYPE.WdfUsbPipeTypeIsochronous
                        if ep.bmAttributes & usbdefs.USB_ENDPOINT_TYPE_BULK:
                            info.PipeType = wdf.WDF_USB_PIPE_TYPE.WdfUsbPipeTypeBulk
                        if ep.bmAttributes & usbdefs.USB_ENDPOINT_TYPE_INTERRUPT:
                            info.PipeType = wdf.WDF_USB_PIPE_TYPE.WdfUsbPipeTypeInterrupt
                        info.PipeType = ep.bmAttributes
                        self.mem_write(PipeInfo, info.get_bytes())

        return

    @apihook('WdfUsbInterfaceGetInterfaceNumber', argc=2)
    def WdfUsbInterfaceGetInterfaceNumber(self, emu, argv, ctx={}):
        '''
        BYTE WdfUsbInterfaceGetInterfaceNumber(
          WDFUSBINTERFACE UsbInterface
        );
        '''
        DriverGlobals, UsbInterface = argv

        rv = 0
        uif = self.usb_interfaces.get(UsbInterface)

        if uif:
            rv = uif.iface_index

        return rv
