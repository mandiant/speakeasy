# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct
import ctypes as ct


USB_DEVICE_DESCRIPTOR_TYPE = 0x01
USB_CONFIGURATION_DESCRIPTOR_TYPE = 0x02
USB_STRING_DESCRIPTOR_TYPE = 0x03
USB_INTERFACE_DESCRIPTOR_TYPE = 0x04
USB_ENDPOINT_DESCRIPTOR_TYPE = 0x05

USB_ENDPOINT_TYPE_MASK = 0x03
USB_ENDPOINT_TYPE_CONTROL = 0x00
USB_ENDPOINT_TYPE_ISOCHRONOUS = 0x01
USB_ENDPOINT_TYPE_BULK = 0x02
USB_ENDPOINT_TYPE_INTERRUPT = 0x03

USB_DIR_IN = 0x80
USB_DIR_OUT = 0x00


class USB_DEVICE_DESCRIPTOR(EmuStruct):
    def __init__(self):
        super().__init__()
        self.bLength = ct.c_uint8
        self.bDescriptorType = ct.c_uint8
        self.bcdUSB = ct.c_uint16
        self.bDeviceClass = ct.c_uint8
        self.bDeviceSubClass = ct.c_uint8
        self.bDeviceProtocol = ct.c_uint8
        self.bMaxPacketSize0 = ct.c_uint8
        self.idVendor = ct.c_uint16
        self.idProduct = ct.c_uint16
        self.bcdDevice = ct.c_uint16
        self.iManufacturer = ct.c_uint8
        self.iProduct = ct.c_uint8
        self.iSerialNumber = ct.c_uint8
        self.bNumConfigurations = ct.c_uint8


class USB_CONFIGURATION_DESCRIPTOR(EmuStruct):
    def __init__(self):
        super().__init__()
        self.bLength = ct.c_uint8
        self.bDescriptorType = ct.c_uint8
        self.wTotalLength = ct.c_uint16
        self.bNumInterfaces = ct.c_uint8
        self.bConfigurationValue = ct.c_uint8
        self.iConfiguration = ct.c_uint8
        self.bmAttributes = ct.c_uint8
        self.MaxPower = ct.c_uint8


class USB_INTERFACE_DESCRIPTOR(EmuStruct):
    def __init__(self):
        super().__init__()
        self.bLength = ct.c_uint8
        self.bDescriptorType = ct.c_uint8
        self.bInterfaceNumber = ct.c_uint8
        self.bAlternateSetting = ct.c_uint8
        self.bNumEndpoints = ct.c_uint8
        self.bInterfaceClass = ct.c_uint8
        self.bInterfaceSubClass = ct.c_uint8
        self.bInterfaceProtocol = ct.c_uint8
        self.iInterface = ct.c_uint8


class USB_ENDPOINT_DESCRIPTOR(EmuStruct):
    def __init__(self):
        super().__init__()
        self.bLength = ct.c_uint8
        self.bDescriptorType = ct.c_uint8
        self.bEndpointAddress = ct.c_uint8
        self.bmAttributes = ct.c_uint8
        self.wMaxPacketSize = ct.c_uint16
        self.bInterval = ct.c_uint8


class USBD_VERSION_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.USBDI_Version = ct.c_uint32
        self.Supported_USB_Version = ct.c_uint32
