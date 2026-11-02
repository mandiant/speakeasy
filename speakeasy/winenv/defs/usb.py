# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct

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
    bLength: Annotated[int, ct.c_uint8]
    bDescriptorType: Annotated[int, ct.c_uint8]
    bcdUSB: Annotated[int, ct.c_uint16]
    bDeviceClass: Annotated[int, ct.c_uint8]
    bDeviceSubClass: Annotated[int, ct.c_uint8]
    bDeviceProtocol: Annotated[int, ct.c_uint8]
    bMaxPacketSize0: Annotated[int, ct.c_uint8]
    idVendor: Annotated[int, ct.c_uint16]
    idProduct: Annotated[int, ct.c_uint16]
    bcdDevice: Annotated[int, ct.c_uint16]
    iManufacturer: Annotated[int, ct.c_uint8]
    iProduct: Annotated[int, ct.c_uint8]
    iSerialNumber: Annotated[int, ct.c_uint8]
    bNumConfigurations: Annotated[int, ct.c_uint8]

    def __init__(self):
        super().__init__()


class USB_CONFIGURATION_DESCRIPTOR(EmuStruct):
    bLength: Annotated[int, ct.c_uint8]
    bDescriptorType: Annotated[int, ct.c_uint8]
    wTotalLength: Annotated[int, ct.c_uint16]
    bNumInterfaces: Annotated[int, ct.c_uint8]
    bConfigurationValue: Annotated[int, ct.c_uint8]
    iConfiguration: Annotated[int, ct.c_uint8]
    bmAttributes: Annotated[int, ct.c_uint8]
    MaxPower: Annotated[int, ct.c_uint8]

    def __init__(self):
        super().__init__()


class USB_INTERFACE_DESCRIPTOR(EmuStruct):
    bLength: Annotated[int, ct.c_uint8]
    bDescriptorType: Annotated[int, ct.c_uint8]
    bInterfaceNumber: Annotated[int, ct.c_uint8]
    bAlternateSetting: Annotated[int, ct.c_uint8]
    bNumEndpoints: Annotated[int, ct.c_uint8]
    bInterfaceClass: Annotated[int, ct.c_uint8]
    bInterfaceSubClass: Annotated[int, ct.c_uint8]
    bInterfaceProtocol: Annotated[int, ct.c_uint8]
    iInterface: Annotated[int, ct.c_uint8]

    def __init__(self):
        super().__init__()


class USB_ENDPOINT_DESCRIPTOR(EmuStruct):
    bLength: Annotated[int, ct.c_uint8]
    bDescriptorType: Annotated[int, ct.c_uint8]
    bEndpointAddress: Annotated[int, ct.c_uint8]
    bmAttributes: Annotated[int, ct.c_uint8]
    wMaxPacketSize: Annotated[int, ct.c_uint16]
    bInterval: Annotated[int, ct.c_uint8]

    def __init__(self):
        super().__init__()


class USBD_VERSION_INFORMATION(EmuStruct):
    USBDI_Version: Annotated[int, ct.c_uint32]
    Supported_USB_Version: Annotated[int, ct.c_uint32]
