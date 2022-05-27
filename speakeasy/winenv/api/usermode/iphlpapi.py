# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

import binascii

import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.windows.iphlpapi as iphlpapi_types

from .. import api


class Iphlpapi(api.ApiHandler):
    """
    Implements exported functions from iphlpapi.dll
    """
    name = 'iphlpapi'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Iphlpapi, self).__init__(emu)

        self.iphlpapi_types = iphlpapi_types

    @apihook('GetAdaptersInfo', argc=2)
    def GetAdaptersInfo(self, emu, argv, ctx={}):
        ptr_adapter_info, size_ptr = argv
        rv = 0

        adapters = emu.get_network_adapters()
        adapter_count = len(adapters)

        if not ptr_adapter_info:
            adapter_info = self.iphlpapi_types.IP_ADAPTER_INFO(emu.get_ptr_size())
            size = adapter_info.sizeof()
            self.mem_write(size_ptr, size.to_bytes(4, 'little'))
            return windefs.ERROR_BUFFER_OVERFLOW

        for index, adapter in enumerate(adapters):
            adapter_info = self.iphlpapi_types.IP_ADAPTER_INFO(emu.get_ptr_size())

            adapter_info.AdapterName = adapter.get('name').encode('utf-8')
            adapter_info.Description = adapter.get('description').encode('utf-8')
            adapter_info.AddressLength = 6
            adapter_info.Address = binascii.unhexlify(adapter.get('mac_address').replace('-', ''))
            adapter_info.Type = iphlpapi_types.get_adapter_type(adapter.get('type'))
            adapter_info.IpAddressList.IpAddress = adapter.get('ip_address').encode('utf-8')
            adapter_info.IpAddressList.IpMask = adapter.get('subnet_mask').encode('utf-8')
            adapter_info.DhcpEnabled = adapter.get('dhcp_enabled')

            if index < adapter_count - 1:
                ptr_next = self.mem_alloc(adapter_info.sizeof(), tag='api.struct.IP_ADAPTER_INFO')
            else:
                ptr_next = 0

            adapter_info.Next = ptr_next
            self.mem_write(ptr_adapter_info, self.get_bytes(adapter_info))
            ptr_adapter_info = ptr_next

        return rv
