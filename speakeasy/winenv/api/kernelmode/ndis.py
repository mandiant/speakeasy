# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.nt.ddk as ddk

import speakeasy.winenv.defs.nt.ntoskrnl as nt
import speakeasy.winenv.defs.ndis.ndis as ndis

from .. import api


NDIS_STATUS_FAILURE = 0xC0000001
NDIS_STATUS_SUCCESS = 0x00000000
NDIS_STATUS_RESOURCES = 0xC000009A


class Ndis(api.ApiHandler):
    """
    Implements the Network Driver Interface Specification (NDIS) used for
    interacting with network cards.
    """

    name = 'ndis'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Ndis, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.handle = 4
        self.wrappers = {}
        self.drivers = {}
        self.protocols = {}

        self.emu = emu

        self.win = nt
        self.ndis = ndis
        super(Ndis, self).__get_hook_attrs__(self)

    def convert_pool_tag(self, tag):
        ret = '0x00'
        if tag:
            try:
                ret = tag.to_bytes(4, 'little').decode('utf-8')
            except Exception:
                ret = '0x%x' % tag
        return ret

    def new_id(self):
        tmp = self.handle
        self.handle += 4
        return tmp

    @apihook('NdisGetVersion', argc=0)
    def NdisGetVersion(self, emu, argv, ctx={}):
        """
        UINT NdisGetVersion();
        """

        ndis_major = 5
        ndis_minor = 0
        osver = self.get_os_version()
        major, minor = osver['major'], osver['minor']

        if major >= 6:
            ndis_major = 6

        if major >= 10:
            ndis_minor = 0x51
        elif minor >= 1:
            ndis_minor = 1

        out_ver = (ndis_major << 16) | ndis_minor

        return out_ver

    @apihook('NdisGetRoutineAddress', argc=1)
    def NdisGetRoutineAddress(self, emu, argv, ctx={}):
        """
        PVOID NdisGetRoutineAddress(
            PNDIS_STRING NdisRoutineName
        );
        """
        NdisRoutineName, = argv
        fn = self.read_unicode_string(NdisRoutineName)

        addr = emu.get_proc('ndis', fn)
        argv[0] = fn
        return addr

    @apihook('NdisMRegisterMiniportDriver', argc=5)
    def NdisMRegisterMiniportDriver(self, emu, argv, ctx={}):
        """
        NDIS_STATUS NdisMRegisterMiniportDriver(
            PDRIVER_OBJECT DriverObject,
            PUNICODE_STRING RegistryPath,
            NDIS_HANDLE MiniportDriverContext,
            PNDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportDriverCharacteristics,
            PNDIS_HANDLE NdisMiniportDriverHandle
        );
        """
        drv, reg, drv_ctx, chars, phnd = argv
        rv = NDIS_STATUS_SUCCESS

        if phnd:
            hnd = self.new_id()
            hnd = hnd.to_bytes(4, 'little')
            self.mem_write(phnd, hnd)
        return rv

    @apihook('NdisInitializeWrapper', argc=4)
    def NdisInitializeWrapper(self, emu, argv, ctx={}):
        """
        VOID NdisInitializeWrapper(
            PNDIS_HANDLE    NdisWrapperHandle,
            PVOID           SystemSpecific1,
            PVOID           SystemSpecific2,
            PVOID           SystemSpecific3)
        """
        pHandle, ss1, ss2, ss3 = argv

        hnd = self.new_id()
        self.wrappers.update({hnd: True})
        self.mem_write(pHandle, hnd.to_bytes(self.get_ptr_size(), 'little'))

    @apihook('NdisTerminateWrapper', argc=2)
    def NdisTerminateWrapper(self, emu, argv, ctx={}):
        """
        VOID NdisTerminateWrapper(
        _In_ NDIS_HANDLE NdisWrapperHandle,
        _In_ PVOID       SystemSpecific
        );
        """
        hnd, ss = argv

    @apihook('NdisInitializeReadWriteLock', argc=1)
    def NdisInitializeReadWriteLock(self, emu, argv, ctx={}):
        """
        void NdisInitializeReadWriteLock(
            PNDIS_RW_LOCK Lock
        );
        """
        lock, = argv

    @apihook('NdisMRegisterUnloadHandler', argc=2)
    def NdisMRegisterUnloadHandler(self, emu, argv, ctx={}):
        """
        VOID NdisMRegisterUnloadHandler(
        _In_ NDIS_HANDLE    NdisWrapperHandle,
        _In_ PDRIVER_UNLOAD UnloadHandler
        );
        """
        hnd, unload = argv

    @apihook('NdisRegisterProtocol', argc=4)
    def NdisRegisterProtocol(self, emu, argv, ctx={}):
        """
        VOID NdisRegisterProtocol(
        _Out_ PNDIS_STATUS                   Status,
        _Out_ PNDIS_HANDLE                   NdisProtocolHandle,
        _In_  PNDIS_PROTOCOL_CHARACTERISTICS ProtocolCharacteristics,
        _In_  UINT                           CharacteristicsLength
        );
        """
        pStatus, pProtoHandle, pChars, clen = argv
        rv = NDIS_STATUS_SUCCESS
        hnd = self.new_id()
        pchr = self.mem_read(pChars, clen)

        self.protocols.update({hnd: pchr})

        if pStatus:
            self.mem_write(pStatus, rv.to_bytes(4, 'little'))

        if pProtoHandle:
            self.mem_write(pProtoHandle, hnd.to_bytes(4, 'little'))

    @apihook('NdisIMRegisterLayeredMiniport', argc=4)
    def NdisIMRegisterLayeredMiniport(self, emu, argv, ctx={}):
        """
        NDIS_STATUS NdisIMRegisterLayeredMiniport(
        _In_  NDIS_HANDLE                    NdisWrapperHandle,
        _In_  PNDIS_MINIPORT_CHARACTERISTICS MiniportCharacteristics,
        _In_  UINT                           CharacteristicsLength,
        _Out_ PNDIS_HANDLE                   DriverHandle
        );
        """
        hnd, mp_chars, clen, drv_hnd = argv
        rv = NDIS_STATUS_SUCCESS

        if not self.wrappers.get(hnd):
            rv = NDIS_STATUS_FAILURE

        dhnd = self.new_id()
        mpc = self.mem_read(mp_chars, clen)
        self.drivers.update({dhnd: mpc})

        if drv_hnd:
            self.mem_write(drv_hnd, dhnd.to_bytes(4, 'little'))

        return rv

    @apihook('NdisIMAssociateMiniport', argc=2)
    def NdisIMAssociateMiniport(self, emu, argv, ctx={}):
        """
        void NdisIMAssociateMiniport(
        NDIS_HANDLE DriverHandle,
        NDIS_HANDLE ProtocolHandle
        );
        """
        drv_hnd, phnd = argv

    @apihook('NdisAllocateGenericObject', argc=3)
    def NdisAllocateGenericObject(self, emu, argv, ctx={}):
        """
        PNDIS_GENERIC_OBJECT NdisAllocateGenericObject(
            PDRIVER_OBJECT DriverObject,
            ULONG          Tag,
            USHORT         Size
        );
        """
        drv, tag, size = argv

        ptr = 0

        stag = self.convert_pool_tag(tag)
        argv[1] = stag

        go = self.ndis.NDIS_GENERIC_OBJECT(emu.get_ptr_size())
        go.DriverObject = drv

        total = size + self.sizeof(go)
        ptr = self.mem_alloc(size=total,
                             tag='api.struct.NDIS_GENERIC_OBJECT.%s' % (stag))
        self.mem_write(ptr, self.get_bytes(go))

        return ptr

    @apihook('NdisAllocateMemoryWithTag', argc=3)
    def NdisAllocateMemoryWithTag(self, emu, argv, ctx={}):
        """
        NDIS_STATUS NdisAllocateMemoryWithTag(
          _Out_ PVOID *VirtualAddress,
          _In_  UINT  Length,
          _In_  ULONG Tag
        );
        """
        va, size, tag = argv

        rv = ddk.STATUS_SUCCESS

        stag = self.convert_pool_tag(tag)
        argv[2] = stag

        ptr = self.mem_alloc(size=size, tag='api.ndis_pool.%s' % (stag))
        self.mem_write(va,
                       ptr.to_bytes(emu.get_ptr_size(), 'little'))

        return rv

    @apihook('NdisAllocateNetBufferListPool', argc=2)
    def NdisAllocateNetBufferListPool(self, emu, argv, ctx={}):
        """
        NDIS_HANDLE NdisAllocateNetBufferListPool(
          NDIS_HANDLE                      NdisHandle,
          PNET_BUFFER_LIST_POOL_PARAMETERS Parameters
        );
        """
        NdisHandle, Parameters = argv

        params = self.mem_cast(self.ndis.NET_BUFFER_LIST_POOL_PARAMETERS(emu.get_ptr_size()),
                               Parameters)

        nbl = self.ndis.NET_BUFFER_LIST(emu.get_ptr_size())

        if params.fAllocateNetBuffer:
            net_buf = self.ndis.NET_BUFFER(emu.get_ptr_size())
            nb_ptr = self.mem_alloc(size=self.sizeof(net_buf),
                                    tag='api.struct.NET_BUFFER')
            nbl.FirstNetBuffer = nb_ptr

            self.mem_write(nb_ptr, self.get_bytes(net_buf))

        nbl_ptr = self.mem_alloc(size=self.sizeof(nbl),
                                 tag='api.struct.NET_BUFFER_LIST')
        self.mem_write(nbl_ptr, self.get_bytes(nbl))

        return nbl_ptr

    @apihook('NdisFreeNetBufferListPool', argc=1)
    def NdisFreeNetBufferListPool(self, emu, argv, ctx={}):
        """
        void NdisFreeNetBufferListPool(
        NDIS_HANDLE PoolHandle
        );
        """
        handle, = argv

        return

    @apihook('NdisFreeMemory', argc=3)
    def NdisFreeMemory(self, emu, argv, ctx={}):
        """
        void NdisFreeMemory(
        PVOID VirtualAddress,
        UINT  Length,
        UINT  MemoryFlags
        );
        """
        va, length, flags = argv

        return

    @apihook('NdisFreeGenericObject', argc=1)
    def NdisFreeGenericObject(self, emu, argv, ctx={}):
        """
        void NdisFreeGenericObject(
        PNDIS_GENERIC_OBJECT NdisObject
        );
        """
        pObj,  = argv

        return
