# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING

from speakeasy.winenv.defs.ndis import ndis
from speakeasy.winenv.defs.nt import ddk

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.kernel import WinKernelEmulator

NDIS_STATUS_FAILURE = 0xC0000001
NDIS_STATUS_SUCCESS = 0x00000000
NDIS_STATUS_RESOURCES = 0xC000009A


class Ndis(api.ApiHandler):
    """
    Implements the Network Driver Interface Specification (NDIS) used for
    interacting with network cards.
    """

    name = "ndis"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.handle: int = 4
        self.wrappers: dict[int, bool] = {}
        self.drivers: dict[int, bytes] = {}
        self.protocols: dict[int, bytes] = {}

        self.emu = emu

        self.ndis = ndis
        super().__get_hook_attrs__(self)

    def convert_pool_tag(self, tag):
        ret = "0x00"
        if tag:
            try:
                ret = tag.to_bytes(4, "little").decode("utf-8")
            except Exception:
                ret = f"0x{tag:x}"
        return ret

    def new_id(self):
        tmp = self.handle
        self.handle += 4
        return tmp

    @apihook("NdisGetVersion", argc=0)
    def NdisGetVersion(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT NdisGetVersion();
        """
        ndis_major = 5
        ndis_minor = 0
        osver = self.emu.config.os_ver
        major, minor = osver.major or 0, osver.minor or 0

        if major >= 6:
            ndis_major = 6

        if major >= 10:
            ndis_minor = 0x51
        elif minor >= 1:
            ndis_minor = 1

        out_ver = (ndis_major << 16) | ndis_minor

        return out_ver

    @apihook("NdisGetRoutineAddress", argc=1)
    def NdisGetRoutineAddress(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID NdisGetRoutineAddress(
            PNDIS_STRING NdisRoutineName
        );
        """
        (NdisRoutineName,) = argv
        fn = self.read_unicode_string(NdisRoutineName)

        addr = emu.get_proc("ndis", fn)
        ctx.args[0].display = fn
        return addr

    @apihook("NdisMRegisterMiniportDriver", argc=5)
    def NdisMRegisterMiniportDriver(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NDIS_STATUS NdisMRegisterMiniportDriver(
            PDRIVER_OBJECT DriverObject,
            PUNICODE_STRING RegistryPath,
            NDIS_HANDLE MiniportDriverContext,
            PNDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportDriverCharacteristics,
            PNDIS_HANDLE NdisMiniportDriverHandle
        );
        """
        DriverObject, RegistryPath, MiniportDriverContext, MiniportDriverCharacteristics, NdisMiniportDriverHandle = (
            argv
        )
        rv = NDIS_STATUS_SUCCESS

        if NdisMiniportDriverHandle:
            hnd = self.new_id()
            hnd = hnd.to_bytes(self.get_ptr_size(), "little")
            self.mem_write(NdisMiniportDriverHandle, hnd)
        return rv

    @apihook("NdisInitializeWrapper", argc=4)
    def NdisInitializeWrapper(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID NdisInitializeWrapper(
            PNDIS_HANDLE NdisWrapperHandle,
            PVOID SystemSpecific1,
            PVOID SystemSpecific2,
            PVOID SystemSpecific3
        );
        """
        NdisWrapperHandle, SystemSpecific1, SystemSpecific2, SystemSpecific3 = argv

        hnd = self.new_id()
        self.wrappers.update({hnd: True})
        self.mem_write(NdisWrapperHandle, hnd.to_bytes(self.get_ptr_size(), "little"))

    @apihook("NdisTerminateWrapper", argc=2)
    def NdisTerminateWrapper(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID NdisTerminateWrapper(
            NDIS_HANDLE NdisWrapperHandle,
            PVOID SystemSpecific
        );
        """
        NdisWrapperHandle, SystemSpecific = argv

    @apihook("NdisInitializeReadWriteLock", argc=1)
    def NdisInitializeReadWriteLock(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        VOID NdisInitializeReadWriteLock(
            PNDIS_RW_LOCK Lock
        );
        """
        (Lock,) = argv

    @apihook("NdisMRegisterUnloadHandler", argc=2)
    def NdisMRegisterUnloadHandler(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        VOID NdisMRegisterUnloadHandler(
            NDIS_HANDLE NdisWrapperHandle,
            PDRIVER_UNLOAD UnloadHandler
        );
        """
        NdisWrapperHandle, UnloadHandler = argv

    @apihook("NdisRegisterProtocol", argc=4)
    def NdisRegisterProtocol(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID NdisRegisterProtocol(
            PNDIS_STATUS Status,
            PNDIS_HANDLE NdisProtocolHandle,
            PNDIS_PROTOCOL_CHARACTERISTICS ProtocolCharacteristics,
            UINT CharacteristicsLength
        );
        """
        Status, NdisProtocolHandle, ProtocolCharacteristics, CharacteristicsLength = argv
        rv = NDIS_STATUS_SUCCESS
        hnd = self.new_id()
        pchr = self.mem_read(ProtocolCharacteristics, CharacteristicsLength)

        self.protocols.update({hnd: pchr})

        if Status:
            self.mem_write(Status, rv.to_bytes(4, "little"))

        if NdisProtocolHandle:
            self.mem_write(NdisProtocolHandle, hnd.to_bytes(self.get_ptr_size(), "little"))

    @apihook("NdisIMRegisterLayeredMiniport", argc=4)
    def NdisIMRegisterLayeredMiniport(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NDIS_STATUS NdisIMRegisterLayeredMiniport(
            NDIS_HANDLE NdisWrapperHandle,
            PNDIS_MINIPORT_CHARACTERISTICS MiniportCharacteristics,
            UINT CharacteristicsLength,
            PNDIS_HANDLE DriverHandle
        );
        """
        NdisWrapperHandle, MiniportCharacteristics, CharacteristicsLength, DriverHandle = argv
        rv = NDIS_STATUS_SUCCESS

        if not self.wrappers.get(NdisWrapperHandle):
            rv = NDIS_STATUS_FAILURE

        dhnd = self.new_id()
        mpc = self.mem_read(MiniportCharacteristics, CharacteristicsLength)
        self.drivers.update({dhnd: mpc})

        if DriverHandle:
            self.mem_write(DriverHandle, dhnd.to_bytes(self.get_ptr_size(), "little"))

        return rv

    @apihook("NdisIMAssociateMiniport", argc=2)
    def NdisIMAssociateMiniport(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID NdisIMAssociateMiniport(
            NDIS_HANDLE DriverHandle,
            NDIS_HANDLE ProtocolHandle
        );
        """
        DriverHandle, ProtocolHandle = argv

    @apihook("NdisAllocateGenericObject", argc=3)
    def NdisAllocateGenericObject(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        PNDIS_GENERIC_OBJECT NdisAllocateGenericObject(
            PDRIVER_OBJECT DriverObject,
            ULONG Tag,
            USHORT Size
        );
        """
        DriverObject, Tag, Size = argv

        ptr = 0

        stag = self.convert_pool_tag(Tag)
        ctx.args[1].display = stag

        go = self.ndis.NDIS_GENERIC_OBJECT(emu.get_ptr_size())
        go.DriverObject = DriverObject  # type: ignore[assignment]

        total = Size + self.sizeof(go)
        ptr = self.mem_alloc(size=total, tag=f"api.struct.NDIS_GENERIC_OBJECT.{stag}")
        self.mem_write(ptr, self.get_bytes(go))

        return ptr

    @apihook("NdisAllocateMemoryWithTag", argc=3)
    def NdisAllocateMemoryWithTag(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NDIS_STATUS NdisAllocateMemoryWithTag(
            PVOID *VirtualAddress,
            UINT Length,
            ULONG Tag
        );
        """
        VirtualAddress, Length, Tag = argv

        rv = ddk.STATUS_SUCCESS

        stag = self.convert_pool_tag(Tag)
        ctx.args[2].display = stag

        ptr = self.mem_alloc(size=Length, tag=f"api.ndis_pool.{stag}")
        self.mem_write(VirtualAddress, ptr.to_bytes(emu.get_ptr_size(), "little"))

        return rv

    @apihook("NdisAllocateNetBufferListPool", argc=2)
    def NdisAllocateNetBufferListPool(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NDIS_HANDLE NdisAllocateNetBufferListPool(
            NDIS_HANDLE NdisHandle,
            const NET_BUFFER_LIST_POOL_PARAMETERS *Parameters
        );
        """
        NdisHandle, Parameters = argv

        params = self.mem_cast(self.ndis.NET_BUFFER_LIST_POOL_PARAMETERS(emu.get_ptr_size()), Parameters)

        nbl = self.ndis.NET_BUFFER_LIST(emu.get_ptr_size())

        if params.fAllocateNetBuffer:
            net_buf = self.ndis.NET_BUFFER(emu.get_ptr_size())
            nb_ptr = self.mem_alloc(size=self.sizeof(net_buf), tag="api.struct.NET_BUFFER")
            nbl.FirstNetBuffer = nb_ptr

            self.mem_write(nb_ptr, self.get_bytes(net_buf))

        nbl_ptr = self.mem_alloc(size=self.sizeof(nbl), tag="api.struct.NET_BUFFER_LIST")
        self.mem_write(nbl_ptr, self.get_bytes(nbl))

        return nbl_ptr

    @apihook("NdisFreeNetBufferListPool", argc=1)
    def NdisFreeNetBufferListPool(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        VOID NdisFreeNetBufferListPool(
            NDIS_HANDLE PoolHandle
        );
        """
        (PoolHandle,) = argv

    @apihook("NdisFreeMemory", argc=3)
    def NdisFreeMemory(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID NdisFreeMemory(
            PVOID VirtualAddress,
            UINT Length,
            UINT MemoryFlags
        );
        """
        VirtualAddress, Length, MemoryFlags = argv

    @apihook("NdisFreeGenericObject", argc=1)
    def NdisFreeGenericObject(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID NdisFreeGenericObject(
            PNDIS_GENERIC_OBJECT NdisObject
        );
        """
        (NdisObject,) = argv
