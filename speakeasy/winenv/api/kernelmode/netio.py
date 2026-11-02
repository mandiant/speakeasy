# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from socket import inet_ntoa, ntohs
from typing import TYPE_CHECKING

import speakeasy.winenv.defs.nt.ntoskrnl as nt
import speakeasy.winenv.defs.winsock.ws2_32 as winsock
from speakeasy.errors import ApiEmuError
from speakeasy.windows import netman, objman
from speakeasy.winenv.defs import wsk
from speakeasy.winenv.defs.nt import ddk

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.kernel import WinKernelEmulator

WSK_FLAG_BASIC_SOCKET = 0x00000000
WSK_FLAG_LISTEN_SOCKET = 0x00000001
WSK_FLAG_CONNECTION_SOCKET = 0x00000002
WSK_FLAG_DATAGRAM_SOCKET = 0x00000004


class WskSocket(objman.KernelObject):
    def __init__(self, api, family, stype, protocol, flags):
        self.emu = api.emu
        super().__init__(self.emu)
        self.family: int = family
        self.sock_type: int = stype
        self.protocol: int = protocol
        self.flags: int = flags
        self.dispatch: wsk.WSK_PROVIDER_DATAGRAM_DISPATCH | None = None
        self.dispatch_addr: int = 0
        self.dispatch_ptr: int = 0
        self.types = api.win

        # TODO: support other wsk socket types
        if flags == WSK_FLAG_DATAGRAM_SOCKET:
            self.dispatch = self.types.WSK_PROVIDER_DATAGRAM_DISPATCH(self.emu.get_ptr_size())
            self.dispatch_ptr = self.emu.mem_map(
                size=self.sizeof(self.dispatch) + self.emu.get_ptr_size(),
                tag="api.struct.WSK_PROVIDER_DATAGRAM_DISPATCH",
            )

            # We need a ptr to the dispatch table ptr
            self.dispatch_addr = self.dispatch_ptr + self.emu.get_ptr_size()
            self.emu.mem_write(self.dispatch_ptr, self.dispatch_addr.to_bytes(self.emu.get_ptr_size(), "little"))

            addr = self.emu.add_callback(Netio.name, api.WskControlSocket.__apihook__[0])
            self.dispatch.Basic.WskControlSocket = addr
            addr = self.emu.add_callback(Netio.name, api.WskCloseSocket.__apihook__[0])
            self.dispatch.Basic.WskCloseSocket = addr
            addr = self.emu.add_callback(Netio.name, api.WskBind.__apihook__[0])
            self.dispatch.WskBind = addr
            addr = self.emu.add_callback(Netio.name, api.WskSendTo.__apihook__[0])
            self.dispatch.WskSendTo = addr
            addr = self.emu.add_callback(Netio.name, api.WskReceiveFrom.__apihook__[0])
            self.dispatch.WskReceiveFrom = addr
            addr = self.emu.add_callback(Netio.name, api.WskRelease.__apihook__[0])
            self.dispatch.WskRelease = addr
            addr = self.emu.add_callback(Netio.name, api.WskGetLocalAddress.__apihook__[0])
            self.dispatch.WskGetLocalAddress = addr

            self.emu.mem_write(self.dispatch_addr, self.get_bytes(self.dispatch))

        else:
            raise ApiEmuError(f"Unsupported WSK socket type: 0x{flags:x}")

    def get_dispatch_ptr(self):
        return self.dispatch_ptr


class Netio(api.ApiHandler):
    """
    Implements kernel networking functions implemented in netio.sys
    """

    name = "netio"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.wsk_registrations: dict[int, int] = {}
        self.wsk_sockets: dict[int, WskSocket] = {}
        self.provider_npi: wsk.WSK_PROVIDER_NPI | None = None

        self.win = wsk
        self.nt = nt

        self.netman: netman.NetworkManager = netman.NetworkManager(emu.handle_allocator, config=emu.config.network)

        super().__get_hook_attrs__(self)

        self.prov_disp: wsk.WSK_PROVIDER_DISPATCH = self.win.WSK_PROVIDER_DISPATCH(emu.get_ptr_size())
        self.prov_disp.Version = 0x100

        addr = emu.add_callback(Netio.name, self.WskSocket.__apihook__[0])
        self.prov_disp.WskSocket = addr
        addr = emu.add_callback(Netio.name, self.WskSocketConnect.__apihook__[0])
        self.prov_disp.WskSocketConnect = addr
        addr = emu.add_callback(Netio.name, self.WskControlClient.__apihook__[0])
        self.prov_disp.WskControlClient = addr
        addr = emu.add_callback(Netio.name, self.WskGetAddressInfo.__apihook__[0])
        self.prov_disp.WskGetAddressInfo = addr
        addr = emu.add_callback(Netio.name, self.WskFreeAddressInfo.__apihook__[0])
        self.prov_disp.WskFreeAddressInfo = addr
        addr = emu.add_callback(Netio.name, self.WskGetNameInfo.__apihook__[0])
        self.prov_disp.WskGetNameInfo = addr

    @apihook("WskRegister", argc=2)
    def WskRegister(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskRegister(
            PWSK_CLIENT_NPI WskClientNpi,
            PWSK_REGISTRATION WskRegistration
        );
        """
        WskClientNpi, WskRegistration = argv
        rv = 0

        self.wsk_registrations.update({WskRegistration: WskClientNpi})

        return rv

    @apihook("WskCaptureProviderNPI", argc=3)
    def WskCaptureProviderNPI(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskCaptureProviderNPI(
            PWSK_REGISTRATION WskRegistration,
            ULONG WaitTimeout,
            PWSK_PROVIDER_NPI WskProviderNpi
        );
        """
        WskRegistration, WaitTimeout, WskProviderNpi = argv
        rv = 0

        cli = self.wsk_registrations.get(WskRegistration)
        if not cli:
            rv = ddk.STATUS_NOINTERFACE
        else:
            if not self.provider_npi:
                wpn = self.win.WSK_PROVIDER_NPI(emu.get_ptr_size())

                wpn.Client = cli
                # Allocate the wpn dispatch table
                wpd_addr = self.mem_alloc(
                    size=self.sizeof(self.prov_disp),
                    tag="api.struct.WSK_PROVIDER_DISPATCH",
                )
                wpn.Dispatch = wpd_addr

                self.mem_write(wpd_addr, self.get_bytes(self.prov_disp))
                self.provider_npi = wpn
            self.mem_write(WskProviderNpi, self.get_bytes(self.provider_npi))

        return rv

    @apihook("callback_WskSocket", argc=11)
    def WskSocket(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskSocket(
            PWSK_CLIENT Client,
            ADDRESS_FAMILY AddressFamily,
            USHORT SocketType,
            ULONG Protocol,
            ULONG Flags,
            PVOID SocketContext,
            const VOID *Dispatch,
            PEPROCESS OwningProcess,
            PETHREAD OwningThread,
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            PIRP Irp
        );
        """
        (
            Client,
            AddressFamily,
            SocketType,
            Protocol,
            Flags,
            SocketContext,
            Dispatch,
            OwningProcess,
            OwningThread,
            SecurityDescriptor,
            Irp,
        ) = argv
        rv = ddk.STATUS_INVALID_PARAMETER

        if Irp:
            irp = self.mem_cast(self.nt.IRP(emu.get_ptr_size()), Irp)
            sock = WskSocket(self, AddressFamily, SocketType, Protocol, Flags)
            addr = sock.get_dispatch_ptr()
            irp.IoStatus.Information = addr
            self.write_back(Irp, irp)

            rv = ddk.STATUS_SUCCESS
            self.wsk_sockets.update({addr: sock})

        return rv

    @apihook("callback_WskSocketConnect", argc=12)
    def WskSocketConnect(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskSocketConnect(
            PWSK_CLIENT Client,
            USHORT SocketType,
            ULONG Protocol,
            PSOCKADDR LocalAddress,
            PSOCKADDR RemoteAddress,
            ULONG Flags,
            PVOID SocketContext,
            const WSK_CLIENT_CONNECTION_DISPATCH *Dispatch,
            PEPROCESS OwningProcess,
            PETHREAD OwningThread,
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            PIRP Irp
        );
        """
        (
            Client,
            SocketType,
            Protocol,
            LocalAddress,
            RemoteAddress,
            Flags,
            SocketContext,
            Dispatch,
            OwningProcess,
            OwningThread,
            SecurityDescriptor,
            Irp,
        ) = argv

        rv = 0

        return rv

    @apihook("callback_WskControlClient", argc=8)
    def WskControlClient(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskControlClient(
            PWSK_CLIENT Client,
            ULONG ControlCode,
            SIZE_T InputSize,
            PVOID InputBuffer,
            SIZE_T OutputSize,
            PVOID OutputBuffer,
            SIZE_T *OutputSizeReturned,
            PIRP Irp
        );
        """
        Client, ControlCode, InputSize, InputBuffer, OutputSize, OutputBuffer, OutputSizeReturned, Irp = argv
        rv = 0

        return rv

    @apihook("callback_WskGetAddressInfo", argc=10)
    def WskGetAddressInfo(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskGetAddressInfo(
            PWSK_CLIENT Client,
            PUNICODE_STRING NodeName,
            PUNICODE_STRING ServiceName,
            ULONG NameSpace,
            GUID *Provider,
            PADDRINFOEXW Hints,
            PADDRINFOEXW *Result,
            PEPROCESS OwningProcess,
            PETHREAD OwningThread,
            PIRP Irp
        );
        """
        Client, NodeName, ServiceName, NameSpace, Provider, Hints, Result, OwningProcess, OwningThread, Irp = argv
        rv = 0

        return rv

    @apihook("callback_WskFreeAddressInfo", argc=2)
    def WskFreeAddressInfo(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID WskFreeAddressInfo(
            PWSK_CLIENT Client,
            PADDRINFOEXW AddrInfo
        );
        """
        Client, AddrInfo = argv
        rv = 0

        return rv

    @apihook("callback_WskGetNameInfo", argc=9)
    def WskGetNameInfo(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskGetNameInfo(
            PWSK_CLIENT Client,
            PSOCKADDR SockAddr,
            ULONG SockAddrLength,
            PUNICODE_STRING NodeName,
            PUNICODE_STRING ServiceName,
            ULONG Flags,
            PEPROCESS OwningProcess,
            PETHREAD OwningThread,
            PIRP Irp
        );
        """
        Client, SockAddr, SockAddrLength, NodeName, ServiceName, Flags, OwningProcess, OwningThread, Irp = argv
        rv = 0

        return rv

    @apihook("callback_WskControlSocket", argc=10)
    def WskControlSocket(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskControlSocket(
            PWSK_SOCKET Socket,
            WSK_CONTROL_SOCKET_TYPE RequestType,
            ULONG ControlCode,
            ULONG Level,
            SIZE_T InputSize,
            PVOID InputBuffer,
            SIZE_T OutputSize,
            PVOID OutputBuffer,
            SIZE_T *OutputSizeReturned,
            PIRP Irp
        );
        """
        (
            Socket,
            RequestType,
            ControlCode,
            Level,
            InputSize,
            InputBuffer,
            OutputSize,
            OutputBuffer,
            OutputSizeReturned,
            Irp,
        ) = argv
        rv = 0

        return rv

    @apihook("callback_WskCloseSocket", argc=2)
    def WskCloseSocket(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskCloseSocket(
            PWSK_SOCKET Socket,
            PIRP Irp
        );
        """
        Socket, Irp = argv
        rv = 0

        return rv

    @apihook("callback_WskBind", argc=4)
    def WskBind(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskBind(
            PWSK_SOCKET Socket,
            PSOCKADDR LocalAddress,
            ULONG Flags,
            PIRP Irp
        );
        """
        Socket, LocalAddress, Flags, Irp = argv
        rv = 0

        sock_addr = self.mem_cast(winsock.sockaddr_in(emu.get_ptr_size()), LocalAddress)

        raddr = inet_ntoa(sock_addr.sin_addr.to_bytes(4, "little"))
        rport = ntohs(sock_addr.sin_port)

        ctx.args[1].display = f"{raddr}:{rport}"

        return rv

    @apihook("callback_WskSendTo", argc=7)
    def WskSendTo(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskSendTo(
            PWSK_SOCKET Socket,
            PWSK_BUF Buffer,
            ULONG Flags,
            PSOCKADDR RemoteAddress,
            ULONG ControlInfoLength,
            PCMSGHDR ControlInfo,
            PIRP Irp
        );
        """
        Socket, Buffer, Flags, RemoteAddress, ControlInfoLength, ControlInfo, Irp = argv
        rv = 0

        return rv

    @apihook("callback_WskReceiveFrom", argc=8)
    def WskReceiveFrom(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskReceiveFrom(
            PWSK_SOCKET Socket,
            PWSK_BUF Buffer,
            ULONG Flags,
            PSOCKADDR RemoteAddress,
            PULONG ControlLength,
            PCMSGHDR ControlInfo,
            PULONG ControlFlags,
            PIRP Irp
        );
        """
        Socket, Buffer, Flags, RemoteAddress, ControlLength, ControlInfo, ControlFlags, Irp = argv
        rv = 0

        return rv

    @apihook("callback_WskRelease", argc=2)
    def WskRelease(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskRelease(
            PWSK_SOCKET Socket,
            PWSK_DATA_INDICATION DataIndication
        );
        """
        Socket, DataIndication = argv
        rv = 0

        return rv

    @apihook("callback_WskGetLocalAddress", argc=3)
    def WskGetLocalAddress(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS WskGetLocalAddress(
            PWSK_SOCKET Socket,
            PSOCKADDR LocalAddress,
            PIRP Irp
        );
        """
        Socket, LocalAddress, Irp = argv
        rv = 0

        return rv

    @apihook("WskReleaseProviderNPI", argc=1)
    def WskReleaseProviderNPI(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID WskReleaseProviderNPI(
            PWSK_REGISTRATION WskRegistration
        );
        """
        (WskRegistration,) = argv

    @apihook("NsiEnumerateObjectsAllParametersEx", argc=0)
    def NsiEnumerateObjectsAllParametersEx(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        NTSTATUS NsiEnumerateObjectsAllParametersEx();

        The Nsi interface is undocumented. The handler takes no arguments and
        returns 0.
        """
        return

    @apihook("WskDeregister", argc=1)
    def WskDeregister(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID WskDeregister(
            PWSK_REGISTRATION WskRegistration
        );
        """
        (WskRegistration,) = argv
