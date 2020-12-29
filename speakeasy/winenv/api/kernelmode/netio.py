# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from socket import inet_ntoa, ntohs

import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.winsock.ws2_32 as winsock

import speakeasy.winenv.defs.nt.ntoskrnl as nt
import speakeasy.winenv.defs.wsk as wsk

import speakeasy.windows.netman as netman
import speakeasy.windows.objman as objman
from speakeasy.errors import ApiEmuError

from .. import api

WSK_FLAG_BASIC_SOCKET = 0x00000000
WSK_FLAG_LISTEN_SOCKET = 0x00000001
WSK_FLAG_CONNECTION_SOCKET = 0x00000002
WSK_FLAG_DATAGRAM_SOCKET = 0x00000004


class WskSocket(objman.KernelObject):
    def __init__(self, api, family, stype, protocol, flags):

        self.emu = api.emu
        super(WskSocket, self).__init__(self.emu)
        self.family = family
        self.sock_type = stype
        self.protocol = protocol
        self.flags = flags
        self.dispatch = None
        self.dispatch_addr = 0
        self.dispatch_ptr = 0
        self.types = api.win

        # TODO: support other wsk socket types
        if flags == WSK_FLAG_DATAGRAM_SOCKET:
            self.dispatch = self.types.WSK_PROVIDER_DATAGRAM_DISPATCH(self.emu.get_ptr_size())
            self.dispatch_ptr = \
                self.emu.mem_map(size=self.sizeof(self.dispatch) +
                                 self.emu.get_ptr_size(),
                                 tag='api.struct.WSK_PROVIDER_DATAGRAM_DISPATCH') # noqa

            # We need a ptr to the dispatch table ptr
            self.dispatch_addr = self.dispatch_ptr + self.emu.get_ptr_size()
            self.emu.mem_write(self.dispatch_ptr, self.dispatch_addr.to_bytes(self.emu.get_ptr_size(), 'little')) # noqa

            addr = self.emu.add_callback(Netio.name, api.WskControlSocket.__apihook__[0]) # noqa
            self.dispatch.Basic.WskControlSocket = addr
            addr = self.emu.add_callback(Netio.name, api.WskCloseSocket.__apihook__[0]) # noqa
            self.dispatch.Basic.WskCloseSocket = addr
            addr = self.emu.add_callback(Netio.name, api.WskBind.__apihook__[0]) # noqa
            self.dispatch.WskBind = addr
            addr = self.emu.add_callback(Netio.name, api.WskSendTo.__apihook__[0]) # noqa
            self.dispatch.WskSendTo = addr
            addr = self.emu.add_callback(Netio.name, api.WskReceiveFrom.__apihook__[0]) # noqa
            self.dispatch.WskReceiveFrom = addr
            addr = self.emu.add_callback(Netio.name, api.WskRelease.__apihook__[0]) # noqa
            self.dispatch.WskRelease = addr
            addr = self.emu.add_callback(Netio.name, api.WskGetLocalAddress.__apihook__[0]) # noqa
            self.dispatch.WskGetLocalAddress = addr

            self.emu.mem_write(self.dispatch_addr, self.get_bytes(self.dispatch))

        else:
            raise ApiEmuError('Unsupported WSK socket type: 0x%x' % (flags))

    def get_dispatch_ptr(self):
        return self.dispatch_ptr


class Netio(api.ApiHandler):
    """
    Implements kernel networking functions implemented in netio.sys
    """

    name = 'netio'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Netio, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.win = None
        self.nt = None
        self.wsk_registrations = {}
        self.wsk_sockets = {}
        self.provider_npi = None

        self.win = wsk
        self.nt = nt

        self.netman = netman.NetworkManager(config=emu.get_network_config())

        super(Netio, self).__get_hook_attrs__(self)

        self.prov_disp = self.win.WSK_PROVIDER_DISPATCH(emu.get_ptr_size())
        self.prov_disp.Version = 0x100

        addr = emu.add_callback(Netio.name, self.WskSocket.__apihook__[0]) # noqa
        self.prov_disp.WskSocket = addr
        addr = emu.add_callback(Netio.name, self.WskSocketConnect.__apihook__[0]) # noqa
        self.prov_disp.WskSocketConnect = addr
        addr = emu.add_callback(Netio.name, self.WskControlClient.__apihook__[0]) # noqa
        self.prov_disp.WskControlClient = addr
        addr = emu.add_callback(Netio.name, self.WskGetAddressInfo.__apihook__[0]) # noqa
        self.prov_disp.WskGetAddressInfo = addr
        addr = emu.add_callback(Netio.name, self.WskFreeAddressInfo.__apihook__[0]) # noqa
        self.prov_disp.WskFreeAddressInfo = addr
        addr = emu.add_callback(Netio.name, self.WskGetNameInfo.__apihook__[0])
        self.prov_disp.WskGetNameInfo = addr

    @apihook('WskRegister', argc=2)
    def WskRegister(self, emu, argv, ctx={}):
        """NTSTATUS WskRegister(
          PWSK_CLIENT_NPI   WskClientNpi,
          PWSK_REGISTRATION WskRegistration
        );
        """
        WskClientNpi, WskRegistration = argv
        rv = 0

        self.wsk_registrations.update({WskRegistration: WskClientNpi})

        return rv

    @apihook('WskCaptureProviderNPI', argc=3)
    def WskCaptureProviderNPI(self, emu, argv, ctx={}):
        """NTSTATUS WskCaptureProviderNPI(
          PWSK_REGISTRATION WskRegistration,
          ULONG             WaitTimeout,
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
                wpd_addr = self.mem_alloc(size = self.sizeof(self.prov_disp), # noqa
                                          tag='api.struct.WSK_PROVIDER_DISPATCH')
                wpn.Dispatch = wpd_addr

                self.mem_write(wpd_addr, self.get_bytes(self.prov_disp))
                self.mem_write(WskProviderNpi, self.get_bytes(wpn))
                self.provider_npi = wpn

        return rv

    @apihook('callback_WskSocket', argc=11)
    def WskSocket(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskSocket(
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
        )"""
        cli, af, stype, proto, flags, sctx, disp, proc, thr, secdesc, pIrp = argv # noqa
        rv = ddk.STATUS_INVALID_PARAMETER

        if pIrp:
            irp = self.mem_cast(self.nt.IRP(emu.get_ptr_size()), pIrp)
            sock = WskSocket(self, af, stype, proto, flags)
            addr = sock.get_dispatch_ptr()
            irp.IoStatus.Information = addr
            self.write_back(pIrp, irp)

            rv = ddk.STATUS_SUCCESS
            self.wsk_sockets.update({addr: sock})

        return rv

    @apihook('callback_WskSocketConnect', argc=12)
    def WskSocketConnect(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskSocketConnect(
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
        )"""
        cli, stype, proto, laddr, raddr, flags, sctx, disp, proc, thr, secdesc, irp = argv # noqa

        rv = 0

        return rv

    @apihook('callback_WskControlClient', argc=8)
    def WskControlClient(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskControlClient(
          PWSK_CLIENT Client,
          ULONG ControlCode,
          SIZE_T InputSize,
          PVOID InputBuffer,
          SIZE_T OutputSize,
          PVOID OutputBuffer,
          SIZE_T *OutputSizeReturned,
          PIRP Irp
        )"""
        cli, ctl, insiz, inbuf, osiz, obuf, oret, irp = argv
        rv = 0

        return rv

    @apihook('callback_WskGetAddressInfo', argc=10)
    def WskGetAddressInfo(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskGetAddressInfo(
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
        )"""
        cli, node, svc, namespace, prov, hints, res, proc, thr, irp = argv
        rv = 0

        return rv

    @apihook('callback_WskFreeAddressInfo', argc=2)
    def WskFreeAddressInfo(self, emu, argv, ctx={}):
        """void PfnWskFreeAddressInfo(
          PWSK_CLIENT Client,
          PADDRINFOEXW AddrInfo
        )"""
        cli, addr = argv
        rv = 0

        return rv

    @apihook('callback_WskGetNameInfo', argc=9)
    def WskGetNameInfo(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskGetNameInfo(
          PWSK_CLIENT Client,
          PSOCKADDR SockAddr,
          ULONG SockAddrLength,
          PUNICODE_STRING NodeName,
          PUNICODE_STRING ServiceName,
          ULONG Flags,
          PEPROCESS OwningProcess,
          PETHREAD OwningThread,
          PIRP Irp
        )"""
        cli, saddr, saddrlen, node, svc, flags, proc, thr, irp = argv
        rv = 0

        return rv

    @apihook('callback_WskControlSocket', argc=10)
    def WskControlSocket(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskControlSocket(
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
        )"""
        sock, rtype, ctl, level, isize, ibuf, osize, obuf, oret, irp = argv
        rv = 0

        return rv

    @apihook('callback_WskCloseSocket', argc=2)
    def WskCloseSocket(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskCloseSocket(
          PWSK_SOCKET Socket,
          PIRP Irp
        )"""
        sock, irp = argv
        rv = 0

        return rv

    @apihook('callback_WskBind', argc=4)
    def WskBind(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskBind(
          PWSK_SOCKET Socket,
          PSOCKADDR LocalAddress,
          ULONG Flags,
          PIRP Irp
        )"""
        sock, laddr, flags, irp = argv
        rv = 0

        sock_addr = self.mem_cast(winsock.sockaddr_in(emu.get_ptr_size()), laddr)

        raddr = inet_ntoa(sock_addr.sin_addr.to_bytes(4, 'little'))
        rport = ntohs(sock_addr.sin_port)

        argv[1] = '%s:%d' % (raddr, rport)

        return rv

    @apihook('callback_WskSendTo', argc=7)
    def WskSendTo(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskSendTo(
          PWSK_SOCKET Socket,
          PWSK_BUF Buffer,
          ULONG Flags,
          PSOCKADDR RemoteAddress,
          ULONG ControlInfoLength,
          PCMSGHDR ControlInfo,
          PIRP Irp
        )"""
        sock, buf, flags, raddr, infolen, ctlinfo, irp = argv
        rv = 0

        return rv

    @apihook('callback_WskReceiveFrom', argc=8)
    def WskReceiveFrom(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskReceiveFrom(
          PWSK_SOCKET Socket,
          PWSK_BUF Buffer,
          ULONG Flags,
          PSOCKADDR RemoteAddress,
          PULONG ControlLength,
          PCMSGHDR ControlInfo,
          PULONG ControlFlags,
          PIRP Irp
        )"""
        sock, buf, flags, raddr, ctllen, ctlinfo, irp = argv
        rv = 0

        return rv

    @apihook('callback_WskRelease', argc=2)
    def WskRelease(self, emu, argv, ctx={}):
        """NTSTATUS WSKAPI WSKAPI * WskRelease(
          _In_ PWSK_SOCKET          Socket,
          _In_ PWSK_DATA_INDICATION DataIndication
        )"""
        sock, data_indic = argv
        rv = 0

        return rv

    @apihook('callback_WskGetLocalAddress', argc=2)
    def WskGetLocalAddress(self, emu, argv, ctx={}):
        """NTSTATUS PfnWskGetLocalAddress(
          PWSK_SOCKET Socket,
          PSOCKADDR LocalAddress,
          PIRP Irp
        )"""
        sock, laddr = argv
        rv = 0

        return rv

    @apihook('WskReleaseProviderNPI', argc=1)
    def WskReleaseProviderNPI(self, emu, argv, ctx={}):
        """
        void WskReleaseProviderNPI(
        PWSK_REGISTRATION WskRegistration
        );
        """
        reg, = argv

        return

    @apihook('NsiEnumerateObjectsAllParametersEx', argc=0)
    def NsiEnumerateObjectsAllParametersEx(self, emu, argv, ctx={}):
        """
        N/A
        """
        return

    @apihook('WskDeregister', argc=1)
    def WskDeregister(self, emu, argv, ctx={}):
        """
        void WskDeregister(
        PWSK_REGISTRATION WskRegistration
        );
        """
        reg, = argv

        return
