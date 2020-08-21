# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import uuid
import speakeasy.winenv.defs.nt.ddk as ddk

import speakeasy.winenv.defs.wfp.fwpmtypes as fwp

from .. import api

FWP_E_NOT_FOUND = 0x80320008
FWP_E_CALLOUT_NOT_FOUND = 0x80320001
FWP_E_FILTER_NOT_FOUND = 0x80320003
FWP_E_LAYER_NOT_FOUND = 0x80320004
FWP_E_SUBLAYER_NOT_FOUND = 0x80320007


class NetIoEmuError(Exception):
    pass


class Fwpkclnt(api.ApiHandler):
    """
    Fwpkclnt is the Windows driver that implements the Windows Filtering Platform.
    For example, packet filters can be writting using this framework.
    """

    name = 'fwpkclnt'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Fwpkclnt, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.handle = 4
        self.sessions = {}
        self.injections = {}
        self.sublayers = {}
        self.callouts = {}
        self.filters = {}

        self.emu = emu

        self.fwp = fwp

        super(Fwpkclnt, self).__get_hook_attrs__(self)

    def new_id(self):
        tmp = self.handle
        self.handle += 4
        return tmp

    def new_session(self):

        # stub
        ret = self.new_id()
        self.sessions.update({ret: 'sess'})

        return ret

    def new_injection(self):
        ret = self.new_id()
        # TODO
        self.injections.update({ret: 'inj'})
        return ret

    def new_filter(self, name, desc, key):
        ret = self.new_id()
        flt = {ret: {'name': name, 'desc': desc, 'key': key}}
        self.filters.update(flt)
        return ret

    @apihook('FwpmEngineOpen0', argc=5)
    def FwpmEngineOpen0(self, emu, argv, ctx={}):
        """
        DWORD FwpmEngineOpen0(
        const wchar_t             *serverName,
        UINT32                    authnService,
        SEC_WINNT_AUTH_IDENTITY_W *authIdentity,
        const FWPM_SESSION0       *session,
        HANDLE                    *engineHandle
        );
        """

        sname, asvc, authid, sess, eng = argv

        rv = ddk.STATUS_SUCCESS

        hnd = self.new_session()

        self.mem_write(eng, hnd.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('FwpsInjectionHandleCreate0', argc=3)
    def FwpsInjectionHandleCreate0(self, emu, argv, ctx={}):
        """
        NTSTATUS FwpsInjectionHandleCreate0(
        ADDRESS_FAMILY addressFamily,
        UINT32         flags,
        HANDLE         *injectionHandle
        );
        """
        family, flags, inj_handle = argv

        rv = ddk.STATUS_SUCCESS

        hnd = self.new_injection()

        self.mem_write(inj_handle,
                       hnd.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('FwpmSubLayerAdd0', argc=3)
    def FwpmSubLayerAdd0(self, emu, argv, ctx={}):
        """
        DWORD FwpmSubLayerAdd0(
        HANDLE               engineHandle,
        const FWPM_SUBLAYER0 *subLayer,
        PSECURITY_DESCRIPTOR sd
        );
        """
        engineHandle, subLayer, sd = argv

        name = ''
        desc = ''
        weight = 0

        rv = ddk.STATUS_SUCCESS

        _sl = self.fwp.FWPM_SUBLAYER0(emu.get_ptr_size())
        layer = self.mem_cast(_sl, subLayer)
        if layer.displayData.name:
            name = self.read_wide_string(layer.displayData.name)
        if layer.displayData.description:
            desc = self.read_wide_string(layer.displayData.description)

        subkey = self.get_bytes(layer.subLayerKey)
        if all(x == 0 for x in subkey):
            subkey = uuid.uuid4().bytes
        subkey = uuid.UUID(bytes_le=subkey)
        subkey = str(subkey)

        provkey = self.get_bytes(layer.providerKey)
        if all(x == 0 for x in provkey):
            provkey = uuid.uuid4().bytes
        provkey = uuid.UUID(bytes_le=provkey)
        provkey = str(provkey)

        layer = {subkey: {'name': name, 'desc': desc, 'weight': weight,
                          'subkey': subkey, 'provkey': provkey}}

        self.sublayers.update(layer)

        return rv

    @apihook('FwpsCalloutRegister1', argc=3)
    def FwpsCalloutRegister1(self, emu, argv, ctx={}):
        """
        NTSTATUS FwpsCalloutRegister1(
          void                *deviceObject,
          const FWPS_CALLOUT1 *callout,
          UINT32              *calloutId
        );
        """
        deviceObject, pCallout, calloutId = argv

        rv = ddk.STATUS_SUCCESS
        cid = self.new_id()

        _co = self.fwp.FWPS_CALLOUT1(emu.get_ptr_size())
        callout = self.mem_cast(_co, pCallout)
        classify_fn = callout.classifyFn
        notify_fn = callout.notifyFn
        delete_fn = callout.flowDeleteFn

        co_key = self.get_bytes(callout.calloutKey)
        if all(x == 0 for x in co_key):
            co_key = uuid.uuid4().bytes
        co_key = uuid.UUID(bytes_le=co_key)
        co_key = str(co_key)

        co = {cid: {'key': co_key, 'flags': callout.flags,
                    'classify_fn': classify_fn, 'notify_fn': notify_fn,
                    'delete_fn': delete_fn}}

        self.callouts.update(co)

        if calloutId:
            self.mem_write(calloutId, cid.to_bytes(4, 'little'))

        return rv

    @apihook('FwpmCalloutAdd0', argc=4)
    def FwpmCalloutAdd0(self, emu, argv, ctx={}):
        """
        DWORD FwpmCalloutAdd0(
          HANDLE               engineHandle,
          const FWPM_CALLOUT0  *callout,
          PSECURITY_DESCRIPTOR sd,
          UINT32               *id
        );
        """
        eng, pCallout, sd, pCid = argv

        name = ''
        desc = ''
        rv = ddk.STATUS_SUCCESS

        _co = self.fwp.FWPM_CALLOUT0(emu.get_ptr_size())
        callout = self.mem_cast(_co, pCallout)
        if callout.displayData.name:
            name = self.read_wide_string(callout.displayData.name)
        if callout.displayData.description:
            desc = self.read_wide_string(callout.displayData.description)

        co_key = self.get_bytes(callout.calloutKey)
        # was the guid set to 0?
        if all(x == 0 for x in co_key):
            co_key = uuid.uuid4().bytes
        co_key = uuid.UUID(bytes_le=co_key)
        co_key = str(co_key)

        cid = 0
        for k, v in self.callouts.items():
            if v['key'] == co_key:
                cid = k
                self.callouts[k].update({'name': name, 'desc': desc})

        if pCid:
            cid = self.mem_write(pCid, cid.to_bytes(4, 'little'))

        return rv

    @apihook('FwpmFilterAdd0', argc=4)
    def FwpmFilterAdd0(self, emu, argv, ctx={}):
        """
        DWORD FwpmFilterAdd0(
          HANDLE               engineHandle,
          const FWPM_FILTER0   *filter,
          PSECURITY_DESCRIPTOR sd,
          UINT64               *id
        );
        """
        eng, pFilter, sd, pId = argv

        self.mem_write(pId, b'\x41\x41')

        rv = ddk.STATUS_SUCCESS

        name = ''
        desc = ''

        _filt = self.fwp.FWPM_FILTER0(emu.get_ptr_size())
        filt = self.mem_cast(_filt, pFilter)
        if filt.displayData.name:
            name = self.read_wide_string(filt.displayData.name)
        if filt.displayData.description:
            desc = self.read_wide_string(filt.displayData.description)

        flt_key = self.get_bytes(filt.filterKey)

        # was the guid set to 0?
        if all(x == 0 for x in flt_key):
            flt_key = uuid.uuid4().bytes

        flt_key = uuid.UUID(bytes_le=flt_key)
        flt_key = str(flt_key)

        fid = self.new_filter(name, desc, flt_key)
        self.mem_write(pId, fid.to_bytes(8, 'little'))

        return rv

    @apihook('FwpmFilterDeleteById0', argc=2)
    def FwpmFilterDeleteById0(self, emu, argv, ctx={}):
        """
        DWORD FwpmFilterDeleteById0(
        HANDLE engineHandle,
        UINT64 id
        );
        """
        eng, fid = argv

        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('FwpmCalloutDeleteById0', argc=2)
    def FwpmCalloutDeleteById0(self, emu, argv, ctx={}):
        """
        DWORD FwpmCalloutDeleteById0(
        HANDLE engineHandle,
        UINT32 id
        );
        """
        eng, cid = argv
        rv = FWP_E_CALLOUT_NOT_FOUND

        co = self.callouts.get(cid)
        if co:
            rv = ddk.STATUS_SUCCESS
        return rv

    @apihook('FwpsCalloutUnregisterById0', argc=1)
    def FwpsCalloutUnregisterById0(self, emu, argv, ctx={}):
        """
        NTSTATUS FwpsCalloutUnregisterById0(
        const UINT32 calloutId
        );
        """
        cid, = argv
        rv = FWP_E_CALLOUT_NOT_FOUND

        co = self.callouts.get(cid)
        if co:
            rv = ddk.STATUS_SUCCESS
        return rv

    @apihook('FwpmSubLayerDeleteByKey0', argc=2)
    def FwpmSubLayerDeleteByKey0(self, emu, argv, ctx={}):
        """
        DWORD FwpmSubLayerDeleteByKey0(
        HANDLE     engineHandle,
        const GUID *key
        );
        """
        eng, key = argv

        rv = FWP_E_SUBLAYER_NOT_FOUND

        guid = self.mem_read(key, 16)
        guid = uuid.UUID(bytes_le=guid)

        if self.sublayers.get(guid):
            rv = ddk.STATUS_SUCCESS

        return rv

    @apihook('FwpmEngineClose0', argc=1)
    def FwpmEngineClose0(self, emu, argv, ctx={}):
        """
        DWORD FwpmEngineClose0(
        HANDLE engineHandle
        );
        """
        eng, = argv

        rv = ddk.STATUS_SUCCESS
        return rv

    @apihook('FwpsInjectionHandleDestroy0', argc=1)
    def FwpsInjectionHandleDestroy0(self, emu, argv, ctx={}):
        """
        NTSTATUS FwpsInjectionHandleDestroy0(
        HANDLE injectionHandle
        );
        """
        handle, = argv

        rv = ddk.STATUS_SUCCESS
        if not self.injections.get(handle):
            rv = FWP_E_NOT_FOUND

        return rv
