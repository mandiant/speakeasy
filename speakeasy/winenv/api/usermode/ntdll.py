# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from .. import api


class Ntdll(api.ApiHandler):

    """
    Implements exported native functions from ntdll.dll. If a function is not supported
    here, but is supported in the ntoskrnl handler (e.g. NtCreateFile) it will be handled by
    the kernel export handler.
    """

    name = 'ntdll'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Ntdll, self).__init__(emu)

        self.funcs = {}
        self.data = {}

        super(Ntdll, self).__get_hook_attrs__(self)

    def normalize_dll_name(self, name):
        ret = name
        if (name.lower().startswith('api-ms-win-crt') or name.lower().startswith('vcruntime')):
            ret = 'msvcrt'
        return ret

    @apihook('RtlGetLastWin32Error', argc=0)
    def RtlGetLastWin32Error(self, emu, argv, ctx={}):
        '''DWORD RtlGetLastWin32Error();'''

        return emu.get_last_error()

    @apihook('RtlAddVectoredExceptionHandler', argc=2)
    def RtlAddVectoredExceptionHandler(self, emu, argv, ctx={}):
        '''
        PVOID AddVectoredExceptionHandler(
            ULONG                       First,
            PVECTORED_EXCEPTION_HANDLER Handler
        );
        '''
        First, Handler = argv

        emu.add_vectored_exception_handler(First, Handler)

        return Handler

    @apihook('RtlRemoveVectoredExceptionHandler', argc=1)
    def RtlRemoveVectoredExceptionHandler(self, emu, argv, ctx={}):
        '''
        ULONG RemoveVectoredExceptionHandler(
            PVOID Handle
        );
        '''
        Handler, = argv

        emu.remove_vectored_exception_handler(Handler)

        return Handler

    @apihook('LdrLoadDll', argc=4)
    def LdrLoadDll(self, emu, argv, ctx={}):
        '''NTSTATUS
        NTAPI
        LdrLoadDll(
        IN PWSTR SearchPath OPTIONAL,
        IN PULONG LoadFlags OPTIONAL,
        IN PUNICODE_STRING Name,
        OUT PVOID *BaseAddress OPTIONAL
        );'''

        SearchPath, LoadFlags, Name, BaseAddress = argv

        hmod = 0

        req_lib = self.read_unicode_string(Name)
        lib = self.normalize_dll_name(req_lib)

        hmod = emu.load_library(lib)

        flags = {
            0x1: 'DONT_RESOLVE_DLL_REFERENCES',
            0x10: 'LOAD_IGNORE_CODE_AUTHZ_LEVEL',
            0x2: 'LOAD_LIBRARY_AS_DATAFILE',
            0x40: 'LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE',
            0x20: 'LOAD_LIBRARY_AS_IMAGE_RESOURCE',
            0x200: 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR',
            0x1000: 'LOAD_LIBRARY_SEARCH_DEFAULT_DIRS',
            0x100: 'LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR',
            0x800: 'LOAD_LIBRARY_SEARCH_SYSTEM32',
            0x400: 'LOAD_LIBRARY_SEARCH_USER_DIRS',
            0x8: 'LOAD_WITH_ALTERED_SEARCH_PATH',
        }

        pretty_flags = ' | '.join([name for bit, name in flags.items()
                                   if LoadFlags & bit])

        if SearchPath:
            argv[0] = self.read_mem_string(SearchPath, 2)

        argv[2] = req_lib
        argv[1] = pretty_flags

        if not hmod:
            STATUS_DLL_NOT_FOUND = 0xC0000135
            return STATUS_DLL_NOT_FOUND

        if BaseAddress:
            self.mem_write(BaseAddress, hmod.to_bytes(self.get_ptr_size(), 'little'))

        return 0
