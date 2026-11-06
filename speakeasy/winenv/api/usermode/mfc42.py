from typing import TYPE_CHECKING

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.objman import Process
    from speakeasy.windows.win32 import Win32Emulator

# sizeof(AFX_MODULE_STATE) in the x86 MFC 4.2 DLL with the TCHAR type char (afxstat_.h)
AFX_MODULE_STATE_SIZE = 0x1090


class mfc42(api.ApiHandler):
    """
    Emulates functions from mfc42.dll
    """

    name = "mfc42"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.module_states: dict[Process, int] = {}
        super().__get_hook_attrs__(self)

    @apihook("?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ", argc=0, ordinal=1168)
    def AfxGetModuleState(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        AFX_MODULE_STATE* AfxGetModuleState();

        Each process has one state, which is zero except for m_hCurrentInstanceHandle and
        m_hCurrentResourceHandle. These two fields have the image base of the process.
        """
        proc = emu.get_current_process()
        state = self.module_states.get(proc)
        if state is None:
            state = self.mem_alloc(AFX_MODULE_STATE_SIZE, tag="api.struct.AFX_MODULE_STATE")
            # The vtable pointer of CNoTrackObject and m_pCurrentWinApp come before the two handles.
            ptr_size = emu.get_ptr_size()
            self.write_ptr(state + 2 * ptr_size, proc.base)
            self.write_ptr(state + 3 * ptr_size, proc.base)
            self.module_states[proc] = state
        return state
