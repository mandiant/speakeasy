import ctypes as ct

from speakeasy.struct import EmuStruct, Ptr

CSIDL = {
    0x00: "CSIDL_DESKTOP",
    0x01: "CSIDL_INTERNET",
    0x02: "CSIDL_PROGRAMS",
    0x03: "CSIDL_CONTROLS",
    0x04: "CSIDL_PRINTERS",
    0x05: "CSIDL_MYDOCUMENTS",
    0x06: "CSIDL_FAVORITES",
    0x07: "CSIDL_STARTUP",
    0x08: "CSIDL_RECENT",
    0x09: "CSIDL_SENDTO",
    0x0a: "CSIDL_BITBUCKET",
    0x0b: "CSIDL_STARTMENU",
    0x0d: "CSIDL_MYMUSIC",
    0x0e: "CSIDL_MYVIDEO",
    0x10: "CSIDL_DESKTOPDIRECTORY",
    0x11: "CSIDL_DRIVES",
    0x12: "CSIDL_NETWORK",
    0x13: "CSIDL_NETHOOD",
    0x14: "CSIDL_FONTS",
    0x15: "CSIDL_TEMPLATES",
    0x16: "CSIDL_COMMON_STARTMENU",
    0x17: "CSIDL_COMMON_PROGRAMS",
    0x18: "CSIDL_COMMON_STARTUP",
    0x19: "CSIDL_COMMON_DESKTOPDIRECTORY",
    0x1a: "CSIDL_APPDATA",
    0x1b: "CSIDL_PRINTHOOD",
    0x1c: "CSIDL_LOCAL_APPDATA",
    0x1d: "CSIDL_ALTSTARTUP",
    0x1e: "CSIDL_COMMON_ALTSTARTUP",
    0x1f: "CSIDL_COMMON_FAVORITES",
    0x20: "CSIDL_INTERNET_CACHE",
    0x21: "CSIDL_COOKIES",
    0x22: "CSIDL_HISTORY",
    0x23: "CSIDL_COMMON_APPDATA",
    0x24: "CSIDL_WINDOWS",
    0x25: "CSIDL_SYSTEM",
    0x26: "CSIDL_PROGRAM_FILES",
    0x27: "CSIDL_MYPICTURES",
    0x28: "CSIDL_PROFILE",
    0x29: "CSIDL_SYSTEMX86",
    0x2a: "CSIDL_PROGRAM_FILESX86",
    0x2b: "CSIDL_PROGRAM_FILES_COMMON",
    0x2c: "CSIDL_PROGRAM_FILES_COMMONX86",
    0x2e: "CSIDL_COMMON_DOCUMENTS",
    0x2d: "CSIDL_COMMON_TEMPLATES",
    0x2f: "CSIDL_COMMON_ADMINTOOLS",
    0x30: "CSIDL_ADMINTOOLS",
    0x31: "CSIDL_CONNECTIONS",
    0x35: "CSIDL_COMMON_MUSIC",
    0x36: "CSIDL_COMMON_PICTURES",
    0x37: "CSIDL_COMMON_VIDEO",
    0x38: "CSIDL_RESOURCES",
    0x39: "CSIDL_RESOURCES_LOCALIZED",
    0x3b: "CSIDL_CDBURN_AREA",
    0x3d: "CSIDL_COMPUTERSNEARME",
    0x3f: "CSIDL_PLAYLISTS",
    0x40: "CSIDL_SAMPLE_MUSIC",
    0x41: "CSIDL_SAMPLE_PLAYLISTS",
    0x42: "CSIDL_SAMPLE_PICTURES",
    0x43: "CSIDL_SAMPLE_VIDEOS",
    0x45: "CSIDL_PHOTOALBUMS",
}

class SHELLEXECUTEINFOA(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.cbSize = ct.c_uint32
        self.fMask = ct.c_uint32
        self.hwnd = Ptr
        self.lpVerb = Ptr
        self.lpFile = Ptr
        self.lpParameters = Ptr
        self.lpDirectory = Ptr
        self.nShow = ct.c_int32
        self.hInstApp = Ptr
        self.lpIDList = Ptr
        self.lpClass = Ptr
        self.hkeyClass = Ptr
        self.dwHotKey = ct.c_uint32
        self.DummyUnionName = Ptr
        self.handle = Ptr