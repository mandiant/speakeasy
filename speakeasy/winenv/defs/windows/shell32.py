import ctypes as ct

from speakeasy.struct import EmuStruct, Ptr

CSIDL_FLAG_MASK = 0xFF00

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
    0x0A: "CSIDL_BITBUCKET",
    0x0B: "CSIDL_STARTMENU",
    0x0D: "CSIDL_MYMUSIC",
    0x0E: "CSIDL_MYVIDEO",
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
    0x1A: "CSIDL_APPDATA",
    0x1B: "CSIDL_PRINTHOOD",
    0x1C: "CSIDL_LOCAL_APPDATA",
    0x1D: "CSIDL_ALTSTARTUP",
    0x1E: "CSIDL_COMMON_ALTSTARTUP",
    0x1F: "CSIDL_COMMON_FAVORITES",
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
    0x2A: "CSIDL_PROGRAM_FILESX86",
    0x2B: "CSIDL_PROGRAM_FILES_COMMON",
    0x2C: "CSIDL_PROGRAM_FILES_COMMONX86",
    0x2E: "CSIDL_COMMON_DOCUMENTS",
    0x2D: "CSIDL_COMMON_TEMPLATES",
    0x2F: "CSIDL_COMMON_ADMINTOOLS",
    0x30: "CSIDL_ADMINTOOLS",
    0x31: "CSIDL_CONNECTIONS",
    0x35: "CSIDL_COMMON_MUSIC",
    0x36: "CSIDL_COMMON_PICTURES",
    0x37: "CSIDL_COMMON_VIDEO",
    0x38: "CSIDL_RESOURCES",
    0x39: "CSIDL_RESOURCES_LOCALIZED",
    0x3B: "CSIDL_CDBURN_AREA",
    0x3D: "CSIDL_COMPUTERSNEARME",
    0x3F: "CSIDL_PLAYLISTS",
    0x40: "CSIDL_SAMPLE_MUSIC",
    0x41: "CSIDL_SAMPLE_PLAYLISTS",
    0x42: "CSIDL_SAMPLE_PICTURES",
    0x43: "CSIDL_SAMPLE_VIDEOS",
    0x45: "CSIDL_PHOTOALBUMS",
}

KNOWN_FOLDERS = {
    "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97": ("FOLDERID_ProgramData", "C:\\ProgramData"),
    "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": ("FOLDERID_RoamingAppData", "C:\\Users\\{user}\\AppData\\Roaming"),
    "F1B32785-6FBA-4FCF-9D55-7B8E7F157091": ("FOLDERID_LocalAppData", "C:\\Users\\{user}\\AppData\\Local"),
    "A520A1A4-1780-4FF6-BD18-167343C5AF16": ("FOLDERID_LocalAppDataLow", "C:\\Users\\{user}\\AppData\\LocalLow"),
    "5E6C858F-0E22-4760-9AFE-EA3317B67173": ("FOLDERID_Profile", "C:\\Users\\{user}"),
    "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": ("FOLDERID_Desktop", "C:\\Users\\{user}\\Desktop"),
    "FDD39AD0-238F-46AF-ADB4-6C85480369C7": ("FOLDERID_Documents", "C:\\Users\\{user}\\Documents"),
    "374DE290-123F-4565-9164-39C4925E467B": ("FOLDERID_Downloads", "C:\\Users\\{user}\\Downloads"),
    "B97D20BB-F46A-4C97-BA10-5E3608430854": (
        "FOLDERID_Startup",
        "C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    ),
    "82A5EA35-D9CD-47C5-9629-E15D2F714E6E": (
        "FOLDERID_CommonStartup",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    ),
    "905E63B6-C1BF-494E-B29C-65B732D3D21A": ("FOLDERID_ProgramFiles", "C:\\Program Files"),
    "F38BF404-1D43-42F2-9305-67DE0B28FC23": ("FOLDERID_Windows", "C:\\Windows"),
    "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": ("FOLDERID_System", "C:\\Windows\\System32"),
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
