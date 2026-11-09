import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr

CSIDL_FLAG_MASK = 0xFF00

SE_ERR_FNF = 2
SEE_MASK_NOCLOSEPROCESS = 0x40

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

CSIDL_PATHS = {
    0x00: "%USERPROFILE%\\Desktop",
    0x02: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    0x05: "%USERPROFILE%\\Documents",
    0x06: "%USERPROFILE%\\Favorites",
    0x07: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    0x08: "%APPDATA%\\Microsoft\\Windows\\Recent",
    0x09: "%APPDATA%\\Microsoft\\Windows\\SendTo",
    0x0B: "%APPDATA%\\Microsoft\\Windows\\Start Menu",
    0x10: "%USERPROFILE%\\Desktop",
    0x13: "%APPDATA%\\Microsoft\\Windows\\Network Shortcuts",
    0x14: "%windir%\\Fonts",
    0x15: "%APPDATA%\\Microsoft\\Windows\\Templates",
    0x1A: "%APPDATA%",
    0x1B: "%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts",
    0x1C: "%LOCALAPPDATA%",
    0x1D: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    0x1E: "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    0x1F: "%USERPROFILE%\\Favorites",
    0x20: "%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files",
    0x21: "%APPDATA%\\Microsoft\\Windows\\Cookies",
    0x22: "%LOCALAPPDATA%\\Microsoft\\Windows\\History",
    0x23: "%ALLUSERSPROFILE%",
    0x24: "%windir%",
    0x25: "%windir%\\System32",
    0x26: "%ProgramFiles%",
    0x27: "%USERPROFILE%\\Pictures",
    0x28: "%USERPROFILE%",
    0x2A: "%ProgramFiles%",
    0x2B: "%ProgramFiles%\\Common Files",
    0x2C: "%ProgramFiles%\\Common Files",
    0x2F: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    0x30: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
}

# A 64-bit OS keeps 32-bit programs apart from the native Program Files
CSIDL_PATHS_X64 = {
    0x2A: "%ProgramFiles(x86)%",
    0x2C: "%ProgramFiles(x86)%\\Common Files",
}

# The default paths of the KNOWNFOLDERID reference. Virtual folders have no path, so they are not here.
KNOWN_FOLDERS = {
    "008CA0B1-55B4-4C56-B8A8-4DE4B299D3BE": (
        "FOLDERID_AccountPictures",
        "%APPDATA%\\Microsoft\\Windows\\AccountPictures",
    ),
    "724EF170-A42D-4FEF-9F26-B60E846FBA4F": (
        "FOLDERID_AdminTools",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    ),
    "B2C5E279-7ADD-439F-B28C-C41FE1BBF672": ("FOLDERID_AppDataDesktop", "%LOCALAPPDATA%\\Desktop"),
    "7BE16610-1F7F-44AC-BFF0-83E15F2FFCA1": ("FOLDERID_AppDataDocuments", "%LOCALAPPDATA%\\Documents"),
    "7CFBEFBC-DE1F-45AA-B843-A542AC536CC9": ("FOLDERID_AppDataFavorites", "%LOCALAPPDATA%\\Favorites"),
    "559D40A3-A036-40FA-AF61-84CB430A4D34": ("FOLDERID_AppDataProgramData", "%LOCALAPPDATA%\\ProgramData"),
    "A3918781-E5F2-4890-B3D9-A7E54332328C": (
        "FOLDERID_ApplicationShortcuts",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\Application Shortcuts",
    ),
    "AB5FB87B-7CE2-4F83-915D-550846C9537B": ("FOLDERID_CameraRoll", "%USERPROFILE%\\Pictures\\Camera Roll"),
    "9E52AB10-F80D-49DF-ACB8-4330F5687855": ("FOLDERID_CDBurning", "%LOCALAPPDATA%\\Microsoft\\Windows\\Burn\\Burn"),
    "D0384E7D-BAC3-4797-8F14-CBA229B392B5": (
        "FOLDERID_CommonAdminTools",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    ),
    "C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D": ("FOLDERID_CommonOEMLinks", "%ALLUSERSPROFILE%\\OEM Links"),
    "0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8": (
        "FOLDERID_CommonPrograms",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs",
    ),
    "A4115719-D62E-491D-AA7C-E74B8BE3B067": (
        "FOLDERID_CommonStartMenu",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu",
    ),
    "82A5EA35-D9CD-47C5-9629-E15D2F714E6E": (
        "FOLDERID_CommonStartup",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    ),
    "B94237E7-57AC-4347-9151-B08C6C32D1F7": (
        "FOLDERID_CommonTemplates",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Templates",
    ),
    "56784854-C6CB-462B-8169-88E350ACB882": ("FOLDERID_Contacts", "%USERPROFILE%\\Contacts"),
    "2B0F765D-C0E9-4171-908E-08A611B84FF6": ("FOLDERID_Cookies", "%APPDATA%\\Microsoft\\Windows\\Cookies"),
    "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": ("FOLDERID_Desktop", "%USERPROFILE%\\Desktop"),
    "5CE4A5E9-E4EB-479D-B89F-130C02886155": (
        "FOLDERID_DeviceMetadataStore",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\DeviceMetadataStore",
    ),
    "FDD39AD0-238F-46AF-ADB4-6C85480369C7": ("FOLDERID_Documents", "%USERPROFILE%\\Documents"),
    "7B0DB17D-9CD2-4A93-9733-46CC89022E7C": (
        "FOLDERID_DocumentsLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\Documents.library-ms",
    ),
    "374DE290-123F-4565-9164-39C4925E467B": ("FOLDERID_Downloads", "%USERPROFILE%\\Downloads"),
    "1777F761-68AD-4D8A-87BD-30B759FA33DD": ("FOLDERID_Favorites", "%USERPROFILE%\\Favorites"),
    "FD228CB7-AE11-4AE3-864C-16F3910AB8FE": ("FOLDERID_Fonts", "%windir%\\Fonts"),
    "054FAE61-4DD8-4787-80B6-090220C4B700": ("FOLDERID_GameTasks", "%LOCALAPPDATA%\\Microsoft\\Windows\\GameExplorer"),
    "D9DC8A3B-B784-432E-A781-5A1130A75963": ("FOLDERID_History", "%LOCALAPPDATA%\\Microsoft\\Windows\\History"),
    "BCB5256F-79F6-4CEE-B725-DC34E402FD46": (
        "FOLDERID_ImplicitAppShortcuts",
        "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\ImplicitAppShortcuts",
    ),
    "352481E8-33BE-4251-BA85-6007CAEDCF9D": (
        "FOLDERID_InternetCache",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files",
    ),
    "1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE": ("FOLDERID_Libraries", "%APPDATA%\\Microsoft\\Windows\\Libraries"),
    "BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968": ("FOLDERID_Links", "%USERPROFILE%\\Links"),
    "F1B32785-6FBA-4FCF-9D55-7B8E7F157091": ("FOLDERID_LocalAppData", "%LOCALAPPDATA%"),
    "A520A1A4-1780-4FF6-BD18-167343C5AF16": ("FOLDERID_LocalAppDataLow", "%USERPROFILE%\\AppData\\LocalLow"),
    "2A00375E-224C-49DE-B8D1-440DF7EF3DDC": ("FOLDERID_LocalizedResourcesDir", "%windir%\\resources\\0409"),
    "4BD8D571-6D19-48D3-BE97-422220080E43": ("FOLDERID_Music", "%USERPROFILE%\\Music"),
    "2112AB0A-C86A-4FFE-A368-0DE96E47012E": (
        "FOLDERID_MusicLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\Music.library-ms",
    ),
    "C5ABBF53-E17F-4121-8900-86626FC2C973": ("FOLDERID_NetHood", "%APPDATA%\\Microsoft\\Windows\\Network Shortcuts"),
    "31C0DD25-9439-4F12-BF41-7FF4EDA38722": ("FOLDERID_Objects3D", "%USERPROFILE%\\3D Objects"),
    "2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39": (
        "FOLDERID_OriginalImages",
        "%LOCALAPPDATA%\\Microsoft\\Windows Photo Gallery\\Original Images",
    ),
    "69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C": ("FOLDERID_PhotoAlbums", "%USERPROFILE%\\Pictures\\Slide Shows"),
    "A990AE9F-A03B-4E80-94BC-9912D7504104": (
        "FOLDERID_PicturesLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\Pictures.library-ms",
    ),
    "33E28130-4E1E-4676-835A-98395C3BC3BB": ("FOLDERID_Pictures", "%USERPROFILE%\\Pictures"),
    "DE92C1C7-837F-4F69-A3BB-86E631204A23": ("FOLDERID_Playlists", "%USERPROFILE%\\Music\\Playlists"),
    "9274BD8D-CFD1-41C3-B35E-B13F55A758F4": ("FOLDERID_PrintHood", "%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts"),
    "5E6C858F-0E22-4760-9AFE-EA3317B67173": ("FOLDERID_Profile", "%USERPROFILE%"),
    "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97": ("FOLDERID_ProgramData", "%ALLUSERSPROFILE%"),
    "905E63B6-C1BF-494E-B29C-65B732D3D21A": ("FOLDERID_ProgramFiles", "%ProgramFiles%"),
    "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": ("FOLDERID_ProgramFilesX86", "%ProgramFiles%"),
    "F7F1ED05-9F6D-47A2-AAAE-29D317C6F066": ("FOLDERID_ProgramFilesCommon", "%ProgramFiles%\\Common Files"),
    "DE974D24-D9C6-4D3E-BF91-F4455120B917": ("FOLDERID_ProgramFilesCommonX86", "%ProgramFiles%\\Common Files"),
    "A77F5D77-2E2B-44C3-A6A2-ABA601054A51": (
        "FOLDERID_Programs",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    ),
    "DFDF76A2-C82A-4D63-906A-5644AC457385": ("FOLDERID_Public", "%PUBLIC%"),
    "C4AA340D-F20F-4863-AFEF-F87EF2E6BA25": ("FOLDERID_PublicDesktop", "%PUBLIC%\\Desktop"),
    "ED4824AF-DCE4-45A8-81E2-FC7965083634": ("FOLDERID_PublicDocuments", "%PUBLIC%\\Documents"),
    "3D644C9B-1FB8-4F30-9B45-F670235F79C0": ("FOLDERID_PublicDownloads", "%PUBLIC%\\Downloads"),
    "DEBF2536-E1A8-4C59-B6A2-414586476AEA": (
        "FOLDERID_PublicGameTasks",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\GameExplorer",
    ),
    "48DAF80B-E6CF-4F4E-B800-0E69D84EE384": (
        "FOLDERID_PublicLibraries",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Libraries",
    ),
    "3214FAB5-9757-4298-BB61-92A9DEAA44FF": ("FOLDERID_PublicMusic", "%PUBLIC%\\Music"),
    "B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5": ("FOLDERID_PublicPictures", "%PUBLIC%\\Pictures"),
    "E555AB60-153B-4D17-9F04-A5FE99FC15EC": (
        "FOLDERID_PublicRingtones",
        "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Ringtones",
    ),
    "0482AF6C-08F1-4C34-8C90-E17EC98B1E17": ("FOLDERID_PublicUserTiles", "%PUBLIC%\\AccountPictures"),
    "2400183A-6185-49FB-A2D8-4A392A602BA3": ("FOLDERID_PublicVideos", "%PUBLIC%\\Videos"),
    "52A4F021-7B75-48A9-9F6B-4B87A210BC8F": (
        "FOLDERID_QuickLaunch",
        "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch",
    ),
    "AE50C081-EBD2-438A-8655-8A092E34987A": ("FOLDERID_Recent", "%APPDATA%\\Microsoft\\Windows\\Recent"),
    "1A6FDBA2-F42D-4358-A798-B74D745926C5": ("FOLDERID_RecordedTVLibrary", "%PUBLIC%\\RecordedTV.library-ms"),
    "8AD10C31-2ADB-4296-A8F7-E4701232C972": ("FOLDERID_ResourceDir", "%windir%\\Resources"),
    "C870044B-F49E-4126-A9C3-B52A1FF411E8": ("FOLDERID_Ringtones", "%LOCALAPPDATA%\\Microsoft\\Windows\\Ringtones"),
    "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": ("FOLDERID_RoamingAppData", "%APPDATA%"),
    "AAA8D5A5-F1D6-4259-BAA8-78E7EF60835E": (
        "FOLDERID_RoamedTileImages",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\RoamedTileImages",
    ),
    "00BCFC5A-ED94-4E48-96A1-3F6217F21990": (
        "FOLDERID_RoamingTiles",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\RoamingTiles",
    ),
    "B250C668-F57D-4EE1-A63C-290EE7D1AA1F": ("FOLDERID_SampleMusic", "%PUBLIC%\\Music\\Sample Music"),
    "C4900540-2379-4C75-844B-64E6FAF8716B": ("FOLDERID_SamplePictures", "%PUBLIC%\\Pictures\\Sample Pictures"),
    "15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5": ("FOLDERID_SamplePlaylists", "%PUBLIC%\\Music\\Sample Playlists"),
    "859EAD94-2E85-48AD-A71A-0969CB56A6CD": ("FOLDERID_SampleVideos", "%PUBLIC%\\Videos\\Sample Videos"),
    "4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4": ("FOLDERID_SavedGames", "%USERPROFILE%\\Saved Games"),
    "3B193882-D3AD-4EAB-965A-69829D1FB59F": ("FOLDERID_SavedPictures", "%USERPROFILE%\\Pictures\\Saved Pictures"),
    "E25B5812-BE88-4BD9-94B0-29233477B6C3": (
        "FOLDERID_SavedPicturesLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\SavedPictures.library-ms",
    ),
    "7D1D3A04-DEBB-4115-95CF-2F29DA2920DA": ("FOLDERID_SavedSearches", "%USERPROFILE%\\Searches"),
    "B7BEDE81-DF94-4682-A7D8-57A52620B86F": ("FOLDERID_Screenshots", "%USERPROFILE%\\Pictures\\Screenshots"),
    "0D4C3DB6-03A3-462F-A0E6-08924C41B5D4": (
        "FOLDERID_SearchHistory",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\ConnectedSearch\\History",
    ),
    "7E636BFE-DFA9-4D5E-B456-D7B39851D8A9": (
        "FOLDERID_SearchTemplates",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\ConnectedSearch\\Templates",
    ),
    "8983036C-27C0-404B-8F08-102D10DCFD74": ("FOLDERID_SendTo", "%APPDATA%\\Microsoft\\Windows\\SendTo"),
    "7B396E54-9EC5-4300-BE0A-2482EBAE1A26": (
        "FOLDERID_SidebarDefaultParts",
        "%ProgramFiles%\\Windows Sidebar\\Gadgets",
    ),
    "A75D362E-50FC-4FB7-AC2C-A8BEAA314493": (
        "FOLDERID_SidebarParts",
        "%LOCALAPPDATA%\\Microsoft\\Windows Sidebar\\Gadgets",
    ),
    "A52BBA46-E9E1-435F-B3D9-28DAA648C0F6": ("FOLDERID_SkyDrive", "%USERPROFILE%\\OneDrive"),
    "767E6811-49CB-4273-87C2-20F355E1085B": (
        "FOLDERID_SkyDriveCameraRoll",
        "%USERPROFILE%\\OneDrive\\Pictures\\Camera Roll",
    ),
    "24D89E24-2F19-4534-9DDE-6A6671FBB8FE": ("FOLDERID_SkyDriveDocuments", "%USERPROFILE%\\OneDrive\\Documents"),
    "339719B5-8C47-4894-94C2-D8F77ADD44A6": ("FOLDERID_SkyDrivePictures", "%USERPROFILE%\\OneDrive\\Pictures"),
    "625B53C3-AB48-4EC1-BA1F-A1EF4146FC19": ("FOLDERID_StartMenu", "%APPDATA%\\Microsoft\\Windows\\Start Menu"),
    "B97D20BB-F46A-4C97-BA10-5E3608430854": (
        "FOLDERID_Startup",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    ),
    "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": ("FOLDERID_System", "%windir%\\System32"),
    "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27": ("FOLDERID_SystemX86", "%windir%\\System32"),
    "A63293E8-664E-48DB-A079-DF759E0509F7": ("FOLDERID_Templates", "%APPDATA%\\Microsoft\\Windows\\Templates"),
    "9E3995AB-1F9C-4F13-B827-48B24B6C7174": (
        "FOLDERID_UserPinned",
        "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
    ),
    "0762D272-C50A-4BB0-A382-697DCD729B80": ("FOLDERID_UserProfiles", "%SystemDrive%\\Users"),
    "5CD7AEE2-2219-4A67-B85D-6C9CE15660CB": ("FOLDERID_UserProgramFiles", "%LOCALAPPDATA%\\Programs"),
    "BCBD3057-CA5C-4622-B42D-BC56DB0AE516": ("FOLDERID_UserProgramFilesCommon", "%LOCALAPPDATA%\\Programs\\Common"),
    "18989B1D-99B5-455B-841C-AB7C74E4DDFC": ("FOLDERID_Videos", "%USERPROFILE%\\Videos"),
    "491E922F-5643-4AF4-A7EB-4E7A138D8174": (
        "FOLDERID_VideosLibrary",
        "%APPDATA%\\Microsoft\\Windows\\Libraries\\Videos.library-ms",
    ),
    "F38BF404-1D43-42F2-9305-67DE0B28FC23": ("FOLDERID_Windows", "%windir%"),
}

# Folders whose paths differ on a 64-bit OS, and the x64 folders that a 32-bit OS does not have
KNOWN_FOLDERS_X64 = {
    "6D809377-6AF0-444B-8957-A3773F02200E": ("FOLDERID_ProgramFilesX64", "%ProgramFiles%"),
    "6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D": ("FOLDERID_ProgramFilesCommonX64", "%ProgramFiles%\\Common Files"),
    "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": ("FOLDERID_ProgramFilesX86", "%ProgramFiles(x86)%"),
    "DE974D24-D9C6-4D3E-BF91-F4455120B917": ("FOLDERID_ProgramFilesCommonX86", "%ProgramFiles(x86)%\\Common Files"),
    "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27": ("FOLDERID_SystemX86", "%windir%\\SysWOW64"),
}


class SHELLEXECUTEINFOA(EmuStruct):
    cbSize: Annotated[int, ct.c_uint32]
    fMask: Annotated[int, ct.c_uint32]
    hwnd: Annotated[int, Ptr]
    lpVerb: Annotated[int, Ptr]
    lpFile: Annotated[int, Ptr]
    lpParameters: Annotated[int, Ptr]
    lpDirectory: Annotated[int, Ptr]
    nShow: Annotated[int, ct.c_int32]
    hInstApp: Annotated[int, Ptr]
    lpIDList: Annotated[int, Ptr]
    lpClass: Annotated[int, Ptr]
    hkeyClass: Annotated[int, Ptr]
    dwHotKey: Annotated[int, ct.c_uint32]
    DummyUnionName: Annotated[int, Ptr]
    handle: Annotated[int, Ptr]
