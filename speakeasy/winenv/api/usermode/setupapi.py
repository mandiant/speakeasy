import speakeasy.winenv.defs.windows.windows as windefs

from .. import api


class SetupApi(api.ApiHandler):
    """
    Emulates functions from setupapi.dll
    """

    name = "setupapi"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("SetupDiEnumDeviceInfo", argc=3)
    def SetupDiEnumDeviceInfo(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetupDiEnumDeviceInfo(
          HDEVINFO         DeviceInfoSet,
          DWORD            MemberIndex,
          PSP_DEVINFO_DATA DeviceInfoData
        );
        """
        emu.set_last_error(windefs.ERROR_NO_MORE_ITEMS)
        return False

    @apihook("SetupDiEnumDeviceInterfaces", argc=5)
    def SetupDiEnumDeviceInterfaces(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetupDiEnumDeviceInterfaces(
          HDEVINFO                  DeviceInfoSet,
          PSP_DEVINFO_DATA          DeviceInfoData,
          const GUID                *InterfaceClassGuid,
          DWORD                     MemberIndex,
          PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData
        );
        """
        emu.set_last_error(windefs.ERROR_NO_MORE_ITEMS)
        return False
