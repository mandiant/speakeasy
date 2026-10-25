from .. import api
from .dxgi import DXGI_ERROR_UNSUPPORTED


class D3d11(api.ApiHandler):
    """
    Emulates functions from d3d11.dll. The emulator has no Direct3D devices,
    so device creation reports that no adapter supports the request.
    """

    name = "d3d11"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    def clear_outputs(self, pointers, feature_level):
        for address in pointers:
            if address:
                self.mem_write(address, b"\x00" * self.get_ptr_size())
        if feature_level:
            self.mem_write(feature_level, b"\x00" * 4)

    @apihook("D3D11CreateDevice", argc=10)
    def D3D11CreateDevice(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT D3D11CreateDevice(
          IDXGIAdapter            *pAdapter,
          D3D_DRIVER_TYPE         DriverType,
          HMODULE                 Software,
          UINT                    Flags,
          const D3D_FEATURE_LEVEL *pFeatureLevels,
          UINT                    FeatureLevels,
          UINT                    SDKVersion,
          ID3D11Device            **ppDevice,
          D3D_FEATURE_LEVEL       *pFeatureLevel,
          ID3D11DeviceContext     **ppImmediateContext
        );
        """
        ppDevice, pFeatureLevel, ppImmediateContext = argv[7:]
        self.clear_outputs((ppDevice, ppImmediateContext), pFeatureLevel)
        return DXGI_ERROR_UNSUPPORTED

    @apihook("D3D11CreateDeviceAndSwapChain", argc=12)
    def D3D11CreateDeviceAndSwapChain(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT D3D11CreateDeviceAndSwapChain(
          IDXGIAdapter               *pAdapter,
          D3D_DRIVER_TYPE            DriverType,
          HMODULE                    Software,
          UINT                       Flags,
          const D3D_FEATURE_LEVEL    *pFeatureLevels,
          UINT                       FeatureLevels,
          UINT                       SDKVersion,
          const DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
          IDXGISwapChain             **ppSwapChain,
          ID3D11Device               **ppDevice,
          D3D_FEATURE_LEVEL          *pFeatureLevel,
          ID3D11DeviceContext        **ppImmediateContext
        );
        """
        ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext = argv[8:]
        self.clear_outputs((ppSwapChain, ppDevice, ppImmediateContext), pFeatureLevel)
        return DXGI_ERROR_UNSUPPORTED
