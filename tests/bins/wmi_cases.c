// A WMI case for speakeasy, on x86. main connects to ROOT\CIMV2 with IWbemLocator and calls
// IWbemServices::PutInstance, a method that speakeasy has no handler for. On Windows,
// PutInstance of no instance fails with WBEM_E_INVALID_PARAMETER, and main returns 0.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

typedef long HRESULT;
typedef unsigned short *BSTR;

typedef struct {
    unsigned long data1;
    unsigned short data2, data3;
    unsigned char data4[8];
} GUID;

typedef struct IWbemServices {
    struct {
        // IUnknown, then OpenNamespace to CreateClassEnumAsync
        void *methods_before_put_instance[14];
        HRESULT(__stdcall *PutInstance)(struct IWbemServices *, void *, long, void *, void **);
    } *lpVtbl;
} IWbemServices;

typedef struct IWbemLocator {
    struct {
        void *QueryInterface, *AddRef, *Release;
        HRESULT(__stdcall *ConnectServer)(struct IWbemLocator *, BSTR, BSTR, BSTR, BSTR, long, BSTR, void *,
                                          IWbemServices **);
    } *lpVtbl;
} IWbemLocator;

__declspec(dllimport) HRESULT __stdcall CoInitializeEx(void *, unsigned long);
__declspec(dllimport) HRESULT __stdcall CoCreateInstance(const GUID *, void *, unsigned long, const GUID *, void **);

#define COINIT_MULTITHREADED 0
#define CLSCTX_INPROC_SERVER 1
#define WBEM_E_INVALID_PARAMETER ((HRESULT)0x80041008)

static const GUID CLSID_WbemLocator = {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
static const GUID IID_IWbemLocator = {0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

// a BSTR points past its byte length
static struct {
    unsigned long length;
    unsigned short text[11];
} root_cimv2 = {20, L"ROOT\\CIMV2"};

int main(void) {
    IWbemLocator *locator;
    IWbemServices *services;
    if (CoInitializeEx(0, COINIT_MULTITHREADED) < 0)
        return 1;
    if (CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&locator) < 0)
        return 2;
    if (locator->lpVtbl->ConnectServer(locator, root_cimv2.text, 0, 0, 0, 0, 0, 0, &services) < 0)
        return 3;
    return services->lpVtbl->PutInstance(services, 0, 0, 0, 0) == WBEM_E_INVALID_PARAMETER ? 0 : 4;
}
