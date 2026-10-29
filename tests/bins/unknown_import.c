// A call to an import that no Windows DLL exports, on x86. Windows does not load the
// program; speakeasy runs it and stops at the call with an unsupported_api error.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

__declspec(dllimport) void __stdcall SpeakeasyNoSuchExport(void);

int main(void) {
    SpeakeasyNoSuchExport();
    return 0;
}
