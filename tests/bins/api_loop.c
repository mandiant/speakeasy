// An API loop for speakeasy's run limit tests, on x86. main starts a thread that returns
// 42, then calls GetTickCount in an endless loop, so the thread is still queued.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

__declspec(dllimport) void *__stdcall CreateThread(void *, unsigned long, unsigned long(__stdcall *)(void *), void *,
                                                   unsigned long, unsigned long *);
__declspec(dllimport) unsigned long __stdcall GetTickCount(void);

static unsigned long __stdcall return_42(void *parameter) {
    return 42;
}

int main(void) {
    CreateThread(0, 0, return_42, 0, 0, 0);
    for (;;)
        GetTickCount();
}
