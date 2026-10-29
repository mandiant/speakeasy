// Thread exit codes for speakeasy, on x86. main starts five threads that speakeasy runs
// after main, in order: they return 7, call ExitThread(5), call _endthreadex(6), call
// _endthread, and check the exit codes of the other four. The checking thread returns a
// bitmask with one bit per case that behaves as it does on Windows (0x1F: all).
//
// main polls the exit code of the first thread while it is STILL_ACTIVE, and returns 1
// when the poll ends. Speakeasy runs a queued thread only after main, so a queued thread
// gives 0, as a wait on it completes.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

typedef void *HANDLE;
typedef unsigned long(__stdcall *thread_function)(void *);

__declspec(dllimport) HANDLE __stdcall CreateThread(void *, unsigned long, thread_function, void *, unsigned long,
                                                    unsigned long *);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitThread(unsigned long);
__declspec(dllimport) int __stdcall GetExitCodeThread(HANDLE, unsigned long *);
__declspec(dllimport) unsigned long __cdecl _beginthread(void(__cdecl *)(void *), unsigned int, void *);
__declspec(dllimport) __declspec(noreturn) void __cdecl _endthread(void);
__declspec(dllimport) __declspec(noreturn) void __cdecl _endthreadex(unsigned int);

#define STILL_ACTIVE 259
#define CURRENT_THREAD ((HANDLE)-2)

static HANDLE returning, exiting, ending_ex, ending;

static unsigned long __stdcall return_7(void *parameter) {
    return 7;
}

static unsigned long __stdcall exit_thread_5(void *parameter) {
    ExitThread(5);
}

static unsigned long __stdcall endthreadex_6(void *parameter) {
    _endthreadex(6);
}

static void __cdecl endthread(void *parameter) {
    _endthread();
}

static int has_exit_code(HANDLE thread, unsigned long expected) {
    unsigned long code;
    return GetExitCodeThread(thread, &code) && code == expected;
}

static unsigned long __stdcall check_exit_codes(void *parameter) {
    return has_exit_code(returning, 7) | has_exit_code(exiting, 5) << 1 | has_exit_code(ending_ex, 6) << 2 |
           has_exit_code(ending, 0) << 3 | has_exit_code(CURRENT_THREAD, STILL_ACTIVE) << 4;
}

int main(void) {
    unsigned long code;
    returning = CreateThread(0, 0, return_7, 0, 0, 0);
    exiting = CreateThread(0, 0, exit_thread_5, 0, 0, 0);
    ending_ex = CreateThread(0, 0, endthreadex_6, 0, 0, 0);
    ending = (HANDLE)_beginthread(endthread, 0, 0);
    CreateThread(0, 0, check_exit_codes, 0, 0, 0);
    do {
        GetExitCodeThread(returning, &code);
    } while (code == STILL_ACTIVE);
    return code == 0;
}
