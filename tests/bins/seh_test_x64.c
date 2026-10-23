// x64 SEH cases for speakeasy's exception dispatch. main returns a bitmask
// with one bit per case that behaves as it does on Windows (0x3F: all).
//
// Built without a CRT or SDK, against import libraries for the few imports:
//   printf 'LIBRARY KERNEL32.dll\nEXPORTS\nRaiseException\nAddVectoredExceptionHandler\n' > kernel32.def
//   printf 'LIBRARY VCRUNTIME140.dll\nEXPORTS\n__C_specific_handler\n' > vcruntime140.def
//   llvm-dlltool -m i386:x86-64 -d kernel32.def -l kernel32.lib
//   llvm-dlltool -m i386:x86-64 -d vcruntime140.def -l vcruntime140.lib
//   clang-cl --target=x86_64-pc-windows-msvc /O1 /GS- /c seh_test_x64.c
//   lld-link /nodefaultlib /entry:main /subsystem:console seh_test_x64.obj kernel32.lib vcruntime140.lib
typedef unsigned long DWORD;
typedef unsigned long long ULONG_PTR;

typedef struct {
    DWORD ExceptionCode;
} EXCEPTION_RECORD;

typedef struct {
    EXCEPTION_RECORD *ExceptionRecord;
    unsigned char *ContextRecord;
} EXCEPTION_POINTERS;

__declspec(dllimport) void __stdcall RaiseException(DWORD, DWORD, DWORD, const ULONG_PTR *);
__declspec(dllimport) void *__stdcall AddVectoredExceptionHandler(DWORD, long(__stdcall *)(EXCEPTION_POINTERS *));
unsigned long __cdecl _exception_code(void);

#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#define CONTEXT_RIP 0xF8

static volatile int trace;

// __except(1) around RaiseException
__declspec(noinline) static int raise_caught(void) {
    __try {
        RaiseException(0xE0000001, 0, 0, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }
    return 0;
}

__declspec(noinline) static int filter(DWORD code) {
    trace = trace * 10 + 2;
    return code == 0xE0000002 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) static void raise_through_finally(void) {
    __try {
        RaiseException(0xE0000002, 0, 0, 0);
    } __finally {
        trace = trace * 10 + 3;
    }
}

// a filter function in an outer frame; the inner __finally runs during the unwind
__declspec(noinline) static int filter_then_finally(void) {
    trace = 1;
    __try {
        raise_through_finally();
    } __except (filter(_exception_code())) {
        trace = trace * 10 + 4;
    }
    return trace == 1234;
}

__declspec(noinline) static void poke(volatile int *p) { *p = 1; }

// a CPU fault in a leaf function, which has no unwind data
__declspec(noinline) static int access_violation(volatile int *p) {
    __try {
        poke(p);
    } __except (_exception_code() == 0xC0000005) {
        return 1;
    }
    return 0;
}

// a filter that returns EXCEPTION_CONTINUE_EXECUTION
__declspec(noinline) static int continue_execution(void) {
    int resumed = 0;
    __try {
        RaiseException(0xE0000003, 0, 0, 0);
        resumed = 1;
    } __except (EXCEPTION_CONTINUE_EXECUTION) {
        return 0;
    }
    return resumed;
}

static long __stdcall skip_int3(EXCEPTION_POINTERS *info) {
    if (info->ExceptionRecord->ExceptionCode != 0x80000003)
        return EXCEPTION_CONTINUE_SEARCH;
    *(ULONG_PTR *)(info->ContextRecord + CONTEXT_RIP) += 1;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// a vectored handler that steps over int3
__declspec(noinline) static int vectored_int3(void) {
    AddVectoredExceptionHandler(1, skip_int3);
    __debugbreak();
    return 1;
}

// no handler in this frame: the exception propagates to the caller's
__declspec(noinline) static void raise_uncaught(void) { RaiseException(0xE0000005, 0, 0, 0); }

__declspec(noinline) static int caught_by_caller(void) {
    __try {
        raise_uncaught();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }
    return 0;
}

int main(void) {
    return raise_caught() | filter_then_finally() << 1 | access_violation(0) << 2 | continue_execution() << 3 |
           vectored_int3() << 4 | caught_by_caller() << 5;
}
