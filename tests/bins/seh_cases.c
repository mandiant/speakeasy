// SEH cases for speakeasy's exception dispatch, on x64 and x86. main returns
// a bitmask with one bit per case that behaves as it does on Windows (0xFF: all).
// x64 uses __C_specific_handler, x86 the _except_handler3 of msvcrt.
//
// Built without a CRT or SDK, against import libraries for the few imports;
// build_seh_cases.sh in this directory builds both.

typedef unsigned long DWORD;
#ifdef _WIN64
typedef unsigned long long ULONG_PTR;
#else
typedef unsigned long ULONG_PTR;
#endif

typedef struct {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    void *ExceptionRecord;
    void *ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
} EXCEPTION_RECORD;

typedef struct {
    EXCEPTION_RECORD *ExceptionRecord;
    unsigned char *ContextRecord;
} EXCEPTION_POINTERS;

__declspec(dllimport) void __stdcall RaiseException(DWORD, DWORD, DWORD, const ULONG_PTR *);
__declspec(dllimport) void *__stdcall AddVectoredExceptionHandler(DWORD, long(__stdcall *)(EXCEPTION_POINTERS *));
__declspec(dllimport) void __stdcall RtlMoveMemory(void *, const void *, ULONG_PTR);
__declspec(dllimport) int __stdcall SetThreadContext(void *, const void *);
unsigned long __cdecl _exception_code(void);
void *__cdecl _exception_info(void);

#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_CONTINUE_EXECUTION (-1)
// Offsets in CONTEXT of the instruction pointer (IP), stack pointer (SP) and return value (AX)
#ifdef _WIN64
#define CONTEXT_SIZE 0x4D0
#define CONTEXT_FLAGS 0x30
#define CONTEXT_EFLAGS 0x44
#define CONTEXT_DR0 0x48
#define CONTEXT_DR6 0x68
#define CONTEXT_DR7 0x70
#define CONTEXT_AX 0x78
#define CONTEXT_SP 0x98
#define CONTEXT_IP 0xF8
#define CONTEXT_DEBUG_REGISTERS 0x100010
#else
#define CONTEXT_SIZE 0x2CC
#define CONTEXT_FLAGS 0x00
#define CONTEXT_DR0 0x04
#define CONTEXT_DR6 0x14
#define CONTEXT_DR7 0x18
#define CONTEXT_AX 0xB0
#define CONTEXT_IP 0xB8
#define CONTEXT_EFLAGS 0xC0
#define CONTEXT_SP 0xC4
#define CONTEXT_DEBUG_REGISTERS 0x10010
#endif
#define RESUME_FLAG 0x10000
#define FIELD(context, offset) (*(ULONG_PTR *)((unsigned char *)(context) + (offset)))

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
    FIELD(info->ContextRecord, CONTEXT_IP) += 1;
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

__declspec(noinline) static int is_bad_read(EXCEPTION_POINTERS *info, ULONG_PTR address) {
    EXCEPTION_RECORD *record = info->ExceptionRecord;
    return record->ExceptionCode == 0xC0000005 && record->ExceptionInformation[0] == 0 &&
           record->ExceptionInformation[1] == address;
}

// an API that reads a bad pointer faults in its caller
__declspec(noinline) static int fault_in_api(void) {
    char buffer[4];
    __try {
        RtlMoveMemory(buffer, (void *)0x10, sizeof(buffer));
    } __except (is_bad_read(_exception_info(), 0x10)) {
        return 1;
    }
    return 0;
}

__declspec(noinline) static int breakpoint_target(void) { return 1; }

static volatile int breakpoint_hits, resume_at_breakpoint;

static long __stdcall on_breakpoint(EXCEPTION_POINTERS *info) {
    unsigned char *context = info->ContextRecord;
    if (info->ExceptionRecord->ExceptionCode != 0x80000004 ||
        FIELD(context, CONTEXT_IP) != (ULONG_PTR)breakpoint_target || !(FIELD(context, CONTEXT_DR6) & 1))
        return EXCEPTION_CONTINUE_SEARCH;
    breakpoint_hits++;
    if (resume_at_breakpoint) {
        // run the instruction at the breakpoint once without breaking again
        *(DWORD *)(context + CONTEXT_EFLAGS) |= RESUME_FLAG;
    } else {
        // return 42 from the target instead of running it
        FIELD(context, CONTEXT_AX) = 42;
        FIELD(context, CONTEXT_IP) = *(ULONG_PTR *)FIELD(context, CONTEXT_SP);
        FIELD(context, CONTEXT_SP) += sizeof(ULONG_PTR);
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

static __declspec(align(16)) unsigned char debug_context[CONTEXT_SIZE];

// a hardware execute breakpoint set with SetThreadContext, caught by a vectored handler
__declspec(noinline) static int hardware_breakpoint(void) {
    int (*volatile target)(void) = breakpoint_target;
    AddVectoredExceptionHandler(1, on_breakpoint);
    *(DWORD *)(debug_context + CONTEXT_FLAGS) = CONTEXT_DEBUG_REGISTERS;
    FIELD(debug_context, CONTEXT_DR0) = (ULONG_PTR)breakpoint_target;
    FIELD(debug_context, CONTEXT_DR7) = 1;  // local enable, break on execution
    SetThreadContext((void *)-2, debug_context);
    int hooked = target() == 42;
    resume_at_breakpoint = 1;
    int resumed = target() == 1;
    FIELD(debug_context, CONTEXT_DR7) = 0;
    SetThreadContext((void *)-2, debug_context);
    int cleared = target() == 1;
    return hooked && resumed && cleared && breakpoint_hits == 2;
}

int main(void) {
    return raise_caught() | filter_then_finally() << 1 | access_violation(0) << 2 | continue_execution() << 3 |
           vectored_int3() << 4 | caught_by_caller() << 5 | fault_in_api() << 6 | hardware_breakpoint() << 7;
}
