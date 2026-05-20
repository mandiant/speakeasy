#include <windows.h>

#ifndef ExceptionContinueExecution
#define ExceptionContinueExecution 0
#endif

#define SPEAKEASY_RESERVED_DIVISOR 0xFEEE0000

typedef DWORD (WINAPI *fn_void_to_dword)(void);

typedef struct seh_record {
    struct seh_record *next;
    void *handler;
} seh_record;

static fn_void_to_dword resolved_get_tick_count;

static fn_void_to_dword manual_resolve(HMODULE base, const char *name) {
    BYTE *b = (BYTE *)base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)b;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(
        b + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD *)(b + exp->AddressOfNames);
    WORD *ords = (WORD *)(b + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(b + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *sym = (const char *)(b + names[i]);
        const char *a = sym;
        const char *c = name;
        while (*a && *c && *a == *c) {
            a++;
            c++;
        }
        if (*a == 0 && *c == 0) {
            return (fn_void_to_dword)(b + funcs[ords[i]]);
        }
    }
    return 0;
}

static EXCEPTION_DISPOSITION __cdecl seh_handler(
    EXCEPTION_RECORD *record,
    void *frame,
    CONTEXT *context,
    void *dispatcher
) {
    volatile DWORD tick = 0;
    volatile DWORD pid;
    seh_record *seh = (seh_record *)frame;

    (void)record;
    (void)context;
    (void)dispatcher;

    __asm__ __volatile__(
        "movl %0, %%fs:0\n\t"
        :
        : "r"(seh->next)
        : "memory"
    );

    if (resolved_get_tick_count) {
        tick = resolved_get_tick_count();
    }
    pid = GetCurrentProcessId();
    ExitProcess((UINT)(tick ^ pid));
    return ExceptionContinueExecution;
}

void __cdecl mainCRTStartup(void) {
    seh_record seh;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    resolved_get_tick_count = manual_resolve(k32, "GetTickCount");

    __asm__ __volatile__(
        "movl %%fs:0, %%eax\n\t"
        "movl %%eax, (%0)\n\t"
        "movl %1, 4(%0)\n\t"
        "movl %0, %%fs:0\n\t"
        :
        : "r"(&seh), "r"(seh_handler)
        : "eax", "memory"
    );

    __asm__ __volatile__(
        "xorl %%edx, %%edx\n\t"
        "movl $1, %%eax\n\t"
        "divl (%%ecx)\n\t"
        :
        : "c"(SPEAKEASY_RESERVED_DIVISOR)
        : "eax", "edx", "memory"
    );

    ExitProcess(1);
}
