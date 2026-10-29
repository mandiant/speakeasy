// A parent process for speakeasy's child process tests, on x86. main allocates from the
// process heap with LocalAlloc, starts c:\child.exe, and returns the CreateProcessA result.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

typedef struct {
    unsigned long cb;
    void *reserved[17];
} STARTUPINFOA;

typedef struct {
    void *process, *thread;
    unsigned long process_id, thread_id;
} PROCESS_INFORMATION;

__declspec(dllimport) void *__stdcall LocalAlloc(unsigned int, unsigned int);
__declspec(dllimport) int __stdcall CreateProcessA(const char *, char *, void *, void *, int, unsigned long, void *,
                                                   const char *, STARTUPINFOA *, PROCESS_INFORMATION *);

static STARTUPINFOA startup_info = {sizeof(STARTUPINFOA)};
static PROCESS_INFORMATION process_info;

int main(void) {
    LocalAlloc(0, 16);
    return CreateProcessA("c:\\child.exe", 0, 0, 0, 0, 0, 0, 0, &startup_info, &process_info);
}
