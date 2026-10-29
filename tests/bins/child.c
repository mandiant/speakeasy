// A child process for speakeasy's child process tests, on x86. main returns the DllBase
// of the first entry in the load order list of the PEB loader data, which is the base of
// the process image. build_programs.sh builds it at two image bases.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

typedef struct {
    void *flink, *blink;
} LIST_ENTRY;

typedef struct {
    LIST_ENTRY in_load_order_links, in_memory_order_links, in_initialization_order_links;
    void *dll_base;
} LDR_DATA_TABLE_ENTRY;

typedef struct {
    unsigned long length;
    unsigned char initialized;
    void *ss_handle;
    LIST_ENTRY in_load_order_module_list;
} PEB_LDR_DATA;

typedef struct {
    unsigned char reserved[12];
    PEB_LDR_DATA *ldr;
} PEB;

int main(void) {
    PEB *peb;
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
    return (int)((LDR_DATA_TABLE_ENTRY *)peb->ldr->in_load_order_module_list.flink)->dll_base;
}
