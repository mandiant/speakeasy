// CPU cases for speakeasy, on x64 and x86. main returns a bitmask with one bit
// per case that behaves as it does on Windows (0x7: all).
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

__declspec(dllimport) void __stdcall Sleep(unsigned long);
__declspec(dllimport) int __stdcall IsProcessorFeaturePresent(unsigned long);

#define PF_AVX_INSTRUCTIONS_AVAILABLE 39
#define PF_AVX2_INSTRUCTIONS_AVAILABLE 40

static unsigned long long read_tsc(void) {
    unsigned int low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return (unsigned long long)high << 32 | low;
}

static void cpuid(unsigned int leaf, unsigned int regs[4]) {
    __asm__ volatile("cpuid" : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3]) : "a"(leaf), "c"(0));
}

// the time stamp counter advances by at least 1 GHz times the time that Sleep waits
__declspec(noinline) static int sleep_advances_tsc(void) {
    unsigned long long before = read_tsc();
    Sleep(50);
    return read_tsc() - before >= 50000000;
}

// IsProcessorFeaturePresent agrees with CPUID leaf 1 ECX bit 28 for AVX
__declspec(noinline) static int avx_agrees_with_cpuid(void) {
    unsigned int regs[4];
    cpuid(1, regs);
    return IsProcessorFeaturePresent(PF_AVX_INSTRUCTIONS_AVAILABLE) == (int)(regs[2] >> 28 & 1);
}

// IsProcessorFeaturePresent agrees with CPUID leaf 7 EBX bit 5 for AVX2
__declspec(noinline) static int avx2_agrees_with_cpuid(void) {
    unsigned int regs[4];
    cpuid(7, regs);
    return IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE) == (int)(regs[1] >> 5 & 1);
}

int main(void) {
    return sleep_advances_tsc() | avx_agrees_with_cpuid() << 1 | avx2_agrees_with_cpuid() << 2;
}
