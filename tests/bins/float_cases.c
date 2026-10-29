// Floating point cases for speakeasy's msvcrt handlers, on x64 and x86. main returns
// a bitmask with one bit per case that behaves as it does on Windows (x64 0x3FF,
// x86 0x7FF: all). A case also checks that the call leaves the stack pointer as it was.
//
// x86 passes a double on the stack and returns it in ST(0); x64 passes and returns it
// in XMM registers. MSVC calls _CIfmod for fmod on x86, with its operands on the x87
// stack; clang does not, so the _CIfmod cases call it from inline assembly.
//
// Built without a CRT or SDK; build_programs.sh in this directory builds it.

int _fltused;

__declspec(dllimport) double __cdecl pow(double, double);
__declspec(dllimport) double __cdecl floor(double);
__declspec(dllimport) double __cdecl ceil(double);
__declspec(dllimport) double __cdecl sin(double);
__declspec(dllimport) double __cdecl fmod(double, double);
#ifdef _WIN64
__declspec(dllimport) float __cdecl ceilf(float);
__declspec(dllimport) float __cdecl floorf(float);
#define READ_SP(sp) __asm__ volatile("movq %%rsp, %0" : "=r"(sp))
typedef unsigned long long ULONG_PTR;
#else
__declspec(dllimport) void __cdecl _CIfmod(void);
#define READ_SP(sp) __asm__ volatile("movl %%esp, %0" : "=r"(sp))
typedef unsigned long ULONG_PTR;
#endif

typedef double(__cdecl *unary)(double);
typedef double(__cdecl *binary)(double, double);

static volatile double inf = 1e300 * 1e300;

__declspec(noinline) static int unary_case(unary function, double x, double expected) {
    ULONG_PTR before, after;
    double result;
    READ_SP(before);
    result = function(x);
    READ_SP(after);
    return result == expected && before == after;
}

__declspec(noinline) static int binary_case(binary function, double x, double y, double expected) {
    ULONG_PTR before, after;
    double result;
    READ_SP(before);
    result = function(x, y);
    READ_SP(after);
    return result == expected && before == after;
}

#ifdef _WIN64
typedef float(__cdecl *unary_single)(float);

__declspec(noinline) static int unary_single_case(unary_single function, float x, float expected) {
    return function(x) == expected;
}
#else
// _CIfmod pops x and y from the x87 stack and pushes fmod(x, y), so the stack top is as before
__declspec(noinline) static int ci_fmod_case(double x, double y, double expected) {
    double result;
    unsigned short before, after;
    __asm__ volatile("fnstsw %1\n\t"
                     "fldl %3\n\t"
                     "fldl %4\n\t"
                     "call *%5\n\t"
                     "fstpl %0\n\t"
                     "fnstsw %2"
                     : "=m"(result), "=m"(before), "=m"(after)
                     : "m"(x), "m"(y), "r"(_CIfmod)
                     : "eax", "ecx", "edx", "memory");
    return result == expected && (before & 0x3800) == (after & 0x3800);
}
#endif

int main(void) {
    return binary_case(pow, 2.0, 10.0, 1024.0) | unary_case(floor, -2.5, -3.0) << 1 |
           unary_case(ceil, -2.5, -2.0) << 2 | unary_case(ceil, 2.25, 3.0) << 3 | unary_case(ceil, inf, inf) << 4 |
           unary_case(floor, -inf, -inf) << 5 | unary_case(sin, 0.0, 0.0) << 6 |
           binary_case(fmod, 5.5, 2.0, 1.5) << 7 |
#ifdef _WIN64
           unary_single_case(ceilf, 2.25f, 3.0f) << 8 | unary_single_case(floorf, -2.5f, -3.0f) << 9 |
#else
           ci_fmod_case(7.5, 2.0, 1.5) << 8 | ci_fmod_case(-7.5, 2.0, -1.5) << 9 | ci_fmod_case(7.5, -2.0, 1.5) << 10 |
#endif
           0;
}
