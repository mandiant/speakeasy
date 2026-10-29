// The C++ frame of a seh_cases.c case: an object with a destructor and no catch block.
// On Windows, __CxxFrameHandler3 finds no catch block for a fault here and passes it on;
// it runs the destructor when the outer frame unwinds.

struct Guard {
    volatile int *destroyed;
    ~Guard() { *destroyed = 1; }
};

extern "C" __declspec(noinline) void fault_in_cxx_frame(volatile int *target, volatile int *destroyed) {
    Guard guard = {destroyed};
    *target = 1;
}
