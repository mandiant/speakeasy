# Exception dispatch

With `exceptions.dispatch_handlers` enabled (the default), exceptions reach the
sample's own handlers the way they would on Windows, so code that relies on
exceptions for control flow or anti-analysis keeps running. Each exception that
is offered to a handler is reported as an `exception` event.

## What raises exceptions

- CPU faults: access violations, including reads of no-access pages and writes
  to read-only pages, and division by zero.
- Trap instructions, following Wine: `int3` and `int 3`, `int 2d` (or nothing,
  for the debug service codes 1, 3, 4 and 5), other `int n` as access
  violations, `ud2`, `icebp`, `hlt`, `in` and `out`, and the trap flag. The
  system service gates (`int 2e`, and `int 2a` and `int 2b` on x86) are not
  emulated and end the run as an unhandled interrupt.
- `PAGE_GUARD` pages, once, with `STATUS_GUARD_PAGE_VIOLATION`.
- Execute breakpoints in the debug registers of the current thread, set with
  `SetThreadContext` or by a handler that edits its context record.
- `RaiseException` and `RtlRaiseException`.
- An API handler that touches an invalid guest pointer: the access violation is
  raised in the API's caller, as the API's own code would fault.

## Who handles them

Vectored handlers run first, then frame-based handlers:

- x64 walks the stack with the unwind data of images (`.pdata`), or of tables
  registered with `RtlAddFunctionTable`, and calls language handlers such as
  `__C_specific_handler`. `RtlUnwind` and `RtlUnwindEx` run `__finally` blocks
  on the way to the target frame.
- x86 walks the chain of registrations at `fs:[0]`. The MSVC language handlers
  `_except_handler3` and `_except_handler4_common` run filters and `__finally`
  blocks; `RtlUnwind` unwinds registrations.

When no frame handles an exception, the filter of `SetUnhandledExceptionFilter`
runs, and may continue execution. Otherwise the run ends with the error of the
exception, as Windows would end the process, whether or not a handler saw it;
an unhandled access violation is `invalid_read`, `invalid_write` or
`invalid_fetch`. As an exception to that, `RaiseException` returns to its
caller when nothing takes a continuable exception, so that emulation goes on.

A fault that repeats at one address without progress ends the run after a few
attempts, rather than looping until the timeout.

## Where the code is

- `speakeasy/windows/guest_callbacks.py`: how a Python handler runs guest code,
  such as a filter, and gets its result, without nesting emulation.
- `speakeasy/windows/seh.py`: what both architectures share; `seh64.py` and
  `unwind.py` for x64, `seh32.py` for x86.
- `speakeasy/windows/cpu_exceptions.py`: the exception a CPU event becomes.
- `speakeasy/windows/thread_context.py` and `hardware_breakpoints.py`: thread
  contexts and debug registers.
- `speakeasy/winenv/api/exception_apis.py`: the exception and unwind APIs that
  kernel32 and ntdll share.

## Limitations

- Unicorn does not enforce privilege levels, so `cli`, `sti`, `mov cr0` and
  `rdmsr` run without raising an exception.
- Data breakpoints (a Dr7 R/W field other than execute) are not emulated.
- Callbacks registered with `RtlInstallFunctionTableCallback` are not called;
  code in their range unwinds as leaf functions.
- XMM6-XMM15 are not restored when continuing at a context.
- On x64, a fault in a function's epilogue unwinds as if it were in the body.
- Security cookies of SEH4 frames are not checked, and x86 registrations are
  not validated against the stack or SafeSEH.
- C++ exceptions are not emulated: `_CxxThrowException` returns, and the C++
  frame handlers do not run catch blocks.
- Continuing a non-continuable exception ends the run with
  `STATUS_NONCONTINUABLE_EXCEPTION`, where Windows would raise that as a new
  exception.
