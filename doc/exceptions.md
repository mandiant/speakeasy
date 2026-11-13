# Exception dispatch

When `exceptions.dispatch` is set (the default), the emulator sends
exceptions to the handlers of the sample as Windows does. So code that uses
exceptions for control flow or anti-analysis continues to run. The report has
an `exception` event for each exception that the emulator sends to a handler.

## What raises exceptions

- CPU faults. These are access violations, which include reads of no-access
  pages and writes to read-only pages, and division by zero.
- Trap instructions, as in Wine. These are `int3` and `int 3`, `int 2d`, other
  `int n` as access violations, `ud2`, `icebp`, `hlt`, `in`, `out` and the trap
  flag. `int 2d` raises nothing for the debug service codes 1, 3, 4 and
  5. The emulator does not emulate the system service gates (`int 2e`, and
  `int 2a` and `int 2b` on x86). They end the run as an unhandled interrupt.
- `PAGE_GUARD` pages, one time, with `STATUS_GUARD_PAGE_VIOLATION`.
- Execute breakpoints in the debug registers of the current thread. The sample
  sets them with `SetThreadContext`, or a handler sets them in its context
  record.
- `RaiseException` and `RtlRaiseException`.
- An API handler that accesses a guest pointer that is not valid. The emulator
  raises the access violation in the caller of the API, at the same point as
  the fault of the real API code.

## Who handles them

Vectored handlers run first, then frame-based handlers.

On x64, the emulator walks the stack with the unwind data (`.pdata`) of the
images, or of the tables that the sample adds with `RtlAddFunctionTable`. It
calls language handlers such as `__C_specific_handler`. `RtlUnwind` and
`RtlUnwindEx` run the `__finally` blocks between the current frame and the
target frame.

On x86, the emulator walks the chain of registrations at `fs:[0]`. The MSVC
language handlers `_except_handler3` and `_except_handler4_common` run filters
and `__finally` blocks, and `RtlUnwind` unwinds registrations. While these
handlers run a `__finally` block for an unwind, the newest registration at
`fs:[0]` has the handler `msvcrt._unwind_handler`, as with `_local_unwind2` of
the CRT. In this block, `_abnormal_termination` returns 1.

When no handler takes an exception, the emulator calls the filter that the
sample set with `SetUnhandledExceptionFilter`. The filter can continue
execution. If it does not, or if the sample set no filter, the run ends with the
error of the exception, as Windows ends the process. An unhandled access violation gives the error
`invalid_read`, `invalid_write` or `invalid_fetch`. `RaiseException` is
different: when no handler takes a continuable exception, it returns to its
caller, so emulation continues.

If a fault occurs again and again at one address and the code does not move
forward, the emulator ends the run after a small number of attempts. It does
not loop until the time limit.

## Where the code is

- `speakeasy/windows/guest_callbacks.py` lets a Python handler run guest code,
  such as a filter, and get its result, without nested emulation.
- `speakeasy/windows/seh.py` has the code for both architectures. `seh64.py`
  and `unwind.py` are for x64, and `seh32.py` is for x86.
- `speakeasy/windows/cpu_exceptions.py` converts a CPU event to an exception.
- `speakeasy/windows/thread_context.py` and `hardware_breakpoints.py` have the
  thread contexts and the debug registers.
- `speakeasy/winenv/api/exception_apis.py` has the exception and unwind APIs
  that kernel32 and ntdll share.

## Limitations

- Unicorn does not apply privilege levels, so `cli`, `sti`, `mov cr0` and
  `rdmsr` do not raise an exception.
- Data breakpoints (a Dr7 R/W field other than execute) have no effect.
- The emulator does not call the callbacks that the sample adds with
  `RtlInstallFunctionTableCallback`. Code in their range unwinds as leaf
  functions.
- When execution continues at a context, the emulator does not restore
  XMM6-XMM15.
- On x64, a fault in the epilogue of a function unwinds as a fault in the body.
- The emulator does not check the security cookies of SEH4 frames, or check
  x86 registrations against the stack or SafeSEH.
- The emulator does not support C++ exceptions. `_CxxThrowException` returns, and the C++
  frame handlers do not run catch blocks.
- If a handler continues a non-continuable exception, the run ends with
  `STATUS_NONCONTINUABLE_EXCEPTION`. Windows raises a new exception in this
  case.
