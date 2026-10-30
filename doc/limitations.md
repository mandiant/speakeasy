# Limitations

Speakeasy does not delegate API calls, object management, or I/O to a real Windows kernel. Those behaviors are modeled by the emulator, so unsupported paths or environment mismatches can stop execution early.

## Unimplemented APIs

Samples call APIs with assumptions about arguments, return values, side effects, and stack behavior. Speakeasy has hand-written handlers for a curated subset of the Windows API; everything else is handled in one of two ways.

### Documented APIs without a handler

If the import is declared in the bundled Win32 API signature database (generated from Microsoft's win32metadata, see [Adding API handlers](api-handlers.md)), Speakeasy emulates it from the declaration alone:

- the correct number of argument slots is consumed and, for stdcall on x86, cleaned up
- the call is traced with parameter names and decoded strings/booleans, e.g. `kernel32.MoveFileExW(lpExistingFileName: "C:\old.txt", lpNewFileName: "C:\new.txt", dwFlags: 0x1)`
- a type-appropriate success value is returned (`TRUE`, `S_OK`, a fresh handle, ...)

What the fallback does **not** do: it has no real side effects. `Out`-only pointer parameters are zero-filled for as many bytes as the prototype declares (the pointed-to scalar or struct, a buffer sized by a sibling count parameter, or just the terminator of an unsized string), so a sample that reads them back sees empty strings, NULL handles and zero counts rather than stale stack contents; but no genuine data is ever produced. Runs that were previously stopped by `Unsupported API` now continue; treat calls in the trace that have parameter names (`name: value`) as unimplemented stubs when interpreting a report.

### Unknown APIs

If neither a handler nor a signature exists (the C runtime, third-party DLLs, natives that neither win32metadata nor phnt declares), the current run stops and records an error.

Expected error pattern:

- `Unsupported API: <module_name>.<api_name>`

Why execution stops:

- for unknown APIs, argument count/calling convention cannot be trusted
- continuing may corrupt stack state and generate misleading report data

Queued runs (for example additional entry points) can still execute. `modules.functions_always_exist` forces these calls through as 4-argument stdcall stubs returning 1.

## Exceptions

Exceptions reach the sample's own handlers, with the limits listed in [Exception dispatch](exceptions.md).

## Threads

Threads do not run at the same time. Each thread is a run in the run queue, and a run executes until it ends, so a thread cannot block and wait for another thread. A wait on an event that is not set times out when its timeout is finite and no run is queued. Otherwise the wait returns as if the event is set. `WaitOnAddress` returns at once when the value at the address differs from the compare value. If the values are equal, a finite wait times out at once, and an INFINITE wait ends the run of the thread. `WakeByAddressSingle` and `WakeByAddressAll` do nothing, because no thread can be in a wait. A sample that polls a value that only a queued thread changes can loop until it reaches `max_api_count`.

## Environmental requirements

A sample may expect files, registry keys, network responses, loaded modules, or runtime structures that are not present in the active profile. These misses can look like anti-analysis behavior even when the issue is configuration drift.

Use config and CLI overrides to model the expected environment before concluding a sample is unsupported.

## Repeatable runs

Two runs of the same sample with the same config give the same random bytes, GUIDs and times to the sample. The `random_seed` and `start_time` options in the [configuration](configuration.md) set these values.

The `rdtsc` and `rdtscp` instructions are an exception. They read the time stamp counter of Unicorn, which counts host time at 1 GHz. Unicorn 2.1.4 has no hook for `rdtsc`, so Speakeasy cannot give a fixed value. `Sleep` and the wait APIs add the waited time to the counter, so the difference across a `Sleep` call is correct. A sample that uses `rdtsc` as a seed, or that measures how long its code takes, can take a different path in each run.

A wall-clock limit (`--timeout`, `--max-total-time`) stops a run at a point that depends on the speed of the host. See [CLI execution controls](cli-execution-controls.md#stopping-conditions).

The report fields `emulation_total_runtime` and `timestamp` are host times, so they are different in each report.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [Exception dispatch](exceptions.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [Adding API handlers](api-handlers.md)
- [Help and troubleshooting](help.md)
