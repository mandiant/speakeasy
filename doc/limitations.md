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

## Environmental requirements

A sample may expect files, registry keys, network responses, loaded modules, or runtime structures that are not present in the active profile. These misses can look like anti-analysis behavior even when the issue is configuration drift.

Use config and CLI overrides to model the expected environment before concluding a sample is unsupported.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [Adding API handlers](api-handlers.md)
- [Help and troubleshooting](help.md)
