# Limitations

Speakeasy does not send API calls, object operations or I/O to a real Windows kernel. The emulator models them, so an API without a model or a difference in the environment can stop execution early. Exceptions reach the handlers of the sample, with the limits in [Exception dispatch](exceptions.md).

## Unimplemented APIs

A sample expects a specific argument layout, return value, side effects and stack cleanup from each API that it calls. Speakeasy has handlers for a part of the Windows API. For the other APIs, Speakeasy uses one of the two methods below.

### Documented APIs without a handler

If the bundled signature database declares the import (see [Adding API handlers](api-handlers.md)), Speakeasy emulates the call from the declaration:

- It reads the correct number of argument slots and, for stdcall on x86, removes them from the stack.
- It logs the call with parameter names and decoded strings and booleans, for example `kernel32.MoveFileExW(lpExistingFileName: "C:\old.txt", lpNewFileName: "C:\new.txt", dwFlags: 0x1)`.
- It returns a success value for the return type (`TRUE`, `S_OK`, a new handle, ...).

The call has no real side effects. Speakeasy writes zeros to each `Out`-only pointer parameter, for the size that the prototype declares: the scalar or struct that the pointer points to, or a buffer with the size of a related count parameter. A string buffer gets only a terminator, and so does a byte or WCHAR buffer, because the prototype does not show the difference. The emulator writes at most 4 KiB for each parameter, and it stops at the first page that the guest cannot write, because a junk call can give a count that is not correct. So a sample that reads these parameters gets empty strings, NULL handles and zero counts, and not old stack data. But it never gets real data. The run continues after the call. The report does not mark these calls, and handler calls also have parameter names. To find them, use `--verbose`: the log has a `no handler for <module>.<name>` line for each of these calls.

### Unknown APIs

An API can have no handler and no signature. Examples are a C runtime function without a handler, a function of a third-party DLL or a native function that neither win32metadata nor phnt declares. By default, `modules.functions_always_exist` is on, and Speakeasy emulates a call to such an API as a stdcall function with 4 arguments that returns 1. The emulator does not know the argument count or the calling convention of an unknown API, so on x86 the stack is wrong when the real argument count is different, and the report can have incorrect data.

With `--no-modules-functions-always-exist`, a call to such an API stops the current run with an error. A call to an API with a signature that the emulator cannot call, for example a variadic function, always stops the run. The log shows:

- `Unsupported API: <module_name>.<api_name>`

The runs in the queue, for example other entry points, still run.

## Threads

Threads do not run at the same time. Each thread is a run in the run queue, and a run executes until it ends, so a thread cannot block and wait for another thread. A wait on an event that is not set times out when its timeout is finite and no run is queued. Otherwise the wait returns as if the event is set. `WaitOnAddress` returns at once when the value at the address differs from the compare value. If the values are equal, a finite wait times out at once, and an INFINITE wait ends the run of the thread. `WakeByAddressSingle` and `WakeByAddressAll` do nothing, because no thread can be in a wait. A sample that polls a value that only a queued thread changes loops until `max_api_loop_calls` or `max_api_calls` ends the run. A message that `PostMessage` or `PostThreadMessage` sends to another thread stays in the queue of that thread until that thread runs. `GetMessage` does not wait for a message. When no message is pending, it returns 0, so the message loop ends.

## Processes

All processes share one emulated address space. `VirtualAlloc` and `VirtualAllocEx` with an address fail with `ERROR_INVALID_ADDRESS` when the range is in use, as on Windows, but `VirtualAllocEx` into another process gives the next free range when the memory in the range is not memory of that process. A process hollowing sample often asks for the image base of the payload in the target, and its own image is often at the same base, for example 0x400000. On Windows the target has that range free. In Speakeasy the payload goes to a different address, so the sample can write it and resume the target, and the report has these events. But a payload without relocations then fails when it runs.

When a sample creates a child process with `CREATE_SUSPENDED`, `ResumeThread` starts a run for the main thread of the child only if the sample changed the child first, for example with `WriteProcessMemory` or `SetThreadContext`. The run starts at the address in the thread context. Speakeasy does not have the code of a program that is not in the emulated file system, such as `cmd.exe`, so the context gives the headers of its image. `ResumeThread` starts no run at these headers unless the sample wrote code over them. A child that has an image in the emulated file system gets its start address when child emulation loads the image, so `ResumeThread` starts no run for it unless the sample set a start address in the context. Code that the sample starts in the child with other APIs, for example `CreateRemoteThread`, runs as usual.

## Strings

The ANSI code page is 1252 and the OEM code page is 437. Speakeasy reads and writes `A` strings in code page 1252, so each byte is one character. A character that is not in code page 1252 becomes `?`. For some of these characters Windows uses a best-fit mapping (`ā` to `a`), but Speakeasy does not. `GetCPInfo`, `MultiByteToWideChar` and `WideCharToMultiByte` also support `CP_UTF8` and code page 437, and fail with `ERROR_INVALID_PARAMETER` for other code pages. `IsValidCodePage` returns `TRUE` only for 437, 1252 and 65001. The C runtime uses the C locale, so `mbstowcs`, `wcstombs` and their `_s` versions map each byte to the wide character with the same value. `wcstombs` and `wcstombs_s` fail for a wide character above 0xFF. `setlocale` always returns `"C"`, and `_create_locale` and `_wcreate_locale` return the same C locale object for each locale name.

`lstrcmp`, `lstrcmpi` and `CompareString` approximate the linguistic sort of Windows. They compare the strings without case first, and when these are equal, lower case sorts before upper case. Punctuation and symbols sort by their code values, without the Windows weights. The case-insensitive C runtime functions, such as `_stricmp`, fold only `A` to `Z`, and the case conversion functions, such as `tolower` and `_wcslwr`, change the case of only the letters `A` to `Z` and `a` to `z`.

## CryptoAPI keys

The `HCRYPTKEY` functions support RC4 keys, and AES keys of 128, 192 and 256 bits. `CryptImportKey` accepts a `PLAINTEXTKEYBLOB` and the `PUBLICKEYBLOB` of an RSA key. `CryptEncrypt` with an RSA public key uses PKCS#1 v1.5 padding. No key has a private part, so `CryptImportKey` fails a `SIMPLEBLOB` with `NTE_BAD_PUBLIC_KEY`, and `CryptDecrypt` fails with an RSA key. `CryptExportKey` gives only a `PLAINTEXTKEYBLOB`. `CryptDeriveKey` derives only RC4 keys. An AES key supports the CBC, ECB and CFB modes and PKCS#5 padding. `CryptSetKeyParam` sets `KP_IV`, `KP_MODE` and `KP_PADDING`, and returns `TRUE` for other parameters without a change to the key. `CryptGenKey` gets the key bytes from the random source of the emulator, so the key is the same in each run with the same `random_seed`.

## CPU features

Unicorn 2.1.4 does not emulate AVX. It runs the VEX forms of the SSE instructions with 128-bit registers. It does not run the 256-bit forms, the EVEX (AVX-512) forms or the instructions that AVX, AVX2 and FMA add. CPUID and `IsProcessorFeaturePresent` report no AVX. A binary that is compiled for AVX, for example with `/arch:AVX2`, can use these instructions without a CPUID check. When such an instruction cannot run, the guest gets `STATUS_ILLEGAL_INSTRUCTION`, as on a CPU without AVX. If no handler takes the exception, the error type of the run is `unsupported_cpu_feature`, and `instruction` in the error has the instruction. Other instructions that Unicorn cannot run, such as `ud2` or data that is not code, give `invalid_instruction`.

## Environmental requirements

A sample can expect files, registry keys, network responses, loaded modules or system structures that the config does not have. When one is missing, the sample can act as if it found an analysis environment, but the cause is the config. Before you decide that Speakeasy does not support a sample, add the missing items with the config file and the CLI overrides.

The `cpuid` instruction gives the values of the Unicorn CPU model, except that leaf 1 does not set the bit that tells that a hypervisor is present (bit 31 of ECX). The hypervisor leaves from 0x40000000 give zeros. So a check for a hypervisor finds a physical machine.

## Repeatable runs

Two runs of the same sample with the same config give the same random bytes, GUIDs and times to the sample. The `random_seed` and `start_time` options in the [configuration](configuration.md) set these values.

The `rdtsc` and `rdtscp` instructions are an exception. They read the time stamp counter of Unicorn, which counts host time at 1 GHz. Unicorn 2.1.4 has no hook for `rdtsc`, so Speakeasy cannot give a fixed value. `Sleep` and the wait APIs add the waited time to the counter, so the difference across a `Sleep` call is correct. A sample that uses `rdtsc` as a seed, or that measures how long its code takes, can take a different path in each run.

A wall-clock limit (`--max-run-time`, `--max-total-time`) stops a run at a point that depends on the speed of the host. See [CLI execution controls](cli-execution-controls.md#stopping-conditions).

The report fields `emulation_total_runtime` and `timestamp` are host times, so they are different in each report.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [Exception dispatch](exceptions.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [Adding API handlers](api-handlers.md)
- [Help and troubleshooting](help.md)
