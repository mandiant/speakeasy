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

If the API has no handler and no signature, the current run stops with an error. Examples are a C runtime function without a handler, a function of a third-party DLL or a native function that neither win32metadata nor phnt declares. The run also stops when the signature has a form that the emulator cannot call, for example a variadic function. The log shows:

- `Unsupported API: <module_name>.<api_name>`

The emulator does not know the argument count or the calling convention of an unknown API. If the run continued, the stack could be wrong and the report could have incorrect data.

The runs in the queue, for example other entry points, still run. With `modules.functions_always_exist`, Speakeasy emulates a call to an API without a declaration as a stdcall function with 4 arguments that returns 1.

## Threads

Threads do not run at the same time. Each thread is a run in the run queue, and a run executes until it ends, so a thread cannot block and wait for another thread. A wait on an event that is not set times out when its timeout is finite and no run is queued. Otherwise the wait returns as if the event is set. `WaitOnAddress` returns at once when the value at the address differs from the compare value. If the values are equal, a finite wait times out at once, and an INFINITE wait ends the run of the thread. `WakeByAddressSingle` and `WakeByAddressAll` do nothing, because no thread can be in a wait. A sample that polls a value that only a queued thread changes can loop until it reaches `max_api_calls`.

## Strings

The ANSI code page is 1252 and the OEM code page is 437. Speakeasy reads and writes `A` strings in code page 1252, so each byte is one character. A character that is not in code page 1252 becomes `?`. For some of these characters Windows uses a best-fit mapping (`ā` to `a`), but Speakeasy does not. `GetCPInfo`, `MultiByteToWideChar` and `WideCharToMultiByte` also support `CP_UTF8` and code page 437, and fail with `ERROR_INVALID_PARAMETER` for other code pages. `IsValidCodePage` returns `TRUE` only for 437, 1252 and 65001. The C runtime uses the C locale, so `mbstowcs`, `wcstombs` and their `_s` versions map each byte to the wide character with the same value. `wcstombs` and `wcstombs_s` fail for a wide character above 0xFF.

`lstrcmp`, `lstrcmpi` and `CompareString` approximate the linguistic sort of Windows. They compare the strings without case first, and when these are equal, lower case sorts before upper case. Punctuation and symbols sort by their code values, without the Windows weights. The case-insensitive C runtime functions, such as `_stricmp`, fold only `A` to `Z`, and the case conversion functions, such as `tolower` and `_wcslwr`, change the case of only the letters `A` to `Z` and `a` to `z`.

## CryptoAPI keys

The `HCRYPTKEY` functions support RC4 keys, and AES keys of 128, 192 and 256 bits. `CryptImportKey` accepts a `PLAINTEXTKEYBLOB` and the `PUBLICKEYBLOB` of an RSA key. `CryptEncrypt` with an RSA public key uses PKCS#1 v1.5 padding. No key has a private part, so `CryptImportKey` fails a `SIMPLEBLOB` with `NTE_BAD_PUBLIC_KEY`, and `CryptDecrypt` fails with an RSA key. `CryptExportKey` gives only a `PLAINTEXTKEYBLOB`. `CryptDeriveKey` derives only RC4 keys. An AES key supports the CBC, ECB and CFB modes and PKCS#5 padding. `CryptSetKeyParam` sets `KP_IV`, `KP_MODE` and `KP_PADDING`, and returns `TRUE` for other parameters without a change to the key. `CryptGenKey` gets the key bytes from the random source of the emulator, so the key is the same in each run with the same `random_seed`.

## Environmental requirements

A sample can expect files, registry keys, network responses, loaded modules or system structures that the config does not have. When one is missing, the sample can act as if it found an analysis environment, but the cause is the config. Before you decide that Speakeasy does not support a sample, add the missing items with the config file and the CLI overrides.

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
