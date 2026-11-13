# Report walkthrough

The report models are in `speakeasy/report.py` and `speakeasy/profiler_events.py`. `speakeasy/profiler.py` builds the report from the data that the emulator records in `speakeasy/windows/winemu.py`, `win32.py` and `kernel.py`.

`speakeasy/resources/report.schema.json` is the JSON schema of the report, and the package includes it. After you change a report model, run `just gen-report-schema`. The models reject unknown keys.

For the changes from the 1.x report, see [Migrating to 2.0](migrating-to-2.0.md#report-from-1x). For the changes from the 6.x report of the 2.0 pre-releases, see [Report schema 7.0.0](migrating-to-2.0.md#report-schema-700).

`get_json_report()` and the CLI write compact JSON, with no indentation and no line breaks. To indent a report, use `jq . report.json`.

The examples on this page are JSONC: JSON with comments that explain the fields. Remove the comments before you parse an example as JSON.

## Report fields

A key is absent when Speakeasy did not collect its data. The option of the data is off, for example `coverage` when `code.coverage=false`, or the data does not apply, for example `memory` in kernel mode. An empty list or object means that Speakeasy collected the data and found nothing. A counter or a boolean is always present when Speakeasy collects it, also when it is 0 or false. By default, Speakeasy collects all the data that this page describes.

The report writes each machine word as a hex string with a `0x` prefix and lowercase digits. Machine words are addresses, pointers, handles, raw argument values, return values, register values, exception codes and coverage addresses. A 64-bit word can be above 2\*\*53 or 2\*\*63. JavaScript, Go `interface{}`, jq and int64 stores such as SQLite lose such a value when it is a JSON number, and they give no error. In Python, `int(value, 16)` reads the string. The schema gives the pattern `^0x[0-9a-f]+$` for each hex string. The report writes each quantity, such as a size, a count, an offset, a tick or an ID, as a JSON number.

`report_version` is the value of `speakeasy.report.REPORT_VERSION`. `timestamp` is the Unix time in seconds of the first start of the run queue, and `emulation_total_runtime` is the wall-clock time in seconds from that start to the end of the emulation. A `call()` after `run_module()` and each child process start the run queue again, and the time to the last end counts. The other top-level fields are:

- `arch` (`x86` or `x64`), `path`, `sha256`, `size`, `file_type` (`exe`, `dll`, `driver` or `shellcode`) and `image_base`: the input metadata that the loader records. `path` is the host path of the input file. If the input came from bytes in memory, the report has no `path`.
- `errors`: the errors of the session that do not belong to one run. If the input PE has a defect, for example an entry point outside the image or an import descriptor that the Windows loader cannot resolve, the loader adds an `invalid_image` error with the defect in `context_summary`, and emulation continues. `PeLoader` in `speakeasy/windows/loaders.py` has the checks. If `limits.total_time` runs out before all child processes run, the emulator adds a `total_time_limit` error with the number of child processes that did not run in `context_summary`.
- `strings`: the strings from the input file and from memory, only if `memory.strings=true`. `static` has the strings of the input file. `in_memory` has the strings at the end of the emulation that are not in `static`. Speakeasy reads them from the stack, from the memory that API handlers allocate, and from the images of the guest modules. In an image, it reads only the strings that the guest changed after the load, for example the strings that an unpacker decodes in place.
- `data`: the payloads that the report stores once, keyed by the SHA-256 of their bytes. Each payload has `compression` (`zlib`), `encoding` (`base64`), `size` (before compression) and `data`. Each `data_ref` field holds a key of `data`. `data` has only the payloads that a `data_ref` refers to.
- `processes`: the processes that the report refers to, in the order of `pid`. See [Processes](#processes).
- `runs`: the runs, in the order that the runs started.

## Processes

`processes` has one entry for the process of each run, for each process that the guest created, and for each process that is the target of an event. A process that existed before the emulation, for example `explorer.exe` from the `processes` of the config, gets an entry when the guest writes to its memory or starts a thread in it. Each entry has these fields:

| Field | Content |
|---|---|
| `pid` | The process ID, the same as `pid` of the runs and of the events. |
| `parent_pid` | The ID of the process that created this process, the `pos.pid` of its `process_create` event. Absent for the first process and for a process that existed before the emulation. |
| `path` | The emulated path of the process image, for example `C:\Windows\system32\svchost.exe`. Absent when the process has no image path. |
| `command_line` | The command line of the process. Absent for a process from the config with no `command_line`. For `CreateProcess` with a NULL `lpCommandLine`, it is the application name. |
| `runs` | The indexes in `runs` of the runs of the process. Empty when no run executed in the process, for example a child process with `runs.children=false`. |

For the input EXE, the first process has the emulated path of the input and the process command line: `process.command_line` of the config, or the quoted path and the `--argv` arguments. For a DLL or shellcode, the first process is the container process of the config (the entry with `is_main_exe`). In kernel mode, the runs have no process, so the list has only the targets of memory events.

This is `processes` of PMA Lab 12-01, which injects a thread into `explorer.exe`:

```json
[
  {"pid": 1220, "path": "C:\\Windows\\explorer.exe", "runs": [1]},
  {"pid": 1240, "path": "C:\\Windows\\system32\\Practical Malware Analysis Lab 12-01.exe_", "command_line": "svchost.exe myarg1 myarg2", "runs": [0]}
]
```

## Runs

A run starts at one address, such as the module entry point, an export, a TLS callback or a thread, and executes until the code returns or an error ends it. Each run has these fields:

| Field | Content |
|---|---|
| `type`, `name` | The kind of code that the run executes, and a detail for that kind. The table below gives the values. |
| `start_address`, `args` | The address where the run started, and the arguments that the emulator gives to the code there. |
| `pid`, `tid` | The process and the thread of the run. Absent in kernel mode. |
| `instruction_count` | The number of instructions that the run executed. See the note on the instruction count below. |
| `api_call_count` | The number of API calls of the run. It also counts the calls that `events` leaves out as repeats. `limits.api_calls` limits this count. |
| `api_hash` | The SHA-256 of the lowercase names of the APIs that the run called, each name once, in the order of the first call. |
| `return_value` | The value of the return register when the run returned. |
| `error` | The error that ended the run. Absent when the run completed. |
| `events` | The events of the run, in order. The `record_*_event` methods of `Profiler` add them. |
| `accesses` | The read, write and execute counts of the regions and the symbols, only if `memory.accesses=true`. |
| `dynamic_code` | The dynamic code regions where code ran in the run, one entry for each region. |
| `coverage` | The sorted addresses of the instructions that ran, only if `code.coverage=true`. |
| `dropped_files` | In user mode, the files that the guest wrote completely, up to the end of the run. The list also has the files that the guest wrote and then deleted. Each file has `path`, `size`, `sha256` and `data_ref`. `data_ref` is equal to `sha256`. An empty file and a file above `MAX_EMBEDDED_FILE_SIZE` (10 MiB, `speakeasy/artifacts.py`) have no `data_ref`. |
| `memory` | In user mode, the memory regions (`layout`) and the modules (`modules`) at the end of the run. |

The emulator counts instructions only when a hook that counts them is active: with `memory.accesses`, with `memory.dynamic_code_contents`, or with `limits.instructions` above 0. Without these options, the runs have no `instruction_count` and the events have no `tick`. With one of them, each run has `instruction_count` and each event has `tick`, also when the value is 0.

If the kind of run has no detail (`None` in Python), the JSON report leaves out `name`.

| `type` | `name` |
|---|---|
| `module_entry` | none |
| `dll_entry` | `DLL_PROCESS_ATTACH` |
| `tls_callback` | index of the callback in the TLS callback array, for example `0` |
| `export` | export name, or none for an export without a name |
| `shellcode` | none |
| `thread` | none for a thread in the same process, the process name for a thread in another process, `apc` for a `QueueUserAPC` routine |
| `service_main` | service name from `StartServiceCtrlDispatcher` |
| `dependency_dll_entry`, `dependency_tls_callback` | name of the DLL that the process loaded |
| `call` | none (`Speakeasy.call` started the run) |
| `driver_entry`, `driver_unload`, `driver_reinit` | none |
| `irp` | IRP major function, for example `IRP_MJ_DEVICE_CONTROL` |

If the run ended abnormally, the run has an `error`. Its `type` is an identifier such as `invalid_read`, `unsupported_api` or `per_run_time_limit`. The report schema lists all values. The emulator fills only the fields of `error` that apply to the type. A Python exception in Speakeasy itself, such as a bug in an API handler, gives `internal_error`, with the exception text in `message` and the Python traceback in `traceback`.

The type of a limit error is the name of its key under `limits` in the singular, then `_limit`. The one exception is `limits.api_loop_calls`, which gives `api_loop_limit`.

| Config key | Flag | Error type |
|---|---|---|
| `limits.per_run_time` | `--limits-per-run-time` | `per_run_time_limit` |
| `limits.total_time` | `--limits-total-time` | `total_time_limit` |
| `limits.api_calls` | `--limits-api-calls` | `api_call_limit` |
| `limits.api_loop_calls` | `--limits-api-loop-calls` | `api_loop_limit` |
| `limits.instructions` | `--limits-instructions` | `instruction_limit` |

For `api_call_limit`, `api_loop_limit` and `instruction_limit`, `count` is the limit. For `api_call_limit` and `api_loop_limit`, `last_api` is the API of the last call. A run that makes `limits.api_loop_calls` API calls with no call from a new call site has `api_loop_limit`, and `error.loop` tells about the calls after the last new call site. In `error.loop`, `start` is the position of the first of these calls, `calls` is their number, and `sites` has up to 16 call sites (`api_name`, `return_address` and `calls`), the site with the most calls first.

An error of a fault has `pc`, `instruction`, `registers` and `stack`. `instruction` is absent when Speakeasy cannot disassemble the instruction at `pc`, for example when `pc` is not mapped. The same is true for `instruction` of an `exception` event. `pc_module` is the file name of the module that contains `pc`, the same as `name` in `memory.modules`, and `pc_offset` is the offset of `pc` from the base of that module. `address` is the memory address of the faulting access. `address_region` is the region that contains `address`. When `address` is not mapped, `nearby_regions` has the regions nearest to it. These regions have the fields of a region in `memory.layout` without `freed` and `data_ref`.

## Events

Each event has `event`, its type, and `pos`, the position of the thread that did the operation, so the event is in the timeline of that thread. `pos` has the `tick` (the instruction count of the run), `tid`, `pid` and `pc`. Each `pid` in the report is the process ID that the guest gets, for example from `GetCurrentProcessId` or `Process32Next`.

An `api` event has the `pc` of the instruction that went to the API: a `call`, or the `jmp` of an import thunk. `return_address` is the address where the API returns to the caller. The profiler leaves out an `api` event that has the same API, `pc`, `return_address`, shown arguments and return value as one of the last 3 events of the run, and adds 1 to `calls` of that event. So `calls` is the number of calls that an `api` event stands for: 1 for a call with no repeats, 5000 for a loop that makes the same call 5000 times. The event keeps the `pos` and the raw `value` of each argument of the first call. `api_call_count` of the run is the sum of `calls` of its `api` events.

The code of an API can add other events, such as `file_create`, `reg_open_key`, `mem_alloc`, `process_create`, `module_load` or `net_dns`. Such an event has the `pos` of the API call: the same `tick` and `pc` as the `api` event of the call. It comes in `events` just before that `api` event. If the profiler leaves out the `api` event as a repeat, no `api` event follows.

`VirtualFree` adds a `mem_free` event. `LoadLibrary`, `LoadLibraryEx` and `LdrLoadDll` add a `module_load` event for each module that the load maps, the dependencies of the module included. The `name` of a `module_load` event is the file name of the module, for example `urlmon.dll`, the same as `name` in `memory.modules` and `module` in `memory.layout`. A module that the config preloads, or that is already loaded, gets no event.

The events about a process, its memory or its threads (`mem_alloc`, `mem_write`, `mem_read`, `mem_protect`, `mem_free`, `thread_create`, `thread_inject` and `process_create`) also have the `pid` of the target process. If the target is the process of that thread, the event has no `pid`. So a `pid` in these events means that the operation crossed a process boundary. `thread_create` and `thread_inject` have the `tid` of the new thread, also when the thread is in the same process.

The `data_ref` of a file, registry or network event refers to the first bytes of the operation, and the `data_ref` of a `mem_write` or `mem_read` event refers to all the bytes of the API call. A `data_ref` is absent when there are no bytes. The profiler merges the reads of one path in a run into one `file_read` event, and the writes into one `file_write` event. It does not merge `mem_write` and `mem_read` events: each call of an API such as `WriteProcessMemory` or `ReadProcessMemory` gets its own event. The report keeps one copy of a payload that repeats.

An `api` event records its arguments in `args`, a list of objects with `name`, `type`, `value` and `display`. If the signature database declares the function, and its prototype uses the same argument slots as the call, `args` has an entry per parameter. Then `name` is the parameter name, and Speakeasy renders `display` from the declared type. It decodes the parameters of a string type, such as `LPCSTR`, `LPWSTR` or `PUNICODE_STRING`, shows enum and flag values as names and expands struct pointers. Without a usable signature, `args` has one entry for each argument slot, with no `name`, and `display` is the hex value. `type` tells you how to read `display`.

| Type | `display` |
|---|---|
| `int` | hex integer |
| `ptr` | address in hex (also null, out-only and unreadable pointers, and buffers such as a `BYTE*`) |
| `handle` | handle value in hex |
| `str` | decoded string, without quotes |
| `bool` | `TRUE` or `FALSE` |
| `enum` | one member name |
| `flags` | member names joined by `\|`, with a hex remainder for unknown bits |
| `struct` | `{field: value, ...}` display text, which is not JSON |
| `bytes` | hex dump of a by-value struct with no known layout |
| `guid` | `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` |
| `float` | decimal number |
| `text` | a value that a handler decoded itself |

`value` is the raw value that the caller passed, as a hex string. With it, you can match a flag or a constant without parsing `display`. If a parameter uses two argument slots on x86, for example a 64-bit integer, `value` has the combined value. If a handler serves the call and decodes a parameter itself, for example the key path of a registry handle, the decoded text replaces the `display` of that parameter. `value` still has what the caller passed. If a variadic handler adds an entry, such as the formatted output of `printf`, that entry has no `value`.

A handle value refers to one object for the whole emulation. Speakeasy gives out the handles of all object types from one counter, and it does not give out the value of a closed handle again. So a `handle` in an event identifies the file, key or other object that the call used.

## Memory regions

All emulated processes share one address space, so `memory` of a run also has the regions and the modules of the other processes. `memory.modules` has the kernel modules too, such as `ntoskrnl.exe` and `hal.dll`. The regions and the modules have no `pid`. Only the tag of a `VirtualAllocEx` region has the pid of the target process, for example `api.VirtualAllocEx.svchost_exe.1444`. So you cannot make one memory map for each process from the report. [Processes](limitations.md#processes) describes how `VirtualAllocEx` into another process can give a different address than on Windows.

`memory.layout` has the memory regions at the end of a run, in the order of `base`. Each region has `base`, `size` and `perms`. `perms` has three characters, `r`, `w` and `x`, with `-` for a permission that the region does not have, such as `r-x`. `tag` is the tag that the memory manager gave to the region, such as `api.VirtualAlloc`, `api.heap.HeapAlloc`, `emu.stack` or `emu.struct.PEB`. The tag does not include the address of the region, so use `base` to identify a region. A region with no tag, such as a small allocation of an API handler, has no `tag`. [Memory management](memory.md#memory-tags) describes the tags.

The emulator splits the image of a module into one region for the PE headers and one region for each section. Each of these regions has the tag `emu.module`, `module` with the file name of the module, such as `sample.exe` or `kernel32.dll`, and `section` with the section name, such as `.text`, or `headers`. `module` is the same as `name` in `memory.modules`. The image of shellcode input is one region with `section` `shellcode`, and its `module` is the SHA-256 of the input. An address in a module image that is outside the headers and the sections belongs to the full image. In `address_region` of an error, such an address has a region with the base and the size of the image, `module`, and no `section`.

Other fields name a region by its base, the `base` of the region in `memory.layout`: `region` of a stack slot in `error.stack` and in an `exception` event, `region` of an entry of `accesses.regions`, and `region` of an entry of `dynamic_code`. For an address in a module image, this is the base of its headers or section. A stack slot whose value is not in mapped memory has no `region`.

`freed` is present on each region only if `memory.freed_regions=true`. Then a region that the guest frees stays mapped, and its `freed` is true. If `memory.freed_regions=false`, the emulator unmaps a freed allocation when no other allocation of its block is live, and the layout leaves out each freed allocation, also an allocation that stays mapped while another allocation of its block is live.

If `memory.final_contents=true`, a region of guest memory has a `data_ref` to its contents at the end of the run. A region of emulator memory has no `data_ref`.

| Region | `data_ref` |
|---|---|
| The image of the input and of each module that loads from a file, such as a DLL that the guest loads from the emulated file system or a DLL from `modules.directory_x86` | yes |
| Allocations and heaps of the guest (`api.*` tags) | yes |
| Regions with no tag, which API handlers allocate for the guest | yes |
| Static TLS data of the guest (`emu.tls.*` tags) | yes |
| The stub images of the system modules and the kernel modules, such as `kernel32.dll` and `ntoskrnl.exe` | no |
| Stacks (`emu.stack`) | no |
| Other emulator memory, such as the GDT, the segments, `KUSER_SHARED_DATA`, the PEB and the other `emu.struct.*` tags | no |

A region of guest memory also has no `data_ref` when the emulator cannot read it.

`accesses` has two lists. `regions` has the read, write and execute counts of each region that the run used, in the order of `region`. An access in a module image outside the headers and the sections counts for the headers. `symbols` has the counts of each symbol address, in the order of the address, with the symbol in `module.symbol` form. Only an access that starts at the exact address of a symbol counts.

`dynamic_code` has the memory regions with dynamic code, for example from `VirtualAlloc`, where code ran. Each entry has `region` (the base), `size`, `tag` and `contents`. The first entry of `contents` has `pos`, the position when the emulator first found code that ran in the region. The emulator finds the code when it runs in the first 16 bytes of the region, or when an API returns into the region. If `memory.dynamic_code_contents.enabled=false`, `contents` has only that entry, with no `data_ref`, and the region has no `limit_reached`.

If `memory.dynamic_code_contents.enabled=true`, each entry of `contents` also has a `data_ref` to the region contents at `pos`, so the report keeps a stage that the guest overwrites later. The emulator then also watches the region for writes. When the region changed and control comes into it from outside, for example with a call or an API return, the emulator adds one more entry to `contents`, with its own `pos` and `data_ref`. `contents` is in the order of `pos.tick`, and with this option `pos.tick` is always the instruction count of the run. Each entry of `contents` has different data from the entry before it. A decoder loop in the region gives no snapshot for each pass, because its blocks do not come from outside the region. `memory.dynamic_code_contents.limit` (default 8) is the maximum number of entries of `contents`, with the first one. `limit_reached` is true when the region changed and ran again after the last snapshot that the limit allows, and false if not. The report does not have a stage that the region decodes and runs before control leaves the region. Each write in the region counts, also a write to data. A region that holds an unpacked image with its global variables can get a snapshot after most API calls, and it gets to the limit fast.

## Report fields and CLI flags

The boolean flags in this table are on by default. The `--no-` form of each flag removes its data from the report.

| Flag | Report fields |
|---|---|
| `--memory-strings` | the top-level `strings` ([recipe](cli-analysis-recipes.md#recipe-memory-strings)) |
| `--code-coverage` | `runs[].coverage` ([recipe](cli-analysis-recipes.md#recipe-code-coverage)) |
| `--memory-accesses` | `runs[].accesses` ([recipe](cli-analysis-recipes.md#recipe-memory-accesses)). It also counts the instructions for `instruction_count` and `pos.tick`. |
| `--memory-final-contents` | `runs[].memory.layout[].data_ref` ([recipe](cli-analysis-recipes.md#recipe-memory-snapshots)) |
| `--memory-dynamic-code-contents` | `runs[].dynamic_code[].contents[].data_ref`, `runs[].dynamic_code[].limit_reached`, and the entries of `contents` after the first. It also counts the instructions. |
| `--memory-dynamic-code-contents-limit N` | the maximum number of entries of `contents` of each region (default 8) |
| `--memory-freed-regions` | `runs[].memory.layout[].freed`, and the freed regions in the layout. This flag also changes what the guest sees. |
| `--limits-per-run-time`, `--limits-total-time`, `--limits-api-calls`, `--limits-api-loop-calls`, `--limits-instructions` | the limit errors in `error` and in the top-level `errors` |
| `--dropped-files-path PATH` | no report field. The CLI also writes the dropped files to a zip archive ([recipe](cli-analysis-recipes.md#recipe-dropped-files)). |

## Annotated report example

This example shows each field. It is not the output of one run, and the values do not agree with each other.

```jsonc
{
  // Report format version.
  "report_version": "7.0.0",

  // Wall-clock seconds from the first start of the run queue to the end.
  "emulation_total_runtime": 1.234,

  // Unix time in seconds of the first start of the run queue.
  "timestamp": 1760000000,

  // Input metadata. A key is absent when the value is unknown.
  "arch": "x86",
  "path": "/samples/payload.bin",
  "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "size": 4096,
  "file_type": "exe",
  "image_base": "0x400000",

  // Errors that do not belong to one run.
  "errors": [
    {
      "type": "invalid_image",
      "context_summary": "entry point RVA 0x5000 is outside the image (size 0x4000)"
    }
  ],

  // Only with memory.strings.
  "strings": {
    "static": {
      "ansi": ["kernel32.dll"],
      "unicode": ["http://example.org"]
    },
    "in_memory": {
      "ansi": ["decoded_c2_token"],
      "unicode": []
    }
  },

  // Payloads, keyed by the SHA-256 of their bytes. This example uses short keys.
  "data": {
    "data-region": {"compression": "zlib", "encoding": "base64", "size": 1, "data": "eJxjAAAAAQAB"}
  },

  // Processes of the runs and of the events, in the order of pid.
  "processes": [
    {
      "pid": 1337,
      // The first process and a process that existed before the emulation have no parent_pid.
      "path": "C:\\Windows\\System32\\sample.exe",
      // Absent when the process has no command line.
      "command_line": "sample.exe",
      // Indexes in runs of the runs of the process.
      "runs": [0]
    },
    {
      "pid": 1444,
      // pos.pid of the process_create event of this process.
      "parent_pid": 1337,
      "path": "C:\\Windows\\system32\\svchost.exe",
      // A child process with runs.children=false has no runs.
      "runs": []
    }
  ],

  "runs": [
    {
      // Kind of code that this run executes. A module_entry run has no name.
      "type": "module_entry",

      // Address where this run started.
      "start_address": "0x401000",

      // Arguments of the code at start_address.
      "args": ["0x1", "0x2"],

      // Process and thread of the run. Absent in kernel mode.
      "pid": 1337,
      "tid": 2000,

      // Only with memory.accesses, memory.dynamic_code_contents or
      // limits.instructions above 0: instructions that the run executed.
      "instruction_count": 12345,

      // API calls of the run, also the calls that events leaves out as repeats.
      "api_call_count": 31,

      // SHA-256 of the names of the APIs that the run called, each name once.
      "api_hash": "2222222222222222222222222222222222222222222222222222222222222222",

      // The run has no return_value, because an error ended it.
      "error": {
        "type": "invalid_read",
        "pc": "0x401234",
        "instruction": "mov eax, dword ptr [ecx]",
        "address": "0x0",
        "access_type": "read",
        "registers": {"eax": "0x403000", "ecx": "0x0", "esp": "0x12ff70"},
        "stack": [
          {"offset": 0, "value": "0x401010", "region": "0x401000"},
          {"offset": 4, "value": "0x0"}
        ],
        "pc_module": "sample.exe",
        "pc_offset": 4660,
        "nearby_regions": [
          {"base": "0x10000", "size": 4096, "perms": "rw-", "tag": "emu.struct.EPROCESS"}
        ],
        "tid": 2000,
        "pid": 1337,
        "context_summary": "invalid read at 0x0"
      },

      // The events of the run, in order.
      "events": [
        {
          // An event that the code of an API adds has the pos of the API call.
          // It comes just before the api event of the call.
          "pos": {"tick": 10, "tid": 2000, "pid": 1337, "pc": "0x401000"},
          "event": "module_load",
          "name": "ws2_32.dll",
          "path": "C:\\Windows\\system32\\ws2_32.dll",
          "base": "0x78c00000",
          "size": 94208
        },
        {
          // pc is the call or the jmp of the import thunk, return_address the
          // address after the call.
          "pos": {"tick": 10, "tid": 2000, "pid": 1337, "pc": "0x401000"},
          "event": "api",
          "api_name": "kernel32.LoadLibraryA",
          // "name" is present when the API signature is known.
          "args": [{"name": "lpLibFileName", "type": "str", "value": "0x40308c", "display": "ws2_32"}],
          "return_value": "0x78c00000",
          "return_address": "0x401006",
          // Number of calls: this call and the repeats that the profiler leaves out.
          "calls": 1
        },
        // The example leaves out the api event of the calls below.
        {
          "pos": {"tick": 20, "tid": 2000, "pid": 1337, "pc": "0x40100a"},
          "event": "process_create",
          "path": "C:\\Windows\\System32\\cmd.exe",
          "command_line": "cmd.exe /c whoami",
          "pid": 4200
        },
        {
          // The thread of pid 1337 allocates memory in pid 4242.
          "pos": {"tick": 30, "tid": 2000, "pid": 1337, "pc": "0x401014"},
          "event": "mem_alloc",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "base": "0x10000000",
          "size": 4096,
          "protect": ["PAGE_EXECUTE_READWRITE"],
          "pid": 4242
        },
        {
          "pos": {"tick": 40, "tid": 2000, "pid": 1337, "pc": "0x40101e"},
          "event": "mem_write",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "base": "0x10000000",
          "size": 16,
          "data_ref": "data-mem-write",
          "pid": 4242
        },
        {
          "pos": {"tick": 50, "tid": 2000, "pid": 1337, "pc": "0x401028"},
          "event": "mem_read",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "base": "0x10000000",
          "size": 16,
          "data_ref": "data-mem-read",
          "pid": 4242
        },
        {
          // No pid: the target is the process in pos.
          "pos": {"tick": 60, "tid": 2000, "pid": 1337, "pc": "0x401032"},
          "event": "mem_protect",
          "path": "C:\\Windows\\System32\\sample.exe",
          "base": "0x401000",
          "size": 4096,
          "protect": ["PAGE_EXECUTE_READ"]
        },
        {
          "pos": {"tick": 70, "tid": 2000, "pid": 1337, "pc": "0x40103c"},
          "event": "mem_free",
          "path": "C:\\Windows\\System32\\sample.exe",
          "base": "0x10000000",
          "size": 4096
        },
        {
          // A thread in the same process has the new tid and no pid.
          "pos": {"tick": 90, "tid": 2000, "pid": 1337, "pc": "0x401050"},
          "event": "thread_create",
          "path": "C:\\Windows\\System32\\sample.exe",
          "start_address": "0x401500",
          "param": "0x0",
          "tid": 2100
        },
        {
          "pos": {"tick": 100, "tid": 2000, "pid": 1337, "pc": "0x40105a"},
          "event": "thread_inject",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "start_address": "0x10000000",
          "param": "0x0",
          "pid": 4242,
          "tid": 4300
        },
        {
          "pos": {"tick": 110, "tid": 2000, "pid": 1337, "pc": "0x401064"},
          "event": "file_create",
          "path": "C:\\ProgramData\\drop.bin",
          "handle": "0x80",
          "open_flags": ["CREATE_ALWAYS"],
          "access_flags": ["GENERIC_WRITE"]
        },
        {
          "pos": {"tick": 120, "tid": 2000, "pid": 1337, "pc": "0x40106e"},
          "event": "file_open",
          "path": "C:\\ProgramData\\drop.bin",
          "handle": "0x84",
          "open_flags": ["OPEN_EXISTING"],
          "access_flags": ["GENERIC_READ"]
        },
        {
          // All reads of one path in a run, merged into one event.
          "pos": {"tick": 130, "tid": 2000, "pid": 1337, "pc": "0x401078"},
          "event": "file_read",
          "path": "C:\\ProgramData\\drop.bin",
          "handle": "0x84",
          "size": 4,
          "data_ref": "data-file-read",
          "buffer": "0x120000"
        },
        {
          "pos": {"tick": 140, "tid": 2000, "pid": 1337, "pc": "0x401082"},
          "event": "file_write",
          "path": "C:\\ProgramData\\drop.bin",
          "handle": "0x80",
          "size": 4,
          "data_ref": "data-file-write",
          "buffer": "0x130000"
        },
        {
          "pos": {"tick": 142, "tid": 2000, "pid": 1337, "pc": "0x401084"},
          "event": "file_delete",
          "path": "C:\\ProgramData\\drop.bin"
        },
        {
          "pos": {"tick": 145, "tid": 2000, "pid": 1337, "pc": "0x401087"},
          "event": "directory_create",
          "path": "C:\\ProgramData\\stage"
        },
        {
          "pos": {"tick": 147, "tid": 2000, "pid": 1337, "pc": "0x401089"},
          "event": "directory_delete",
          "path": "C:\\ProgramData\\stage"
        },
        {
          "pos": {"tick": 150, "tid": 2000, "pid": 1337, "pc": "0x40108c"},
          "event": "reg_open_key",
          "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft",
          "handle": "0x88",
          "access_flags": ["KEY_READ"]
        },
        {
          "pos": {"tick": 160, "tid": 2000, "pid": 1337, "pc": "0x401096"},
          "event": "reg_create_key",
          "path": "HKEY_CURRENT_USER\\Software\\Lab",
          "handle": "0x8c",
          "open_flags": ["REG_CREATED_NEW_KEY"],
          "access_flags": ["KEY_WRITE"]
        },
        {
          "pos": {"tick": 170, "tid": 2000, "pid": 1337, "pc": "0x4010a0"},
          "event": "reg_read_value",
          "path": "HKEY_CURRENT_USER\\Software\\Lab",
          "handle": "0x8c",
          "value_name": "Config",
          "size": 4,
          "data_ref": "data-reg-read",
          "buffer": "0x140000"
        },
        {
          "pos": {"tick": 175, "tid": 2000, "pid": 1337, "pc": "0x4010a5"},
          "event": "reg_write_value",
          "path": "HKEY_CURRENT_USER\\Software\\Lab",
          "handle": "0x8c",
          "value_name": "Config",
          "size": 4,
          "data_ref": "data-reg-write",
          "buffer": "0x140000"
        },
        {
          "pos": {"tick": 180, "tid": 2000, "pid": 1337, "pc": "0x4010aa"},
          "event": "reg_list_subkeys",
          "path": "HKEY_CURRENT_USER\\Software",
          "handle": "0x8c"
        },
        {
          "pos": {"tick": 182, "tid": 2000, "pid": 1337, "pc": "0x4010ac"},
          "event": "reg_delete_value",
          "path": "HKEY_CURRENT_USER\\Software\\Lab",
          "handle": "0x184",
          "value_name": "Config"
        },
        {
          "pos": {"tick": 185, "tid": 2000, "pid": 1337, "pc": "0x4010af"},
          "event": "reg_delete_key",
          "path": "HKEY_CURRENT_USER\\Software\\Lab",
          "handle": "0x184"
        },
        {
          "pos": {"tick": 190, "tid": 2000, "pid": 1337, "pc": "0x4010b4"},
          "event": "net_dns",
          "query": "example.org",
          "response": "93.184.216.34"
        },
        {
          "pos": {"tick": 200, "tid": 2000, "pid": 1337, "pc": "0x4010be"},
          "event": "net_traffic",
          "server": "93.184.216.34",
          "port": 443,
          "proto": "tcp",
          "type": "data_out",
          "data_ref": "data-net-traffic",
          "method": "winsock.send"
        },
        {
          "pos": {"tick": 210, "tid": 2000, "pid": 1337, "pc": "0x4010c8"},
          "event": "net_http",
          "server": "example.org",
          "port": 443,
          "proto": "https",
          "headers": "GET /stage HTTP/1.1\nHost: example.org\n"
        },
        {
          "pos": {"tick": 220, "tid": 2000, "pid": 1337, "pc": "0x4010d2"},
          "event": "exception",
          "instruction": "int 3",
          "exception_code": "0x80000003",
          "handler_address": "0x401500",
          "registers": {"eax": "0x0", "ebx": "0x0"},
          // File name of the module, the same as memory.modules[].name.
          "pc_module": "sample.exe",
          "pc_offset": 4306,
          "stack": [
            // region is the base of the region of value in memory.layout.
            {"offset": 0, "value": "0x401010", "region": "0x401000"},
            {"offset": 4, "value": "0x0"}
          ]
        }
      ],

      // Only with memory.accesses: the counts of the regions and the symbols.
      "accesses": {
        "regions": [
          // region is the base of the region in memory.layout.
          {"region": "0x401000", "reads": 10, "writes": 0, "execs": 400}
        ],
        "symbols": [
          // Only an access at the exact address of the symbol counts.
          {"symbol": "kernel32.LoadLibraryA", "reads": 0, "writes": 0, "execs": 1}
        ]
      },

      // Dynamic code regions where code ran, one entry for each region.
      "dynamic_code": [
        {
          "region": "0x10000000",
          "size": 4096,
          "tag": "api.VirtualAlloc",
          "contents": [
            {
              // Position when code first ran in the region.
              "pos": {"tick": 95, "tid": 2000, "pid": 1337, "pc": "0x10000000"},
              // Only with memory.dynamic_code_contents: the region contents at pos.
              "data_ref": "data-dyn-code"
            },
            {
              // Only with memory.dynamic_code_contents: the region when code
              // ran in it again after the region changed.
              "pos": {"tick": 310, "tid": 2000, "pid": 1337, "pc": "0x10000000"},
              "data_ref": "data-dyn-code-stage2"
            }
          ],
          // Only with memory.dynamic_code_contents: true if the region changed
          // and ran again after the snapshot limit.
          "limit_reached": false
        }
      ],

      // Only with code.coverage: sorted addresses of the instructions that ran.
      "coverage": ["0x401000", "0x401005", "0x40100a"],

      // User mode only: files that the guest wrote completely.
      "dropped_files": [
        {
          "path": "C:\\ProgramData\\drop.bin",
          "size": 4,
          "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
          // The same as sha256.
          "data_ref": "3333333333333333333333333333333333333333333333333333333333333333"
        }
      ],

      // User mode only: memory regions and modules at the end of the run.
      "memory": {
        "layout": [
          {
            // A section of the input image.
            "base": "0x401000",
            "size": 8192,
            "perms": "r-x",
            "tag": "emu.module",
            "module": "sample.exe",
            "section": ".text",
            // Only with memory.freed_regions.
            "freed": false,
            // Only with memory.final_contents, and only for guest memory.
            "data_ref": "data-region"
          },
          {
            // A section of a stub system module: no data_ref.
            "base": "0x77001000",
            "size": 57344,
            "perms": "r-x",
            "tag": "emu.module",
            "module": "kernel32.dll",
            "section": ".text",
            "freed": false
          },
          {
            // An allocation that the guest freed. The tag has no address.
            "base": "0x10000000",
            "size": 4096,
            "perms": "rwx",
            "tag": "api.VirtualAlloc",
            "freed": true,
            "data_ref": "data-dyn-code-stage2"
          },
          {
            // The stack: no data_ref.
            "base": "0x1200000",
            "size": 1048576,
            "perms": "rw-",
            "tag": "emu.stack",
            "freed": false
          }
        ],
        "modules": [
          {
            "name": "sample.exe",
            "path": "C:\\Windows\\System32\\sample.exe",
            "base": "0x400000",
            "size": 20480
          }
        ]
      }
    }
  ]
}
```

## Minimal report

This command emulates three bytes of x86 shellcode (`xor eax, eax; ret`) with all the report options off:

```console
printf '\x31\xc0\xc3' > ret.bin
speakeasy -t ret.bin --raw --arch x86 --no-memory-accesses --no-memory-strings --no-memory-final-contents \
  --no-memory-dynamic-code-contents --no-code-coverage --no-memory-freed-regions -o report.json
jq . report.json
```

This is the report. The real `memory.layout` has 355 regions and `memory.modules` has 53 modules. The example keeps only the shellcode and the stack in `layout` and the shellcode in `modules`.

```json
{
  "report_version": "7.0.0",
  "emulation_total_runtime": 0.001,
  "timestamp": 1794582170,
  "arch": "x86",
  "path": "ret.bin",
  "sha256": "251447ee91a9067dcd6ab96703133f617565974cd6c4819021760c4688c91abf",
  "size": 3,
  "file_type": "shellcode",
  "image_base": "0x10140",
  "errors": [],
  "data": {},
  "processes": [
    {
      "pid": 1240,
      "path": "C:\\Windows\\system32\\svchost.exe",
      "command_line": "svchost.exe",
      "runs": [
        0
      ]
    }
  ],
  "runs": [
    {
      "type": "shellcode",
      "start_address": "0x10140",
      "args": [
        "0x41420000",
        "0x41421000",
        "0x41422000",
        "0x41423000"
      ],
      "pid": 1240,
      "tid": 1444,
      "api_call_count": 0,
      "api_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "return_value": "0x0",
      "events": [],
      "dynamic_code": [],
      "dropped_files": [],
      "memory": {
        "layout": [
          {
            "base": "0x10140",
            "size": 3,
            "perms": "rwx",
            "tag": "emu.module",
            "module": "251447ee91a9067dcd6ab96703133f617565974cd6c4819021760c4688c91abf",
            "section": "shellcode"
          },
          {
            "base": "0x1200000",
            "size": 16384,
            "perms": "rw-",
            "tag": "emu.stack"
          }
        ],
        "modules": [
          {
            "name": "251447ee91a9067dcd6ab96703133f617565974cd6c4819021760c4688c91abf",
            "path": "",
            "base": "0x10140",
            "size": 3
          }
        ]
      }
    }
  ]
}
```

The report has no `strings`, `accesses`, `coverage` or `instruction_count`, because their options are off. The regions have no `freed` and no `data_ref` for the same reason. `errors`, `data`, `events`, `dynamic_code` and `dropped_files` are empty: Speakeasy collected them and found nothing. The shellcode called no API, so `api_call_count` is 0 and `api_hash` is the SHA-256 of no bytes. `return_value` is the value of `eax` after `xor eax, eax`.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [CLI execution controls](cli-execution-controls.md)
- [Memory management](memory.md)
- [Help and troubleshooting](help.md)
