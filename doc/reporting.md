# Report walkthrough

The report models are in `speakeasy/report.py` and `speakeasy/profiler_events.py`. `speakeasy/profiler.py` builds the report from the data that the emulator records in `speakeasy/windows/winemu.py`, `win32.py` and `kernel.py`.

`speakeasy/resources/report.schema.json` is the JSON schema of the report, and the package includes it. After you change a report model, run `just gen-report-schema`. The models reject unknown keys.

For the changes from the 1.x report, see [Migrating to 2.0](migrating-to-2.0.md#report-schema-600).

`get_json_report()` and the CLI write compact JSON, with no indentation and no line breaks. To indent a report, use `jq . report.json`.

The examples on this page are JSONC: JSON with comments that explain the fields. Remove the comments before you parse an example as JSON.

## Report fields

If Speakeasy did not collect the data of a key, the report leaves out the key, for example `coverage` when `code.coverage=false`. By default, Speakeasy collects all the data that this page describes. An empty list or object means that Speakeasy collected the data and found nothing.

The report writes each machine word as a hex string with a `0x` prefix and lowercase digits. Machine words are addresses, pointers, handles, raw argument values, return values, register values, exception codes and coverage addresses. A 64-bit word can be above 2\*\*53 or 2\*\*63. JavaScript, Go `interface{}`, jq and int64 stores such as SQLite lose such a value when it is a JSON number, and they give no error. In Python, `int(value, 16)` reads the string. The schema gives the pattern `^0x[0-9a-f]+$` for each hex string. The report writes each quantity, such as a size, a count, an offset, a tick or an ID, as a JSON number.

`report_version` is the value of `speakeasy.report.REPORT_VERSION`. `timestamp` is the Unix time in seconds of the first start of the run queue, and `emulation_total_runtime` is the wall-clock time in seconds from that start to the end of the emulation. A `call()` after `run_module()` and each child process start the run queue again, and the time to the last end counts. The other top-level fields are:

- `arch` (`x86` or `x64`), `path`, `sha256`, `size`, `file_type` (`exe`, `dll`, `driver` or `shellcode`) and `image_base`: the input metadata that the loader records. `path` is the host path of the input file. If the input came from bytes in memory, the report has no `path`.
- `errors`: the errors of the session that do not belong to one run. If the input PE has a defect, for example an entry point outside the image or an import descriptor that the Windows loader cannot resolve, the loader adds an `invalid_image` error with the defect in `context_summary`, and emulation continues. `PeLoader` in `speakeasy/windows/loaders.py` has the checks. If `limits.total_time` runs out before all child processes run, the emulator adds a `max_total_time` error with the number of child processes that did not run in `context_summary`.
- `strings`: the strings from the input file and from memory, only if `memory.strings=true`. `static` has the strings of the input file. `in_memory` has the strings at the end of the emulation that are not in `static`. Speakeasy reads them from the stack, from the memory that API handlers allocate, and from the images of the guest modules. In an image, it reads only the strings that the guest changed after the load, for example the strings that an unpacker decodes in place.
- `data`: the payloads that the report stores once, keyed by SHA-256. Each `data_ref` field holds a key of `data`.
- `runs`: a list of the runs (`Run` objects), in the order that the runs started.

Each entry point has these fields:

- `api_hash`: the SHA-256 of the lowercase names of the APIs that the run called, each name once, in the order of the first call.
- `events`: the events of the run, in order. The `record_*_event` methods of `Profiler` add them.
- `symbol_accesses`: the read, write and execute counts of each symbol, only if `memory.accesses=true`.
- `dynamic_code_segments`: the memory regions with dynamic code, for example from `VirtualAlloc`, where code ran. Each region has `pos`, the position when the emulator first found code that ran in the region. The emulator finds the code when it runs in the first 16 bytes of the region, or when an API returns into the region. If `memory.dynamic_code_contents.enabled=true`, each region also has a `data_ref` to its contents at `pos`, so the report keeps a stage that the guest overwrites later. The emulator then also watches the region for writes. When the region changed and control comes into it from outside, for example with a call or an API return, the emulator adds one more entry for the region, with the same `tag`, `base` and `size` and its own `pos` and `data_ref`. The list is in the order of `pos.tick`, and with snapshots `pos.tick` is always the instruction count of the run. Each entry of a region has different data from the entry of the region before it. A decoder loop in the region gives no snapshot for each pass, because its blocks do not come from outside the region. `memory.dynamic_code_contents.limit` (default 8) is the maximum number of snapshots of a region in a run, with the first one. `snapshot_limit_reached` is true on the last entry of a region when the region changed and ran again after the last snapshot that the limit allows, and it is absent on the other entries. The report does not have a stage that the region decodes and runs before control leaves the region. Each write in the region counts, also a write to data. A region that holds an unpacked image with its global variables can get a snapshot after most API calls, and it gets to the limit fast.
- `coverage`: the addresses of the instructions that ran, only if `code.coverage=true`.
- `dropped_files`: in user mode, the files that the guest wrote completely, up to the end of the run. The list also has the files that the guest wrote and then deleted.
- `memory`: in user mode, the memory regions and the modules at the end of the run. If `memory.final_contents=true`, each region also has a `data_ref` to its contents, except the stacks.

If the run ended abnormally, the entry point has an `error`. Its `type` is an identifier such as `invalid_read`, `unsupported_api` or `timeout`. The report schema lists all values. A run that `max_api_calls` ends has `max_api_count`. A run that makes `max_api_loop_calls` API calls with no call from a new call site has `api_loop`, and `error.loop` tells about the calls after the last new call site. In `error.loop`, `start` is the position of the first of these calls, `calls` is their number, and `sites` has up to 16 call sites (`api_name`, `return_address` and `calls`), the site with the most calls first. For both types, `count` is the limit and `last_api` is the API of the last call. A Python exception in Speakeasy itself, such as a bug in an API handler, gives `internal_error`, with the exception text in `message` and the Python traceback in `traceback`.

The `type` of an entry point is the kind of code that the run executes, and `name` is a detail for that kind. If the kind has no detail (`None` in Python), the JSON report leaves out `name`.

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

`VirtualFree` adds a `mem_free` event. `LoadLibrary`, `LoadLibraryEx` and `LdrLoadDll` add a `module_load` event for each module that the load maps, the dependencies of the module included. A module that the config preloads, or that is already loaded, gets no event.

## API arguments and handles

An `api` event records its arguments in `args`, a list of objects with `name`, `type`, `value` and `display`. If the signature database declares the function, and its prototype uses the same argument slots as the call, `args` has an entry per parameter. Then `name` is the parameter name, and Speakeasy renders `display` from the declared type. It decodes strings, shows enum and flag values as names and expands struct pointers. Without a usable signature, `args` has one entry for each argument slot, with no `name`, and `display` is the hex value. `type` tells you how to read `display`.

| Type | `display` |
|---|---|
| `int` | hex integer |
| `ptr` | address in hex (also null, out-only and unreadable pointers) |
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

Each event has `pos`, the position of the thread that did the operation, so the event is in the timeline of that thread. The events about a process, its memory or its threads (`mem_alloc`, `mem_write`, `mem_read`, `mem_protect`, `mem_free`, `thread_create`, `thread_inject` and `process_create`) also have the `pid` of the target process. If the target is the process of that thread, the event has no `pid`. So a `pid` in these events means that the operation crossed a process boundary. `thread_create` and `thread_inject` have the `tid` of the new thread, also when the thread is in the same process.

## Report fields and CLI flags

The boolean flags in this list are on by default. The `--no-` form of each flag removes its data from the report.

- `--memory-strings` controls the top-level `strings` ([recipe](cli-analysis-recipes.md#recipe-memory-strings)).
- `--code-coverage` fills `runs[*].coverage` ([recipe](cli-analysis-recipes.md#recipe-code-coverage)).
- `--memory-accesses` fills `runs[*].symbol_accesses` and `runs[*].memory.layout[*].accesses` ([recipe](cli-analysis-recipes.md#recipe-memory-accesses)).
- `--memory-final-contents` fills `runs[*].memory.layout[*].data_ref` ([recipe](cli-analysis-recipes.md#recipe-memory-snapshots)).
- `--memory-dynamic-code-contents` fills `runs[*].dynamic_code_segments[*].data_ref` and `snapshot_limit_reached`, and adds an entry for each later snapshot of a region. `--memory-dynamic-code-contents-limit` sets the maximum number of snapshots of each region.
- `runs[*].dropped_files[*].data_ref` holds a key of the top-level `data`. A file above `MAX_EMBEDDED_FILE_SIZE` (`speakeasy/artifacts.py`) has no `data_ref`. To also write the dropped files to an archive, use `--dropped-files-path` ([recipe](cli-analysis-recipes.md#recipe-dropped-files)).

## Annotated report schema example

```jsonc
{
  // Report format version.
  "report_version": "6.2.0",

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

  // Session-level errors, not tied to one entry point.
  "errors": [
    {
      "type": "invalid_image",
      "context_summary": "entry point RVA 0x5000 is outside the image (size 0x4000)"
    }
  ],

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

  "data": {
    "data-region": {"compression": "zlib", "encoding": "base64", "size": 1, "data": "eJw="}
  },

  "runs": [
    {
      // Kind of code that this run executes. A module_entry run has no name.
      "type": "module_entry",

      // Address where this run started.
      "start_address": "0x401000",

      // Entry arguments.
      "args": ["0x1", "0x2"],

      // Process/thread context when known.
      "pid": 1337,
      "tid": 2000,

      // Total instructions executed by this run.
      "instruction_count": 12345,

      // Hash over unique API names called in this run.
      "api_hash": "2222222222222222222222222222222222222222222222222222222222222222",

      // Return value of the run entry point.
      "return_value": "0x0",

      // Run-local error if abnormal termination occurred.
      "error": {
        "type": "unsupported_api",
        "pc": "0x401234",
        "instruction": "call dword ptr [eax]",
        "registers": {"eax": "0x403000", "esp": "0x12ff70"},
        "tid": 2000,
        "pid": 1337
      },

      // Unified chronological event stream.
      "events": [
        {
          "pos": {"tick": 10, "tid": 2000, "pid": 1337, "pc": "0x401000"},
          "event": "api",
          "api_name": "kernel32.LoadLibraryA",
          // "name" is present when the API signature is known.
          "args": [{"name": "lpLibFileName", "type": "str", "value": "0x40308c", "display": "ws2_32"}],
          "return_value": "0x78c00000"
        },
        {
          "pos": {"tick": 20, "tid": 2000, "pid": 1337, "pc": "0x40100a"},
          "event": "process_create",
          "path": "C:\\Windows\\System32\\cmd.exe",
          "command_line": "cmd.exe /c whoami",
          "pid": 4200
        },
        {
          // Cross-process: the actor (pid 1337) allocates inside pid 4242.
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
          // Local: no pid payload, so the target is the actor's own process.
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
          "pos": {"tick": 80, "tid": 2000, "pid": 1337, "pc": "0x401046"},
          "event": "module_load",
          "name": "urlmon",
          "path": "C:\\Windows\\system32\\urlmon.dll",
          "base": "0x6f000000",
          "size": 94208
        },
        {
          // Local thread creation keeps the new tid but carries no pid payload.
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
          "type": "connect",
          "data_ref": "data-net-traffic",
          "method": "winsock.connect"
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
          "pc_module": "sample.exe",
          "pc_offset": 4306,
          "stack": [
            {"offset": 0, "value": "0x401010", "tag": "emu.module.sample.exe.0x400000"},
            {"offset": 4, "value": "0x0"}
          ]
        }
      ],

      // Symbol-level R/W/X counts, only with memory.accesses.
      "symbol_accesses": [
        {
          "symbol": "kernel32.LoadLibraryA",
          "reads": 1,
          "writes": 0,
          "execs": 1
        }
      ],

      // Dynamic code segments that executed, in tick order.
      "dynamic_code_segments": [
        {
          "tag": "emu.alloc.0x10000000",
          "base": "0x10000000",
          "size": 4096,
          // Position when code first ran in the region.
          "pos": {"tick": 95, "tid": 2000, "pid": 1337, "pc": "0x10000000"},
          // Only with memory.dynamic_code_contents: the region contents at pos.
          "data_ref": "data-dyn-code"
        },
        {
          // Only with memory.dynamic_code_contents: the same region, when code
          // ran in it again after the region changed.
          "tag": "emu.alloc.0x10000000",
          "base": "0x10000000",
          "size": 4096,
          "pos": {"tick": 310, "tid": 2000, "pid": 1337, "pc": "0x10000000"},
          "data_ref": "data-dyn-code-stage2",
          // Only on the last entry of a region, if the region changed and ran
          // again after the snapshot limit.
          "snapshot_limit_reached": true
        }
      ],

      // Instruction addresses executed when coverage is enabled.
      "coverage": ["0x401000", "0x401005", "0x40100a"],

      // Files fully written during the run.
      "dropped_files": [
        {
          "path": "C:\\ProgramData\\drop.bin",
          "size": 4,
          "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
          "data_ref": "3333333333333333333333333333333333333333333333333333333333333333"
        }
      ],

      "memory": {
        "layout": [
          {
            "tag": "emu.module.main..text.0x401000",
            "base": "0x401000",
            "size": 8192,
            "perms": "r-x",
            "is_free": false,
            "accesses": {
              "reads": 10,
              "writes": 0,
              "execs": 400
            },

            // Optional: resolve via the top-level data store.
            "data_ref": "data-region"
          }
        ],
        "modules": [
          {
            "name": "sample.exe",
            "path": "C:\\Windows\\System32\\sample.exe",
            "base": "0x400000",
            "size": 20480,
            "segments": [
              {
                "name": ".text",
                "base": "0x401000",
                "size": 8192,
                "perms": "r-x"
              }
            ]
          }
        ]
      }
    }
  ]
}
```

## Minimal output report (valid JSON)

```json
{
  "report_version": "6.2.0",
  "emulation_total_runtime": 0.012,
  "timestamp": 1760000000,
  "arch": "x86",
  "path": "/samples/minimal.bin",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "size": 1234,
  "file_type": "exe",
  "image_base": "0x400000",
  "runs": [
    {
      "type": "module_entry",
      "start_address": "0x401000",
      "args": [],
      "api_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

## Minimal output report with interpretation comments

```jsonc
{
  // Report schema version.
  "report_version": "6.2.0",

  // Total runtime in seconds for this emulation session.
  "emulation_total_runtime": 0.012,

  // Emulation start time (epoch seconds).
  "timestamp": 1760000000,

  // Input metadata captured at load time.
  "arch": "x86",
  "path": "/samples/minimal.bin",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "size": 1234,
  "file_type": "exe",
  "image_base": "0x400000",

  "runs": [
    {
      // This run started at the module entrypoint. A module_entry run has no name.
      "type": "module_entry",

      // Entry virtual address where execution began.
      "start_address": "0x401000",

      // No explicit entry args in this minimal case.
      "args": [],

      // SHA-256 of unique API names called in order.
      // e3b0... means no API events were recorded for this run.
      "api_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [CLI execution controls](cli-execution-controls.md)
- [Memory management](memory.md)
- [Help and troubleshooting](help.md)
