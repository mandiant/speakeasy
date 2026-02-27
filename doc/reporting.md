# Report walkthrough

Source of truth:
- `speakeasy/report.py`
- `speakeasy/profiler_events.py`
- population logic in `speakeasy/profiler.py` and `speakeasy/windows/win32.py`

The examples use JSONC for explanation. Remove comments for machine parsing.

## How report fields are populated

- `report_version`: from `speakeasy.profiler.__report_version__`.
- `emulation_total_runtime`: profiler start/stop wall-clock duration.
- `timestamp`: profiler start time epoch seconds.
- `arch`, `filepath`, `sha256`, `size`, `filetype`: loader/input metadata.
- `errors`: top-level session errors recorded by profiler.
- `strings`: only present if string extraction is enabled and non-empty.
- `entry_points`: one per run (`Run` object) in execution order.

Entry-point highlights:
- `apihash`: SHA-256 over unique API names, lowercased, first-seen order.
- `events`: built by profiler recorders (`record_api_event`, `record_file_access_event`, `record_process_event`, `record_registry_access_event`, `record_dns_event`, `record_http_event`, `record_network_event`, `record_exception_event`).
- `sym_accesses`: populated from memory-tracing symbol counters.
- `dynamic_code_segments`: populated when dynamically mapped code executes.
- `coverage`: populated only if `analysis.coverage=true`.
- `dropped_files`: populated from filesystem manager fully-written files.
- `memory`: populated from run-end memory/module capture, with optional compressed region data when `capture_memory_dumps=true`.

## Annotated report schema example

```jsonc
{
  // Report format version.
  "report_version": "2.0.0",

  // Total wall-clock runtime in seconds.
  "emulation_total_runtime": 1.234,

  // Emulation start timestamp (epoch seconds).
  "timestamp": 1760000000,

  // Input metadata (may be null if unavailable in a custom flow).
  "arch": "x86",
  "filepath": "/samples/payload.bin",
  "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "size": 4096,
  "filetype": "exe",

  // Session-level errors, not tied to one entry point.
  "errors": [
    {
      "type": "top_level_error",
      "pc": "0x401000",
      "instr": "mov eax, [ecx]"
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

  "entry_points": [
    {
      // Execution primitive label.
      "ep_type": "module_entry",

      // Address where this run started.
      "start_addr": "0x401000",

      // Entry arguments, integers usually hex-encoded.
      "ep_args": ["0x1", "0x2"],

      // Process/thread context when known.
      "pid": 1337,
      "tid": 2000,

      // Total instructions executed by this run.
      "instr_count": 12345,

      // Hash over unique API names called in this run.
      "apihash": "2222222222222222222222222222222222222222222222222222222222222222",

      // Return value of the run entry point.
      "ret_val": "0x0",

      // Run-local error if abnormal termination occurred.
      "error": {
        "type": "unsupported_api",
        "pc": "0x401234",
        "instr": "call dword ptr [eax]"
      },

      // Unified chronological event stream.
      "events": [
        {
          "pos": {"tick": 10, "tid": 2000, "pid": 1337, "pc": 4198400},
          "event": "api",
          "api_name": "kernel32.LoadLibraryA",
          "args": ["ws2_32"],
          "ret_val": "0x78c00000"
        },
        {
          "pos": {"tick": 20, "tid": 2000, "pid": 1337, "pc": 4198410},
          "event": "process_create",
          "path": "C:\\Windows\\System32\\cmd.exe",
          "cmdline": "cmd.exe /c whoami"
        },
        {
          "pos": {"tick": 30, "tid": 2000, "pid": 4242, "pc": 4198420},
          "event": "mem_alloc",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "base": "0x10000000",
          "size": "0x1000",
          "protect": "PAGE_EXECUTE_READWRITE"
        },
        {
          "pos": {"tick": 40, "tid": 2000, "pid": 4242, "pc": 4198430},
          "event": "mem_write",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "base": "0x10000000",
          "size": 16,
          "data": "QUJDRA=="
        },
        {
          "pos": {"tick": 50, "tid": 2000, "pid": 4242, "pc": 4198440},
          "event": "mem_read",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "base": "0x10000000",
          "size": 16,
          "data": "QUJDRA=="
        },
        {
          "pos": {"tick": 60, "tid": 2000, "pid": 4242, "pc": 4198450},
          "event": "mem_protect",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "base": "0x10000000",
          "size": "0x1000",
          "protect": "PAGE_EXECUTE_READ"
        },
        {
          "pos": {"tick": 70, "tid": 2000, "pid": 4242, "pc": 4198460},
          "event": "mem_free",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "base": "0x10000000",
          "size": "0x1000"
        },
        {
          "pos": {"tick": 80, "tid": 2000, "pid": 1337, "pc": 4198470},
          "event": "module_load",
          "name": "wininet.dll",
          "path": "C:\\Windows\\System32\\wininet.dll",
          "base": "0x7bc00000",
          "size": "0x1a000"
        },
        {
          "pos": {"tick": 90, "tid": 2000, "pid": 4242, "pc": 4198480},
          "event": "thread_create",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "start_addr": "0x10000000",
          "param": "0x0"
        },
        {
          "pos": {"tick": 100, "tid": 2000, "pid": 4242, "pc": 4198490},
          "event": "thread_inject",
          "path": "C:\\Windows\\System32\\notepad.exe",
          "start_addr": "0x10000000",
          "param": "0x0"
        },
        {
          "pos": {"tick": 110, "tid": 2000, "pid": 1337, "pc": 4198500},
          "event": "file_create",
          "path": "C:\\ProgramData\\drop.bin",
          "handle": "0x80",
          "open_flags": ["CREATE_ALWAYS"],
          "access_flags": ["GENERIC_WRITE"]
        },
        {
          "pos": {"tick": 120, "tid": 2000, "pid": 1337, "pc": 4198510},
          "event": "file_open",
          "path": "C:\\ProgramData\\drop.bin",
          "handle": "0x84",
          "open_flags": ["OPEN_EXISTING"],
          "access_flags": ["GENERIC_READ"]
        },
        {
          "pos": {"tick": 130, "tid": 2000, "pid": 1337, "pc": 4198520},
          "event": "file_read",
          "path": "C:\\ProgramData\\drop.bin",
          "handle": "0x84",
          "size": 4,
          "data": "QUJDRA==",
          "buffer": "0x120000"
        },
        {
          "pos": {"tick": 140, "tid": 2000, "pid": 1337, "pc": 4198530},
          "event": "file_write",
          "path": "C:\\ProgramData\\drop.bin",
          "handle": "0x80",
          "size": 4,
          "data": "QUJDRA==",
          "buffer": "0x130000"
        },
        {
          "pos": {"tick": 150, "tid": 2000, "pid": 1337, "pc": 4198540},
          "event": "reg_open_key",
          "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft",
          "handle": "0x180",
          "open_flags": ["REG_OPTION_NON_VOLATILE"],
          "access_flags": ["KEY_READ"]
        },
        {
          "pos": {"tick": 160, "tid": 2000, "pid": 1337, "pc": 4198550},
          "event": "reg_create_key",
          "path": "HKEY_CURRENT_USER\\Software\\Lab",
          "handle": "0x184",
          "open_flags": ["REG_OPTION_NON_VOLATILE"],
          "access_flags": ["KEY_WRITE"]
        },
        {
          "pos": {"tick": 170, "tid": 2000, "pid": 1337, "pc": 4198560},
          "event": "reg_read_value",
          "path": "HKEY_CURRENT_USER\\Software\\Lab",
          "handle": "0x184",
          "value_name": "Config",
          "size": 4,
          "data": "QUJDRA==",
          "buffer": "0x140000"
        },
        {
          "pos": {"tick": 180, "tid": 2000, "pid": 1337, "pc": 4198570},
          "event": "reg_list_subkeys",
          "path": "HKEY_CURRENT_USER\\Software",
          "handle": "0x184"
        },
        {
          "pos": {"tick": 190, "tid": 2000, "pid": 1337, "pc": 4198580},
          "event": "net_dns",
          "query": "example.org",
          "response": "93.184.216.34"
        },
        {
          "pos": {"tick": 200, "tid": 2000, "pid": 1337, "pc": 4198590},
          "event": "net_traffic",
          "server": "93.184.216.34",
          "port": 443,
          "proto": "tcp",
          "type": "connect",
          "data": "QUJDRA==",
          "method": "winsock.connect"
        },
        {
          "pos": {"tick": 210, "tid": 2000, "pid": 1337, "pc": 4198600},
          "event": "net_http",
          "server": "example.org",
          "port": 443,
          "proto": "tcp.https",
          "headers": "GET /stage HTTP/1.1\nHost: example.org\n",
          "body": null
        },
        {
          "pos": {"tick": 220, "tid": 2000, "pid": 1337, "pc": 4198610},
          "event": "exception",
          "instr": "int 3",
          "exception_code": "0x80000003",
          "handler_address": "0x401500",
          "registers": {"eax": "0x0", "ebx": "0x0"}
        }
      ],

      // Symbol-level R/W/X counts, typically from memory tracing.
      "sym_accesses": [
        {
          "symbol": "kernel32.LoadLibraryA",
          "reads": 1,
          "writes": 0,
          "execs": 1
        }
      ],

      // Dynamic code segments that executed.
      "dynamic_code_segments": [
        {
          "tag": "emu.alloc.0x10000000",
          "base": "0x10000000",
          "size": "0x1000"
        }
      ],

      // Instruction addresses executed when coverage is enabled.
      "coverage": [4198400, 4198405, 4198410],

      // Files fully written during the run.
      "dropped_files": [
        {
          "path": "C:\\ProgramData\\drop.bin",
          "data": "QUJDRA==",
          "sha256": "3333333333333333333333333333333333333333333333333333333333333333"
        }
      ],

      "memory": {
        "layout": [
          {
            "tag": "emu.module.main..text.0x401000",
            "address": "0x401000",
            "size": "0x2000",
            "prot": "r-x",
            "is_free": false,
            "accesses": {
              "reads": 10,
              "writes": 0,
              "execs": 400
            },

            // Optional: base64(zlib(raw_region_bytes)).
            "data": "eJw="
          }
        ],
        "modules": [
          {
            "name": "sample.exe",
            "path": "C:\\Windows\\System32\\sample.exe",
            "base": "0x400000",
            "size": "0x5000",
            "segments": [
              {
                "name": ".text",
                "address": "0x401000",
                "size": "0x2000",
                "prot": "r-x"
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
  "report_version": "2.0.0",
  "emulation_total_runtime": 0.012,
  "timestamp": 1760000000,
  "arch": "x86",
  "filepath": "/samples/minimal.bin",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "size": 1234,
  "filetype": "exe",
  "entry_points": [
    {
      "ep_type": "module_entry",
      "start_addr": "0x401000",
      "ep_args": [],
      "apihash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

## Minimal output report with interpretation comments

```jsonc
{
  // Report schema version.
  "report_version": "2.0.0",

  // Total runtime in seconds for this emulation session.
  "emulation_total_runtime": 0.012,

  // Emulation start time (epoch seconds).
  "timestamp": 1760000000,

  // Input metadata captured at load time.
  "arch": "x86",
  "filepath": "/samples/minimal.bin",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "size": 1234,
  "filetype": "exe",

  "entry_points": [
    {
      // This run started at the module entrypoint.
      "ep_type": "module_entry",

      // Entry virtual address where execution began.
      "start_addr": "0x401000",

      // No explicit entry args in this minimal case.
      "ep_args": [],

      // SHA-256 of unique API names called in order.
      // e3b0... means no API events were recorded for this run.
      "apihash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```
