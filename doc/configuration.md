# Configuration walkthrough

`speakeasy/config.py` defines the config fields and their defaults. `speakeasy --dump-default-config` prints the default config. The example below shows the fields with comments. It is JSONC (JSON with comments), so remove the comments before you give it to Speakeasy.

The config has these groups: `limits`, `runs`, `memory`, `code`, `apis`, `modules`, `exceptions`, `system`, `user`, `process`, `processes`, `filesystem`, `registry` and `network`. Each group is an object, except `processes`, which is a list. No group accepts `null`. To turn off the registry keys, the DNS answers, the HTTP responses or the Winsock responses, give an empty list, for example `"registry": {"keys": []}` or `"network": {"http": {"responses": []}}`.

By default, Speakeasy collects all the data that it can and emulates as much of the sample as it can, so all the [feature options](#feature-options) are on. Set an option to `false`, or use its `--no-` flag, to turn a feature off. A run with fewer features is faster and gives a smaller report.

Addresses and sizes (`base_addr`, `runs.stack_size`, `byte_fill.size`) are ints of 0 or more. JSON has no hex numbers, so these fields also take a string that starts with `0x`, such as `"0x400000"`. `--dump-default-config` writes each `base_addr` as a `0x` string.

Speakeasy checks the values of the config before the emulation starts. A value that is not valid gives a `ConfigError` in the library, and a usage error with exit status 2 in the CLI.

```jsonc
{
  // Schema version. Speakeasy 2.0 reads only "2.0" and gives a ConfigError for
  // other values, such as the 0.2 of Speakeasy 1.x configs. Leave it out to use "2.0".
  "config_version": "2.0",

  // Emulation engine. The only value is "unicorn".
  "emu_engine": "unicorn",

  // Limits of the runs. 0 means "no limit" for each of them. A negative value
  // gives a ConfigError.
  "limits": {
    // Limit of the execution time of each run, in seconds.
    // At the limit, the emulator ends the run with a per_run_time_limit error.
    // Increase it for slow samples. Decrease it for quick triage.
    "per_run_time": 60,

    // Limit of the execution time of all runs of one run_module, run_shellcode,
    // call or resume call, in seconds.
    // At the limit, the emulator ends the current run with a total_time_limit error
    // and cancels the other runs.
    "total_time": 0,

    // Limit of the API calls of each run. A run that makes more API calls ends
    // with an api_call_limit error. It stops a loop that calls APIs from new call
    // sites in each iteration, which api_loop_calls does not stop.
    "api_calls": 10000,

    // Limit of the API calls of a run with no call from a new call site. A call
    // site is an API and a return address. A run that gets to the limit ends
    // with an api_loop_limit error, and error.loop of the report names the call sites
    // of the loop. Increase it to see more of a loop. 0 disables it.
    "api_loop_calls": 5000,

    // Limit of the instructions of each run.
    // The emulator stops a run at the limit and records an instruction_limit error.
    "instructions": 0
  },

  // The runs that the emulator starts.
  "runs": {
    // If true, run_module also runs the exports of the PE input. For a driver,
    // it also sends IRPs to the dispatch functions and runs the unload routine.
    "exports": true,

    // If true, the emulator runs the processes that the PE input starts, after
    // the input finishes. Kernel mode ignores it.
    "children": true,

    // Size in bytes of the stack that the emulator allocates for the input.
    // 0 uses the stack size of the input: max(SizeOfStackReserve, 0x12000) for a
    // PE, or the stack_commit argument of run_shellcode (default 0x4000).
    // Set it, for example to 0x100000 (1 MiB), for a sample that uses a large stack.
    "stack_size": 0
  },

  "memory": {
    // Count the reads, writes and executes of each symbol, section and memory map
    // in the report. Use it to examine unpackers, PEB walks and import resolvers.
    // It makes the run slower, mostly for samples that access much memory.
    "accesses": true,

    // Add the strings of the input file and the strings that the guest decoded
    // in memory to the report.
    // Set it to false to make the emulation faster when you do not need the strings.
    "strings": true,

    // Add the contents of each region of guest memory at the end of each run
    // to the report: the images of the modules that load from a file, the
    // allocations and heaps of the guest, the memory that API handlers allocate
    // for it, and its static TLS data. The stacks, the stub images of the system
    // modules and the other memory of the emulator get no contents. Only in
    // user mode.
    // The report keeps each content one time in its top-level data store.
    // The report is larger, but you do not need the emulator to examine the memory.
    "final_contents": true,

    "dynamic_code_contents": {
      // Add the contents of each dynamic code region, for example from VirtualAlloc,
      // to the report at the first time that code runs in the region, and again
      // each time that code runs in it after the region changes.
      // Use it to keep the stages of an unpacker that overwrites its buffers.
      // Each snapshot needs the instruction count. If memory.accesses is off and
      // limits.instructions is 0, the emulator adds a hook that counts each
      // instruction, which makes tight loops about two times slower.
      "enabled": true,

      // The maximum number of snapshots of each dynamic code region in one run,
      // with the first snapshot. It stops a sample that changes a region in a loop.
      "limit": 8
    },

    // Keep a freed region mapped, so you can read
    // the data that the sample freed. The guest can then also read and write the
    // region after the free without a fault, which is different from Windows.
    // Each region in the report then has "freed". If false, the report leaves
    // out the freed regions.
    "freed_regions": true
  },

  "code": {
    // Record the address of each instruction that a run executes.
    // Use it to compare runs or to see which code ran.
    "coverage": true
  },

  "apis": {
    // If true, an API that has no handler and no entry in the signature database
    // resolves to a stub. The stub takes 4 stdcall arguments and returns 1.
    // An API with an entry in the signature database always uses that entry
    // (see api-handlers.md). If false, a call to an API that has no handler and no
    // entry ends the run with an unsupported_api error, so the report names the API.
    "stubs": true
  },

  "modules": {
    // If true, when the guest loads an unknown module, the emulator creates an
    // empty synthetic API module. If false, the load fails, as on Windows.
    "stubs": true,

    // Directories of native DLLs, by architecture. If a directory has a file
    // with the name of a module, the emulator loads that file in place of the
    // synthetic API module. null uses the synthetic API modules.
    "directory_x86": null,
    "directory_x64": null,

    // User mode modules that the emulator loads at their base_addr.
    // The path of each user and system module is a file that exists, so
    // CreateFile opens it and FindFirstFile lists it. The file has no content.
    "user": [
      {
        "name": "ntdll",
        "base_addr": "0x7C000000",
        "path": "C:\\Windows\\system32\\ntdll.dll"
      },
      {
        "name": "kernel32",
        "base_addr": "0x77000000",
        "path": "C:\\Windows\\system32\\kernel32.dll"
      }
    ],

    // Kernel mode modules.
    "system": [
      {
        "name": "ntoskrnl",
        "base_addr": "0x803D0000",
        "path": "C:\\Windows\\system32\\ntoskrnl.exe",

        // Optional driver object and device objects of the module, in the
        // object manager namespace.
        "driver": {
          "name": "\\Driver\\ntoskrnl",
          "devices": [
            {
              "name": "\\Device\\HarddiskVolume1"
            }
          ]
        }
      }
    ]
  },

  "exceptions": {
    // Send CPU exceptions to the VEH and SEH handlers of the guest
    // (see exceptions.md). If false, a fault ends the run, so you can
    // find the fault more easily.
    "dispatch": true
  },

  "system": {
    "os_ver": {
      // The only value is "windows".
      "name": "windows",

      // The version that the PEB, KUSER_SHARED_DATA and the version functions,
      // such as GetVersionEx and RtlGetVersion, give. For 6.1, 6.2, 6.3 and 10.0,
      // the emulator also sets the values of
      // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
      // A value for that key in registry.keys replaces the value of the emulator.
      // Set the version that your sample expects.
      "major": 6,
      "minor": 1,

      // Build number that the version functions give.
      "build": 7601
    },

    // Host name, for example for GetComputerName.
    "hostname": "WIN7-LAB",

    // Domain or workgroup of the user, for example for LookupAccountName.
    // Set it to match the domain that the sample expects.
    "domain": "LAB",

    // System time when emulation starts, in ISO 8601 with a time zone.
    // The system time, the file times, the msvcrt time functions, timeGetTime,
    // KUSER_SHARED_DATA and the kernel-mode system time count from it.
    // The emulated system booted one day before this time. In user mode, each
    // time query and each Sleep or wait moves the clock forward. In kernel mode,
    // only the system time queries move it. The time fields of KUSER_SHARED_DATA
    // change only when an API moves the clock, so a loop that only reads them
    // does not see time pass.
    // The default is fixed so that runs give the same times to the sample.
    "start_time": "2026-10-31T15:15:00Z",

    // Seed of the random number generator of the random APIs, such as
    // RtlGenRandom and CoCreateGuid.
    // Runs with the same seed give the same random bytes and GUIDs to the sample.
    "random_seed": 0,

    // Drives that the drive APIs, such as GetLogicalDrives, give.
    // drive_type is the value that GetDriveType gives: DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR,
    // DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_REMOTE, DRIVE_CDROM or DRIVE_RAMDISK. A drive with no
    // drive_type gives DRIVE_UNKNOWN.
    "drives": [
      {
        "root_path": "C:\\",
        "drive_type": "DRIVE_FIXED",
        "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000001}\\"
      },
      {
        "root_path": "D:\\",
        "drive_type": "DRIVE_CDROM",
        "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000002}\\"
      }
    ],

    // Symbolic links of the object manager. The emulator uses them to resolve device paths.
    "symlinks": [
      {
        "name": "\\??\\C:",
        "target": "\\Device\\HarddiskVolume1"
      },
      {
        "name": "\\??\\PhysicalDrive0",
        "target": "\\Device\\Harddisk0\\DR0"
      }
    ]
  },

  "user": {
    // User name, for example for GetUserName.
    "name": "analyst",

    // If true, the token of the user is elevated and has a high integrity level.
    "admin": true,

    // SID of the user.
    "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001"
  },

  // The process in which the input runs.
  "process": {
    // Command line of the process, for example for GetCommandLine and the argv
    // that the CRT gives to main. null gives the quoted path of the process image
    // followed by argv, for example "C:\Windows\system32\sample.exe" -x.
    // For a DLL or shellcode input, the process image is the container image,
    // and null gives the command_line of the is_main_exe entry if it has one.
    // Speakeasy gives a ConfigError if you set it together with argv.
    "command_line": null,

    // Current directory of the process. The emulator resolves relative paths from it.
    // It also gives CurrentDirectory in the PEB ProcessParameters.
    "current_dir": "C:\\Windows\\system32",

    // Environment variables of the process. Change them when a sample selects
    // paths or detects sandboxes from the environment.
    // Names are not case-sensitive, and the config stores them in lower case.
    // programfiles and commonprogramfiles also give the ProgramFilesDir and CommonFilesDir
    // values of HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion. A value for that
    // key in registry.keys replaces the value of the environment.
    // systemroot also gives NtSystemRoot in KUSER_SHARED_DATA.
    // The shell folder APIs, such as SHGetKnownFolderPath and SHGetFolderPath, give
    // paths under systemdrive, userprofile, appdata, localappdata, allusersprofile,
    // public, programfiles and windir. When env does not have one of these, the APIs
    // use its Windows default under userprofile or systemdrive.
    "env": {
      "comspec": "C:\\Windows\\system32\\cmd.exe",
      "systemroot": "C:\\Windows",
      "windir": "C:\\Windows",
      "temp": "C:\\Windows\\temp",
      "userprofile": "C:\\Users\\analyst"
    }
  },

  // Processes that the process enumeration APIs give, in this order, then the
  // main process.
  // path and command_line give ImagePathName and CommandLine in the PEB
  // ProcessParameters of the process.
  // The is_main_exe entry defines the container image, which is the main image
  // of the process when the input is a DLL or shellcode (see architecture.md).
  // The emulator ignores the base_addr of this entry and loads the container image
  // at the first free base above 0x7D000000.
  // The container process gets the session of the entry, but not its pid.
  // When process.command_line is null, the container process gets the
  // command_line of the entry. Speakeasy gives a ConfigError if you set it
  // together with argv.
  // The pid of an entry is the process ID that the guest and the report use.
  // Speakeasy gives an entry without pid a free process ID of 0x400 or more.
  // In kernel mode, the System process always has pid 4.
  "processes": [
    {
      "name": "System",
      "base_addr": "0x80000000",
      "pid": 4,
      "path": "[System Process]",
      "command_line": null,
      "is_main_exe": false,
      "session": 0
    },
    {
      "name": "main",
      "base_addr": "0x00400000",
      "path": "C:\\Windows\\system32\\svchost.exe",
      "pid": 1337,
      "command_line": "svchost.exe -k netsvcs",
      "is_main_exe": true,
      "session": 1
    }
  ],

  "filesystem": {
    "files": [
      {
        // full_path matches the full path of the file.
        "mode": "full_path",

        // Path in the emulated file system. It can have wildcards, such as *.
        "emu_path": "c:\\programdata\\seed\\config.bin",

        // Host file that gives the content of the file.
        // $ROOT$ is the directory of the installed speakeasy package.
        // Each entry has path or byte_fill, but not both.
        "path": "$ROOT$/resources/files/default.bin"
      },
      {
        "mode": "full_path",
        "emu_path": "c:\\programdata\\seed\\padding.bin",

        // Content that the emulator makes, in place of a host file.
        "byte_fill": {
          // Byte that fills the content, in hex: "00" to "ff", or "0x00" to "0xff".
          "byte": "0x41",
          // Size of the content in bytes.
          "size": 512
        }
      },
      {
        // by_ext matches all paths with this extension, if no full_path entry matches.
        "mode": "by_ext",
        "ext": "txt",
        "path": "$ROOT$/resources/files/default.bin"
      },
      {
        // default matches all paths, if no full_path or by_ext entry matches.
        "mode": "default",
        "path": "$ROOT$/resources/files/default.bin"
      }
    ]
  },

  // Registry keys and values that exist when emulation starts.
  // An empty keys list gives a registry without config keys.
  "registry": {
    "keys": [
      {
        "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "values": [
          {
            // Value name. "default" is the unnamed default value.
            "name": "Updater",
            // Value type: REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_BINARY, REG_DWORD or REG_QWORD.
            "type": "REG_SZ",
            // Data as a string. REG_DWORD and REG_QWORD data is a number, such as "3" or "0x3".
            // REG_MULTI_SZ data separates the strings with "\u0000".
            "data": "C:\\ProgramData\\updater.exe"
          }
        ]
      }
    ]
  },

  "network": {
    "dns": {
      // IP address of each domain name. "default" gives the address of all other names.
      // An empty mapping gives no address for any name.
      "names": {
        "default": "10.10.10.10",
        "example.org": "93.184.216.34"
      },

      // Host files that give the TXT record of a domain name.
      "txt": [
        {
          // TXT record of one domain name.
          "name": "bootstrap.example.org",
          "path": "$ROOT$/resources/web/default.bin"
        },
        {
          // TXT record of all other names.
          "name": "default",
          "path": "$ROOT$/resources/web/default.bin"
        }
      ]
    },

    "http": {
      // An empty responses list gives no HTTP response data.
      "responses": [
        {
          // HTTP verb of the requests that these files answer: GET, POST or HEAD.
          // by_ext matches the extension of the URL path.
          "verb": "GET",
          "files": [
            {
              "mode": "by_ext",
              "ext": "gif",
              "path": "$ROOT$/resources/web/decoy.gif"
            },
            {
              "mode": "default",
              "path": "$ROOT$/resources/web/default.bin"
            }
          ]
        },
        {
          "verb": "POST",
          "files": [
            {
              "mode": "default",
              "path": "$ROOT$/resources/web/default.bin"
            }
          ]
        }
      ]
    },

    "winsock": {
      // Data that recv gives on a socket. The emulator uses only the default entry.
      // An empty responses list gives no data.
      "responses": [
        {
          "mode": "default",
          "path": "$ROOT$/resources/web/stager.bin"
        }
      ]
    },

    // Network adapters that APIs such as GetAdaptersInfo give.
    "adapters": [
      {
        "name": "{00000000-0000-0000-0000-000000000000}",
        "description": "Intel(R) PRO/1000 MT Network Connection",
        "mac_address": "00-13-CE-12-34-56",
        "type": "ethernet",
        "ip_address": "192.168.56.101",
        "subnet_mask": "255.255.255.0",
        "dhcp_enabled": true
      }
    ]
  }
}
```

## Feature options

Each feature option is a boolean, and each one is on by default. Some options add data to the report and do not change what the guest sees. The other options change the behavior of the guest or the code that runs, so the report of a run without them can show other events.

| Option | Flag to turn it off | Effect | What it does |
|---|---|---|---|
| `memory.accesses` | `--no-memory-accesses` | Report data | Fills `accesses`. Hooks each instruction and each memory access, so it is the slowest option. |
| `memory.strings` | `--no-memory-strings` | Report data | Fills the top-level `strings`. |
| `memory.final_contents` | `--no-memory-final-contents` | Report data | Fills `memory.layout[].data_ref` of the regions of guest memory at the end of each run. User mode only. |
| `memory.dynamic_code_contents.enabled` | `--no-memory-dynamic-code-contents` | Report data | Fills `dynamic_code[].contents[].data_ref` and `dynamic_code[].limit_reached`. Adds an instruction counting hook when `memory.accesses` is off and `limits.instructions` is 0. |
| `code.coverage` | `--no-code-coverage` | Report data | Fills `runs[].coverage`. Hooks each instruction. |
| `memory.freed_regions` | `--no-memory-freed-regions` | Guest behavior | A freed region stays mapped, so a read after the free does not fault. Adds `freed` to each region in the report. Off: the report leaves out the freed regions. |
| `runs.exports` | `--no-runs-exports` | Guest behavior | Runs the exports of a DLL, and the IRP dispatch functions and the unload routine of a driver. |
| `runs.children` | `--no-runs-children` | Guest behavior | Runs the child processes after the input. |
| `apis.stubs` | `--no-apis-stubs` | Guest behavior | An unknown API returns 1. Off: the run ends with `unsupported_api`. |
| `modules.stubs` | `--no-modules-stubs` | Guest behavior | An unknown module loads as an empty API module. Off: the load fails. |
| `exceptions.dispatch` | `--no-exceptions-dispatch` | Guest behavior | CPU exceptions go to the VEH and SEH handlers of the guest. Off: a fault ends the run. |

`memory.freed_regions` costs little time. If you turn off all of `memory` to make a run faster, keep `memory.freed_regions` on, because it changes the result of the run.

## CLI flags

The CLI has a flag for most config fields. `speakeasy/cli_config.py` makes the flags from the fields of `SpeakeasyConfig`. A flag joins the parts of the config path with `-` and replaces `_` with `-`, so `code.coverage` gives `--code-coverage`. A final `enabled` is not part of the flag, so `memory.dynamic_code_contents.enabled` gives `--memory-dynamic-code-contents`. `runs.children` also has the short flag `-k`.

A boolean field has two flags, such as `--memory-strings` and `--no-memory-strings`. An int flag takes a decimal value or a hex value that starts with `0x`. A mapping takes one `KEY=VALUE` for each flag, such as `--network-dns-names c2.example=203.0.113.10`, and each flag adds or replaces one key. A list of objects, such as `processes`, `filesystem.files` or `registry.keys`, has no flag, so set it in a config file. [CLI reference](cli-reference.md#config-flags) lists the flags.

The CLI builds the config in this order, and each step changes the result of the step before it:

1. the built-in defaults
2. the `--config` file
3. the `--volume` mounts, which add entries to `filesystem.files` (see [volumes](volumes.md))
4. the config flags

The CLI reads the `--config` file in the same way as `Speakeasy(config=...)` reads a dict. A key that the file gives replaces the default value, also when the value is a mapping such as `process.env` or a list. A key that the file leaves out gets its default, also in a nested object. For example, `{"user": {"name": "bob"}}` keeps `user.admin` at `true`.

Speakeasy has no named config profiles. To make a config file, start from the output of `--dump-default-config`.

## Operational notes

`speakeasy/profiler.py` and `speakeasy/windows/win32.py` fill most of the report data that the feature options control.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [CLI execution controls](cli-execution-controls.md)
- [Report walkthrough](reporting.md)
- [Help and troubleshooting](help.md)
