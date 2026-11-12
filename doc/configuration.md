# Configuration walkthrough

`speakeasy/config.py` defines the config fields and their defaults. `speakeasy --dump-default-config` prints the default config. The example below shows the fields with comments. It is JSONC (JSON with comments), so remove the comments before you give it to Speakeasy.

By default, Speakeasy collects all the data that it can and emulates as much of the sample as it can, so the features of the `analysis` section, `keep_memory_on_free`, `snapshot_memory_regions`, `api_hammering`, `modules_always_exist` and `functions_always_exist` are on. Set a field to `false`, or use its `--no-` flag, to turn a feature off. A run with fewer features is faster and gives a smaller report.

Addresses and sizes (`base_addr`, `stack_size`, `byte_fill.size`) are ints. JSON has no hex numbers, so these fields also take a string that starts with `0x`, such as `"0x400000"`. `--dump-default-config` writes each `base_addr` as a `0x` string.

```jsonc
{
  // Schema version. Speakeasy 2.0 reads only "2.0" and gives a ConfigError for
  // other values, such as the 0.2 of Speakeasy 1.x configs. Leave it out to use "2.0".
  "config_version": "2.0",

  // Emulation engine. The only value is "unicorn".
  "emu_engine": "unicorn",

  // Limit of the execution time of each run, in seconds. 0 disables it.
  // At the limit, the emulator ends the run with a timeout error.
  // Increase it for slow samples. Decrease it for quick triage.
  "max_run_time": 60,

  // Limit of the execution time of all runs of one run_module, run_shellcode,
  // call or resume call, in seconds. 0 disables it.
  // At the limit, the emulator ends the current run with a max_total_time error
  // and cancels the other runs.
  "max_total_time": 0,

  // Limit of the API calls of each run. A run that makes more API calls ends
  // with a max_api_count error. Decrease it to stop anti-analysis loops sooner.
  "max_api_calls": 10000,

  // Limit of the instructions of each run. -1 disables it.
  // The emulator stops a run at the limit and records a max_instructions error.
  "max_instructions": -1,

  // Size in bytes of the stack that the emulator allocates for the input.
  // 0 uses the stack size of the input: the SizeOfStackReserve of a PE, or
  // the stack_commit argument of run_shellcode.
  // Set it, for example to 0x100000 (1 MiB), for a sample that uses a large stack.
  "stack_size": 0,

  // Seed of the random number generator of the random APIs, such as
  // RtlGenRandom and CoCreateGuid.
  // Runs with the same seed give the same random bytes and GUIDs to the sample.
  "random_seed": 0,

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

  "analysis": {
    // Count the reads, writes and executes of each symbol, section and memory map
    // in the report. Use it to examine unpackers, PEB walks and import resolvers.
    // It makes the run slower, mostly for samples that access much memory.
    "memory_tracing": true,

    // If true, the report has the strings of the input file and of emulated memory.
    // Set it to false to make the emulation faster when you do not need the strings.
    "strings": true,

    // Record the address of each instruction that a run executes.
    // Use it to compare runs or to see which code ran.
    "coverage": true,

    // If true, the report has the contents of each dynamic code region, for example
    // from VirtualAlloc, at the first time that code runs in the region, and again
    // each time that code runs in it after the region changes. The emulator then
    // counts each instruction for the tick of each snapshot, which makes tight
    // loops about two times slower.
    // Use it to keep the stages of an unpacker that overwrites its buffers.
    "dynamic_code_snapshots": true,

    // The maximum number of snapshots of each dynamic code region in one run,
    // with the first snapshot. It stops a sample that changes a region in a loop.
    "dynamic_code_snapshot_limit": 8
  },

  // If true, the memory manager keeps a freed region mapped, so you can read
  // the data that the sample freed. The guest can then also read and write the
  // region after the free without a fault, which is different from Windows.
  "keep_memory_on_free": true,

  // If true, the report has the contents of the memory regions at the end of each run.
  // The report keeps each content one time in its top-level data store.
  // The report is larger, but you do not need the emulator to examine the memory.
  "snapshot_memory_regions": true,

  "exceptions": {
    // If true, the emulator sends CPU exceptions to the VEH and SEH handlers of
    // the guest (see exceptions.md). If false, a fault ends the run, so you can
    // find the fault more easily.
    "dispatch_handlers": true
  },

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

  // Current directory of the process. The emulator resolves relative paths from it.
  "current_dir": "C:\\Windows\\system32",

  // Command line of the process, for example for GetCommandLine.
  "command_line": "svchost.exe -k netsvcs",

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
  },

  // Domain or workgroup of the user, for example for LookupAccountName.
  // Set it to match the domain that the sample expects.
  "domain": "LAB",

  // Host name, for example for GetComputerName.
  "hostname": "WIN7-LAB",

  "user": {
    // User name, for example for GetUserName.
    "name": "analyst",

    // If true, the token of the user is elevated and has a high integrity level.
    "is_admin": true,

    // SID of the user.
    "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001"
  },

  "api_hammering": {
    // If true, the emulator patches API hammering loops in x86 code.
    // Set it to false, or set "api_hammering" to null, to turn the mitigation off.
    "enabled": true,

    // When the guest calls one API from one call site this number of times,
    // the emulator patches the call to return 0.
    "threshold": 2000,

    // APIs that the emulator does not patch. An empty list uses a built-in list.
    "allow_list": [
      "kernel32.WriteFile",
      "kernel32.ReadFile"
    ]
  },

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
  ],

  // Drives that the drive APIs, such as GetLogicalDrives, give.
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

  "filesystem": {
    "files": [
      {
        // full_path matches the full path of the file.
        "mode": "full_path",

        // Path in the emulated file system. It can have wildcards, such as *.
        "emu_path": "c:\\programdata\\seed\\config.bin",

        // Host file that gives the content of the file.
        // $ROOT$ is the directory of the installed speakeasy package.
        "path": "$ROOT$/resources/files/default.bin"
      },
      {
        "mode": "full_path",
        "emu_path": "c:\\programdata\\seed\\padding.bin",

        // Content that the emulator makes, in place of a host file.
        "byte_fill": {
          // Byte that fills the content.
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
  "registry": {
    "keys": [
      {
        "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "values": [
          {
            // Value name. "default" is the unnamed default value.
            "name": "Updater",
            // Value type, such as REG_SZ, REG_DWORD or REG_MULTI_SZ.
            "type": "REG_SZ",
            // Data as a string. REG_DWORD and REG_QWORD data is a number, such as "0x3".
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
  },

  // Processes that the process enumeration APIs give, in this order, then the
  // main process.
  // The is_main_exe entry defines the container image, which is the main image
  // of the process when the input is a DLL or shellcode (see architecture.md).
  // The emulator ignores the base_addr of this entry and loads the container image
  // at the first free base above 0x7D000000.
  // The container process gets the session of the entry, but not its pid.
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

  "modules": {
    // If true, when the guest loads an unknown module, the emulator creates an
    // empty synthetic API module. If false, the load fails, as on Windows.
    "modules_always_exist": true,

    // If true, an API that has no handler and no entry in the signature database
    // resolves to a stub. The stub takes 4 stdcall arguments and returns 1.
    // An API with an entry in the signature database always uses that entry
    // (see api-handlers.md). If false, a call to an API that has no handler and no
    // entry ends the run with an unsupported_api error, so the report names the API.
    "functions_always_exist": true,

    // Directories of native DLLs, by architecture. If a directory has a file
    // with the name of a module, the emulator loads that file in place of the
    // synthetic API module.
    "module_directory_x86": null,
    "module_directory_x64": null,

    // User mode modules that the emulator loads at their base_addr.
    // The path of each user and system module is a file that exists, so
    // CreateFile opens it and FindFirstFile lists it. The file has no content.
    "user_modules": [
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
    "system_modules": [
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
  }
}
```

## CLI flags

The CLI has a flag for most config fields. `speakeasy/cli_config.py` makes the flags from the fields of `SpeakeasyConfig`. A flag joins the parts of the config path with `-` and replaces `_` with `-`, so `analysis.coverage` gives `--analysis-coverage`. The CLI leaves out a path part when the next part starts with the same word, so `modules.modules_always_exist` gives `--modules-always-exist` and `modules.module_directory_x86` gives `--module-directory-x86`.

A boolean field has two flags, such as `--analysis-strings` and `--no-analysis-strings`. An int flag takes a decimal value or a hex value that starts with `0x`. A list of strings takes one value for each flag, such as `--api-hammering-allow-list kernel32.WriteFile`, and the flag values replace the list. A mapping takes one `KEY=VALUE` for each flag, such as `--network-dns-names c2.example=203.0.113.10`, and each flag adds or replaces one key. A list of objects, such as `processes`, `filesystem.files` or `registry.keys`, has no flag, so set it in a config file.

The CLI builds the config in this order, and each step changes the result of the step before it:

1. the built-in defaults
2. the `--config` file
3. the `--volume` mounts, which add entries to `filesystem.files` (see [volumes](volumes.md))
4. the config flags

The CLI reads the `--config` file in the same way as `Speakeasy(config=...)` reads a dict. A key that the file gives replaces the default value, also when the value is a mapping such as `env` or a list. A key that the file leaves out gets its default, also in a nested object. For example, `{"user": {"name": "bob"}}` keeps `user.is_admin` at `true`.

Speakeasy has no named config profiles. To make a config file, start from the output of `--dump-default-config`.

## Operational notes

Field behavior for report population is implemented primarily in `speakeasy/profiler.py` and `speakeasy/windows/win32.py`.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [CLI execution controls](cli-execution-controls.md)
- [Report walkthrough](reporting.md)
- [Help and troubleshooting](help.md)
