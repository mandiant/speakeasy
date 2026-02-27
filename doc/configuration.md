# Configuration walkthrough

Source of truth:
- `speakeasy/config.py`
- behavior references in `speakeasy/windows/*.py`, `speakeasy/binemu.py`, and `speakeasy/winenv/api/*`

The example below is JSONC (JSON with comments). Remove comment lines for machine parsing.

```jsonc
{
  // Schema version expected by speakeasy.config.SpeakeasyConfig.
  // Keep at 0.2 unless the schema version changes in source.
  "config_version": 0.2,

  // Human note for analysts. Safe to change any time.
  "description": "Example profile for walkthrough documentation",

  // Emulation backend. Only "unicorn" is currently supported.
  "emu_engine": "unicorn",

  // Wall-clock timeout in seconds for each emulation session.
  // Raise for slow/staged samples. Lower for quick triage.
  "timeout": 60,

  // Per-run API call cap. If exceeded, the run ends with a max_api_count error.
  // Raise to allow very API-heavy behavior; lower to cut anti-analysis loops earlier.
  "max_api_count": 10000,

  // Instruction cap forwarded to the emulator.
  // -1 means effectively unbounded from Speakeasy policy.
  "max_instructions": -1,

  // OS family model. Only "windows" is supported.
  "system": "windows",

  "analysis": {
    // Enables per-region memory access counters and symbol access telemetry.
    // Turn on for unpacking/PEB-walk/import-resolver analysis.
    "memory_tracing": false,

    // Enables static + in-memory string extraction in the report.
    // Disable for speed when string data is not needed.
    "strings": true,

    // Enables instruction-address coverage collection per entry point.
    // Useful for diffing runs and rough execution mapping.
    "coverage": false
  },

  // If true, frees do not immediately remove memory maps.
  // Useful when you want to inspect post-free data artifacts.
  "keep_memory_on_free": false,

  // If true, report memory regions can include base64(zlib(raw_bytes)).
  // This greatly increases report size but helps memory forensics.
  "capture_memory_dumps": false,

  "exceptions": {
    // If true, emulate exception-handler dispatch (SEH/VEH-like paths).
    // If false, faulting paths stop sooner and are easier to localize.
    "dispatch_handlers": true
  },

  "os_ver": {
    // OS family marker. Keep as "windows".
    "name": "windows",

    // Version fields exposed through PEB/API version behavior.
    // Align these with the environment your sample expects.
    "major": 6,
    "minor": 1,

    // Optional release discriminator. Usually left null.
    "release": null,

    // Build number used by version checks.
    "build": 7601
  },

  // Current directory exposed to process APIs and relative path resolution.
  "current_dir": "C:\\Windows\\system32",

  // Process command line exposed to query APIs.
  "command_line": "svchost.exe -k netsvcs",

  // Environment variables visible to the emulated process.
  // Change when malware reads env values for path decisions or anti-sandbox checks.
  "env": {
    "comspec": "C:\\Windows\\system32\\cmd.exe",
    "systemroot": "C:\\Windows",
    "windir": "C:\\Windows",
    "temp": "C:\\Windows\\temp",
    "userprofile": "C:\\Users\\analyst"
  },

  // Domain/workgroup identity used by account/network APIs.
  // Set to match expected enterprise or non-domain environments.
  "domain": "LAB",

  // Hostname returned by networking/system identity APIs.
  "hostname": "WIN7-LAB",

  "user": {
    // Username used by account/profile APIs.
    "name": "analyst",

    // Privilege context for is-admin checks.
    "is_admin": true,

    // Optional explicit SID. Set when SID-sensitive logic is present.
    "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001"
  },

  "api_hammering": {
    // Enables anti-API-hammering mitigation.
    "enabled": false,

    // Repeat count before mitigation patches trigger.
    "threshold": 2000,

    // APIs exempt from mitigation. Use for hot APIs that are legitimately noisy.
    "allow_list": [
      "kernel32.WriteFile",
      "kernel32.ReadFile"
    ]
  },

  // Object-manager symbolic links, used by path/device resolution.
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

  // Virtual drive metadata used by drive APIs.
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
        // Mode discriminator. full_path = exact/wildcard path matching.
        "mode": "full_path",

        // Emulated file path pattern to match (supports wildcard matching).
        "emu_path": "c:\\programdata\\seed\\config.bin",

        // Host file to serve for reads.
        // Use $ROOT$ for repo-relative assets in packaged configs.
        "path": "$ROOT$/resources/files/default.bin"
      },
      {
        "mode": "full_path",
        "emu_path": "c:\\programdata\\seed\\padding.bin",

        // Synthetic content source when no host file is desired.
        "byte_fill": {
          // Byte to repeat for generated data.
          "byte": "0x41",
          // Generated size in bytes.
          "size": 512
        }
      },
      {
        // by_ext = apply to all paths with this extension.
        "mode": "by_ext",
        "ext": "txt",
        "path": "$ROOT$/resources/files/default.bin"
      },
      {
        // default = catch-all fallback if no full_path/by_ext matches.
        "mode": "default",
        "path": "$ROOT$/resources/files/default.bin"
      }
    ]
  },

  // Optional registry seed data.
  // Keep only keys/values that your sample reads to reduce maintenance.
  "registry": {
    "keys": [
      {
        "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "values": [
          {
            // Value name. Use "default" for unnamed default values.
            "name": "Updater",
            // Registry type token consumed by registry emulation.
            "type": "REG_SZ",
            // Value payload as string form.
            "data": "C:\\ProgramData\\updater.exe"
          }
        ]
      }
    ]
  },

  "network": {
    "dns": {
      // A-record style domain -> IP mappings.
      // Include "default" for fallback name lookups.
      "names": {
        "default": "10.10.10.10",
        "example.org": "93.184.216.34"
      },

      // TXT response handlers loaded from files.
      "txt": [
        {
          // Domain-specific TXT mapping.
          "name": "bootstrap.example.org",
          "path": "$ROOT$/resources/web/default.bin"
        },
        {
          // Fallback TXT response if no exact name matches.
          "name": "default",
          "path": "$ROOT$/resources/web/default.bin"
        }
      ]
    },

    "http": {
      "responses": [
        {
          // Verb this response set applies to.
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
      // Raw socket recv seed payloads. A default handler is typically sufficient.
      "responses": [
        {
          "mode": "default",
          "path": "$ROOT$/resources/web/stager.bin"
        }
      ]
    },

    // Adapter inventory returned by networking APIs such as GetAdaptersInfo.
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

  // Process inventory visible to process enumeration APIs.
  // Include one is_main_exe=true process for shellcode/DLL container use.
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
    // If true, unknown module loads synthesize decoys instead of failing.
    "modules_always_exist": false,

    // If true, unresolved API imports are treated as existing stubs.
    "functions_always_exist": false,

    // Decoy search roots by architecture.
    "module_directory_x86": "$ROOT$/winenv/decoys/x86",
    "module_directory_x64": "$ROOT$/winenv/decoys/amd64",

    // User-mode module inventory.
    "user_modules": [
      {
        "name": "ntdll",
        "base_addr": "0x7C000000",
        "path": "C:\\Windows\\system32\\ntdll.dll",
        "images": [
          {
            // arch accepts 32/64 or aliases x86/i386/x64/amd64.
            "arch": "x86",
            "name": "ntdll"
          },
          {
            "arch": "x64",
            "name": "ntdll"
          }
        ]
      },
      {
        "name": "kernel32",
        "base_addr": "0x77000000",
        "path": "C:\\Windows\\system32\\kernel32.dll",
        "images": []
      }
    ],

    // Kernel/system module inventory.
    "system_modules": [
      {
        "name": "ntoskrnl",
        "base_addr": "0x803D0000",
        "path": "C:\\Windows\\system32\\ntoskrnl.exe",

        // Optional driver/device object declaration for kernel object namespace realism.
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

## CLI mapping and precedence

CLI config overrides are generated from `SpeakeasyConfig` field definitions.

Mapping rules:
- config path `a.b_c` maps to `--a-b-c`
- booleans map to dual flags (`--flag` / `--no-flag`)
- `dict[str, str]` maps to repeatable `--flag KEY=VALUE`
- `list[str]` maps to repeatable `--flag VALUE`

Examples:
- `analysis.coverage` -> `--analysis-coverage`
- `analysis.strings` -> `--analysis-strings` / `--no-analysis-strings`
- `network.dns.names` -> `--network-dns-names c2.example=203.0.113.10`
- `api_hammering.allow_list` -> `--api-hammering-allow-list kernel32.WriteFile`

Runtime precedence:
1. built-in model defaults
2. optional `--config` overlay
3. explicit CLI flags

`--volume` is a dedicated shortcut for filesystem mappings and is applied before schema-derived CLI overrides.

Use `--dump-default-config` to emit the built-in default profile.

Complex nested structures remain config-file-only (for example `filesystem.files`, `registry.keys`, `processes`, `modules.user_modules`, `modules.system_modules`, and structured network response lists).

## Operational notes

Field behavior for report population is implemented primarily in `speakeasy/profiler.py` and `speakeasy/windows/win32.py`.
