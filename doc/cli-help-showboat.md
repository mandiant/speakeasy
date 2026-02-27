# Speakeasy CLI help snapshot

*2026-02-27T11:30:03Z by Showboat 0.6.1*
<!-- showboat-id: 24f3e6d5-7d0f-4de1-84fb-c60633a5d043 -->

Captured from the current source tree to show the full runtime and schema-derived flag surface.

```bash
.venv/bin/python -m speakeasy.cli -h
```

```output
usage: cli.py [-h] [-t TARGET] [-o OUTPUT] [--argv [ARGV ...]] [-c CONFIG]
              [--dump-default-config] [--raw] [--raw-offset RAW_OFFSET]
              [--arch ARCH] [--memory-dump-path MEMORY_DUMP_PATH]
              [--dropped-files-path DROPPED_FILES_PATH] [-k] [--no-mp] [-v]
              [--gdb] [--gdb-port GDB_PORT] [-V VOLUMES] [--timeout TIMEOUT]
              [--max-api-count MAX_API_COUNT]
              [--max-instructions MAX_INSTRUCTIONS]
              [--analysis-memory-tracing | --no-analysis-memory-tracing]
              [--analysis-strings | --no-analysis-strings]
              [--analysis-coverage | --no-analysis-coverage]
              [--keep-memory-on-free | --no-keep-memory-on-free]
              [--capture-memory-dumps | --no-capture-memory-dumps]
              [--exceptions-dispatch-handlers | --no-exceptions-dispatch-handlers]
              [--os-ver-major MAJOR] [--os-ver-minor MINOR]
              [--os-ver-release RELEASE] [--os-ver-build BUILD]
              [--current-dir CURRENT_DIR] [--command-line COMMAND_LINE]
              [--env KEY=VALUE] [--domain DOMAIN] [--hostname HOSTNAME]
              [--user-name NAME] [--user-is-admin | --no-user-is-admin]
              [--user-sid SID]
              [--api-hammering-enabled | --no-api-hammering-enabled]
              [--api-hammering-threshold THRESHOLD]
              [--api-hammering-allow-list VALUE]
              [--network-dns-names KEY=VALUE]
              [--modules-modules-always-exist | --no-modules-modules-always-exist]
              [--modules-functions-always-exist | --no-modules-functions-always-exist]
              [--modules-module-directory-x86 MODULE_DIRECTORY_X86]
              [--modules-module-directory-x64 MODULE_DIRECTORY_X64]

Emulate a Windows binary with speakeasy

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Path to input file to emulate
  -o, --output OUTPUT   Path to output file to save report
  --argv [ARGV ...]     Commandline parameters to supply to emulated process
                        (e.g. main(argv))
  -c, --config CONFIG   Path to emulator config file
  --dump-default-config
                        Print built-in default config JSON and exit
  --raw                 Attempt to emulate file as-is with no parsing (e.g.
                        shellcode)
  --raw-offset RAW_OFFSET
                        When in raw mode, offset (hex) to start emulating
  --arch ARCH           Force architecture to use during emulation (for multi-
                        architecture files or shellcode). Supported archs: [
                        x86 | amd64 ]
  --memory-dump-path MEMORY_DUMP_PATH
                        Path to store compressed memory dump package
  --dropped-files-path DROPPED_FILES_PATH
                        Path to store files created during emulation
  -k, --emulate-children
                        Emulate any processes created with CreateProcess APIs
                        after the input file finishes emulating
  --no-mp               Run emulation in the current process instead of a
                        child process
  -v, --verbose         Enable verbose (DEBUG) logging
  --gdb                 Enable GDB server stub (pauses before first
                        instruction)
  --gdb-port GDB_PORT   GDB server port (default: 1234)
  -V, --volume VOLUMES  Mount a host path into the emulated filesystem
                        (host_path:guest_path). May be repeated.
  --timeout TIMEOUT     Emulation timeout in seconds. (default: 60)
  --max-api-count MAX_API_COUNT
                        Maximum API calls allowed per run. (default: 10000)
  --max-instructions MAX_INSTRUCTIONS
                        Maximum instructions to execute per run. (default: -1)
  --analysis-memory-tracing, --no-analysis-memory-tracing
                        Enable memory access tracing in reports. (default:
                        False)
  --analysis-strings, --no-analysis-strings
                        Extract strings from input and emulated memory.
                        (default: True)
  --analysis-coverage, --no-analysis-coverage
                        Collect executed instruction addresses per run.
                        (default: False)
  --keep-memory-on-free, --no-keep-memory-on-free
                        Retain freed memory maps for post-free inspection.
                        (default: False)
  --capture-memory-dumps, --no-capture-memory-dumps
                        Include compressed raw memory in report regions.
                        (default: False)
  --exceptions-dispatch-handlers, --no-exceptions-dispatch-handlers
                        Dispatch configured exception handlers during faults.
                        (default: True)
  --os-ver-major MAJOR  Emulated OS major version. (default: 6)
  --os-ver-minor MINOR  Emulated OS minor version. (default: 1)
  --os-ver-release RELEASE
                        Optional emulated OS release number. (default: None)
  --os-ver-build BUILD  Emulated OS build number. (default: 7601)
  --current-dir CURRENT_DIR
                        Current working directory for emulated process APIs.
                        (default: 'C:\\Windows\\system32')
  --command-line COMMAND_LINE
                        Command line exposed to emulated process APIs.
                        (default: 'svchost.exe myarg1 myarg2')
  --env KEY=VALUE       Environment variables visible to the emulated process.
                        (default: 8 entries)
  --domain DOMAIN       Domain or workgroup identity. (default:
                        'speakeasy_domain')
  --hostname HOSTNAME   Hostname exposed to emulated system APIs. (default:
                        'speakeasy_host')
  --user-name NAME      Username exposed to account and profile APIs.
                        (default: 'speakeasy_user')
  --user-is-admin, --no-user-is-admin
                        Expose elevated privileges to admin checks. (default:
                        True)
  --user-sid SID        Optional explicit SID for the emulated user. (default:
                        'S-1-5-21-1111111111-2222222222-3333333333-1001')
  --api-hammering-enabled, --no-api-hammering-enabled
                        Enable API hammering mitigation. (default: False)
  --api-hammering-threshold THRESHOLD
                        Repetition threshold that triggers mitigation.
                        (default: 2000)
  --api-hammering-allow-list VALUE
                        API names exempt from mitigation. (default: 0 items)
  --network-dns-names KEY=VALUE
                        Domain-to-IP mappings used by DNS lookups. (default: 4
                        entries)
  --modules-modules-always-exist, --no-modules-modules-always-exist
                        Synthesize unknown modules instead of failing loads.
                        (default: False)
  --modules-functions-always-exist, --no-modules-functions-always-exist
                        Treat unresolved imports as existing stubs. (default:
                        False)
  --modules-module-directory-x86 MODULE_DIRECTORY_X86
                        Search path for x86 decoy modules. (default:
                        '$ROOT$/winenv/decoys/x86')
  --modules-module-directory-x64 MODULE_DIRECTORY_X64
                        Search path for x64 decoy modules. (default:
                        '$ROOT$/winenv/decoys/amd64')
```

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Help and troubleshooting](help.md)
