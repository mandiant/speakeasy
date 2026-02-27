# CLI reference

## Overview

`speakeasy` combines runtime execution flags with configuration-model overrides.

Runtime config precedence:
1. built-in model defaults (`SpeakeasyConfig`)
2. optional `--config` JSON overlay
3. explicit CLI overrides

At execution start, Speakeasy logs the active config values at INFO level.

## Runtime-only flags

- `-t, --target`: input file path to emulate
- `-o, --output`: write emulation report JSON
- `-p, --params`: argv values for emulated process
- `-c, --config`: optional config overlay JSON file
- `--dump-default-config`: print built-in default config JSON and exit
- `-r, --raw`: emulate input as raw shellcode/blob
- `--raw_offset`: raw mode start offset (hex)
- `-a, --arch`: `x86` or `amd64` (primarily for raw mode)
- `-d, --dump`: write memory dump archive zip
- `-z, --dropped-files`: write dropped-files archive zip
- `-k, --emulate-children`: emulate child processes
- `--no-mp`: run in-process instead of child process
- `-v, --verbose`: DEBUG logging
- `--gdb`: enable GDB remote stub
- `--gdb-port`: GDB server port
- `-V, --volume`: host_path:guest_path mapping (repeatable)

## Schema-derived config flags

Flag names are generated from config paths:
- dots become dashes
- underscores become dashes
- booleans get dual form: `--flag` and `--no-flag`

Examples:
- `analysis.memory_tracing` -> `--analysis-memory-tracing`
- `modules.module_directory_x86` -> `--modules-module-directory-x86`
- `user.is_admin` -> `--user-is-admin` / `--no-user-is-admin`

### Scalar and boolean flags

- `--timeout`
- `--max-api-count`
- `--max-instructions`
- `--analysis-memory-tracing`
- `--analysis-strings`
- `--analysis-coverage`
- `--keep-memory-on-free`
- `--capture-memory-dumps`
- `--exceptions-dispatch-handlers`
- `--os-ver-major`
- `--os-ver-minor`
- `--os-ver-release`
- `--os-ver-build`
- `--current-dir`
- `--command-line`
- `--domain`
- `--hostname`
- `--user-name`
- `--user-is-admin`
- `--user-sid`
- `--api-hammering-enabled`
- `--api-hammering-threshold`
- `--modules-modules-always-exist`
- `--modules-functions-always-exist`
- `--modules-module-directory-x86`
- `--modules-module-directory-x64`

### Mapping/list flags

- `--env KEY=VALUE` (repeatable; updates specified keys only)
- `--network-dns-names KEY=VALUE` (repeatable; updates specified keys only)
- `--api-hammering-allow-list VALUE` (repeatable)

## Unsupported complex config fields on CLI

These remain config-file-only due to complexity and poor command-line ergonomics:
- filesystem file handlers (`filesystem.files`)
- registry trees (`registry.keys`)
- structured network response lists (`network.http.responses`, `network.winsock.responses`, `network.dns.txt`)
- process/module inventories (`processes`, `modules.user_modules`, `modules.system_modules`)
- symlink and drive object lists (`symlinks`, `drives`)

Use `--config` for those structures, with targeted CLI overrides for simple fields.

## Concrete examples

Default config dump:

```bash
speakeasy --dump-default-config
```

Overlay + CLI override precedence:

```bash
speakeasy -t sample.exe \
  --config profile.json \
  --timeout 20 \
  --analysis-coverage \
  --no-analysis-strings
```

Raw shellcode with explicit architecture:

```bash
speakeasy -t shellcode.bin -r -a x86 --raw_offset 0x20
```

Map host artifacts and override DNS/env keys:

```bash
speakeasy -t sample.exe \
  -V /tmp/stage:c:\\windows\\temp \
  --env TEMP=c:\\windows\\temp \
  --network-dns-names c2.example=203.0.113.50
```
