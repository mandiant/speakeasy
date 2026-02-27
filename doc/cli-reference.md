# CLI reference

## Invocation and required input

Basic emulation invocation:

```bash
speakeasy --target <path-to-sample> [flags]
```

Rules:
- `--target` is required for emulation runs.
- `--dump-default-config` is the only mode that does not require `--target`.

Default config dump:

```bash
speakeasy --dump-default-config > default-config.json
```

## Runtime-only flags

These flags are not generated from the config schema.

- `-t, --target`: input file to emulate
- `-o, --output`: output report JSON path
- `--argv`: argv values for the emulated process
- `-c, --config`: JSON config overlay file
- `--dump-default-config`: print built-in default config and exit
- `--raw`: treat input as raw bytes/shellcode
- `--raw-offset`: raw execution start offset (hex)
- `--arch`: architecture override (`x86`, `amd64`; `x64` accepted in raw mode)
- `--memory-dump-path`: memory dump archive output path
- `--dropped-files-path`: dropped-files archive output path
- `-k, --emulate-children`: emulate child processes spawned by the sample
- `--no-mp`: run in current process instead of worker process
- `-v, --verbose`: DEBUG logging
- `--gdb`: enable GDB stub and pause before first instruction
- `--gdb-port`: GDB stub port (default `1234`)
- `-V, --volume`: host_path:guest_path mapping (repeatable)

Notes:
- `--gdb` implies `--no-mp`; Speakeasy enables this automatically.
- `--raw-offset` is parsed as base-16.
- option abbreviations are disabled; pass full flag names.

## Schema-derived config flags

Most scalar/toggle/list/mapping fields in `SpeakeasyConfig` are exposed as CLI flags.

Naming rules:
- config path `a.b_c` maps to `--a-b-c`
- booleans use dual form: `--flag` and `--no-flag`
- dict mappings use repeatable `KEY=VALUE`
- list values use repeatable `VALUE`

### Current schema-derived flags (complete list)

Boolean toggles:
- `--analysis-memory-tracing` / `--no-analysis-memory-tracing`
- `--analysis-strings` / `--no-analysis-strings`
- `--analysis-coverage` / `--no-analysis-coverage`
- `--keep-memory-on-free` / `--no-keep-memory-on-free`
- `--capture-memory-dumps` / `--no-capture-memory-dumps`
- `--exceptions-dispatch-handlers` / `--no-exceptions-dispatch-handlers`
- `--user-is-admin` / `--no-user-is-admin`
- `--api-hammering-enabled` / `--no-api-hammering-enabled`
- `--modules-modules-always-exist` / `--no-modules-modules-always-exist`
- `--modules-functions-always-exist` / `--no-modules-functions-always-exist`

Scalars:
- `--timeout`
- `--max-api-count`
- `--max-instructions`
- `--os-ver-major`
- `--os-ver-minor`
- `--os-ver-release`
- `--os-ver-build`
- `--current-dir`
- `--command-line`
- `--domain`
- `--hostname`
- `--user-name`
- `--user-sid`
- `--api-hammering-threshold`
- `--modules-module-directory-x86`
- `--modules-module-directory-x64`

Mappings/lists:
- `--env KEY=VALUE` (repeatable)
- `--network-dns-names KEY=VALUE` (repeatable)
- `--api-hammering-allow-list VALUE` (repeatable)

## Config precedence

Active runtime config is built in this order:
1. built-in defaults (`SpeakeasyConfig`)
2. optional `--config` JSON overlay
3. explicit CLI overrides

Conflict example:

```bash
speakeasy --target sample.exe \
  --config profile.json \
  --timeout 20 \
  --no-analysis-strings \
  --output report.json
```

If `profile.json` sets `timeout=120` and `analysis.strings=true`, effective runtime values are `timeout=20` and `analysis.strings=false`.

## Unsupported complex fields on CLI

The following fields are config-file-only:
- schema/meta: `config_version`, `description`, `emu_engine`, `system`, `os_ver.name`
- object lists and nested structures:
  - `symlinks`, `drives`
  - `filesystem.files`
  - `registry.keys`
  - `network.adapters`, `network.dns.txt`, `network.http.responses`, `network.winsock.responses`
  - `processes`
  - `modules.user_modules`, `modules.system_modules`

Rationale: these are nested or large structures and are not ergonomic as CLI arguments.

## Concrete examples

Simple PE run:

```bash
speakeasy --target sample.exe --output report.json
```

Raw shellcode run:

```bash
speakeasy --target shellcode.bin --raw --arch x86 --raw-offset 0x20 --output report.json
```

Memory and dropped-files archives:

```bash
speakeasy --target sample.exe --memory-dump-path memdump.zip --dropped-files-path dropped.zip
```

For analyst-focused artifact recipes and environment/control profiles, see:
- [CLI analysis recipes](cli-analysis-recipes.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [CLI execution controls](cli-execution-controls.md)

For a full captured `-h` output snapshot from this tree, see:
- [CLI help snapshot (showboat)](cli-help-showboat.md)
