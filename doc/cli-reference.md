# CLI reference

## Invocation and required input

To emulate a sample, give its path with `--target`:

```bash
speakeasy --target <path-to-sample> [flags]
```

An emulation run needs `--target`. Only `--dump-default-config` and `--version` run without it. `--dump-default-config` prints the default config:

```bash
speakeasy --dump-default-config > default-config.json
```

## Runtime-only flags

These flags do not come from the config schema.

- `-t, --target`: input file to emulate
- `-o, --output`: path of the report JSON. Without it, the CLI writes the report to stdout
- `--argv`: arguments of the emulated process, as one quoted string that the CLI splits with shell rules. For an EXE, they replace `command_line`, and the process command line is the quoted program path followed by these arguments
- `-c, --config`: JSON config file that changes the defaults
- `--dump-default-config`: print the default config as JSON and exit
- `--raw`: emulate the input as raw bytes, such as shellcode
- `--raw-offset`: offset in the raw input where emulation starts
- `--entry-point`: RVA where a PE starts, in place of its entry point
- `--arch`: shellcode architecture (`x86`, `x64` or `amd64`, in any case). `--raw` needs it, and other modes ignore it
- `--dropped-files-path`: path of the dropped-files archive
- `-k, --emulate-children`: after the input finishes, emulate the processes that it created with the CreateProcess APIs
- `--no-mp`: run the emulation in the CLI process instead of a child process
- `-v, --verbose`: DEBUG logging
- `--gdb`: start a GDB server and stop before the first instruction. See [GDB debugging](gdb.md)
- `--gdb-host`: address where the GDB server listens (default `127.0.0.1`)
- `--gdb-port`: port of the GDB server (default `1234`)
- `-V, --volume`: `host_path:guest_path` mapping (repeatable). See [Volumes](volumes.md)
- `--version`: print the speakeasy version and exit

With `--gdb`, the CLI also sets `--no-mp`. `--raw-offset`, `--entry-point` and the integer config flags take a decimal number, or a hex number with `0x`, so `--raw-offset 32` and `--raw-offset 0x20` are the same. The CLI does not accept abbreviated flag names.

## Output and exit status

The CLI writes the report JSON to the `--output` file, or to stdout without `--output`. Log messages go to stderr, so you can pipe stdout to another tool:

```bash
speakeasy --target sample.exe | jq '.entry_points[].error'
```

The CLI exits 0 when it writes a report. This is also true when an entry point in the report has an `error`, for example an invalid instruction or a timeout. To find the runs that stopped early, read `error` in each entry point. The CLI exits 1 when it cannot make a report, for example because the loader rejects the input. It then writes the error message to stderr. If an error stops the emulation outside an entry point, the CLI still gives the partial report and exits 1. An argument error gives exit status 2, for example `--raw` without `--arch`, or a `--volume` host path that does not exist.

## Config flags

The CLI makes a flag for each config field with a boolean, number, string, string list or string-to-string mapping value. The [config-file-only fields](#config-file-only-fields) have no flag. `speakeasy --help` shows the description and the default of each flag.

The CLI makes the flag name from the config path. `analysis.memory_tracing` gives `--analysis-memory-tracing`. If a path part starts with the same word as the part before it, the CLI uses that word one time: `modules.modules_always_exist` gives `--modules-always-exist`. A boolean field has two flags, such as `--analysis-coverage` and `--no-analysis-coverage`.

A mapping flag takes `KEY=VALUE` and is repeatable. Each value adds the key to the mapping or replaces its value, and the other keys of the mapping do not change. A list flag takes one `VALUE` and is repeatable. The values replace the whole list.

Boolean flags: `--analysis-memory-tracing`, `--analysis-strings`, `--analysis-coverage`, `--keep-memory-on-free`, `--snapshot-memory-regions`, `--exceptions-dispatch-handlers`, `--user-is-admin`, `--api-hammering-enabled`, `--modules-always-exist` and `--modules-functions-always-exist`, each also with a `--no-` form.

Value flags: `--max-run-time`, `--max-total-time`, `--max-api-calls`, `--max-instructions`, `--stack-size`, `--random-seed`, `--start-time`, `--os-ver-major`, `--os-ver-minor`, `--os-ver-build`, `--current-dir`, `--command-line`, `--domain`, `--hostname`, `--user-name`, `--user-sid`, `--api-hammering-threshold`, `--module-directory-x86` and `--module-directory-x64`.

Mapping flags: `--env KEY=VALUE` and `--network-dns-names KEY=VALUE`. List flag: `--api-hammering-allow-list VALUE`.

## Config precedence

The CLI builds the config of a run in this order:

1. the defaults of `SpeakeasyConfig`
2. the `--config` file
3. the `--volume` mappings
4. the config flags

The CLI reads the `--config` file in the same way as `Speakeasy(config=...)` reads a dict. A key in the file replaces the default value. This is also true for a mapping such as `env` or `network.dns.names`, and for a list. A key that the file leaves out keeps its default, also in a nested object. For example, `{"user": {"name": "bob"}}` keeps `user.is_admin` at `true`.

In this example, the flags change two values of the config file:

```bash
speakeasy --target sample.exe \
  --config profile.json \
  --max-run-time 20 \
  --no-analysis-strings \
  --output report.json
```

If `profile.json` sets `max_run_time` to 120 and `analysis.strings` to `true`, the run uses `max_run_time` 20 and `analysis.strings` `false`.

## Config-file-only fields

These fields hold nested objects or lists of objects, or describe the config itself. They have no flag, so set them in a `--config` file:

- `config_version`, `emu_engine`, `os_ver.name`
- `symlinks`, `drives`
- `filesystem.files`
- `registry.keys`
- `network.adapters`, `network.dns.txt`, `network.http.responses`, `network.winsock.responses`
- `processes`
- `modules.user_modules`, `modules.system_modules`

## Examples

Run a PE:

```bash
speakeasy --target sample.exe --output report.json
```

Run raw shellcode:

```bash
speakeasy --target shellcode.bin --raw --arch x86 --raw-offset 0x20 --output report.json
```

Save memory snapshots in the report and write the dropped-files archive:

```bash
speakeasy --target sample.exe --snapshot-memory-regions --dropped-files-path dropped.zip --output report.json
```

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [CLI execution controls](cli-execution-controls.md)
- [Configuration walkthrough](configuration.md)
- [Help and troubleshooting](help.md)
