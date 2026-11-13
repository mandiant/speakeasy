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
- `--argv`: arguments of the emulated process, as one quoted string that the CLI splits with shell rules. For an EXE, they replace `process.command_line`, and the process command line is the quoted program path followed by these arguments
- `-c, --config`: JSON config file that changes the defaults
- `--dump-default-config`: print the default config as JSON and exit
- `--raw`: emulate the input as raw bytes, such as shellcode
- `--raw-offset`: offset in the raw input where emulation starts
- `--entry-point`: RVA where a PE starts, in place of its entry point
- `--arch`: shellcode architecture (`x86`, `x64` or `amd64`, in any case). `--raw` needs it, and other modes ignore it
- `--dropped-files-path`: path of the dropped-files archive
- `--no-mp`: run the emulation in the CLI process instead of a child process
- `-v, --verbose`: DEBUG logging
- `--gdb`: start a GDB server and stop before the first instruction. See [GDB debugging](gdb.md)
- `--gdb-host`: address where the GDB server listens (default `127.0.0.1`)
- `--gdb-port`: port of the GDB server (default `1234`)
- `-V, --volume`: `host_path:guest_path` mapping (repeatable). See [Volumes](volumes.md)
- `--no-auto-mount`: do not mount the files of the directory of the input into the emulated current directory. See [Automatic mount of the target directory](volumes.md#automatic-mount-of-the-target-directory)
- `--version`: print the speakeasy version and exit

With `--gdb`, the CLI also sets `--no-mp`. `--raw-offset`, `--entry-point` and the integer config flags take a decimal number, or a hex number with `0x`, so `--raw-offset 32` and `--raw-offset 0x20` are the same. The CLI does not accept abbreviated flag names.

## Output and exit status

The CLI writes the report JSON to the `--output` file, or to stdout without `--output`. The CLI writes log messages to stderr. When stderr is a terminal, the CLI formats them with Rich. When stderr is a pipe or a file, the CLI writes each message as one plain line, so `grep` and tools that read stderr line by line get full messages. Stdout has only the report, so you can pipe stdout to another tool:

```bash
speakeasy --target sample.exe | jq '.runs[].error'
```

The CLI exits 0 when it writes a report. This is also true when a run in the report has an `error`, for example an invalid instruction or a `per_run_time_limit`. To find the runs that stopped early, read `error` in each entry of `runs`. The CLI exits 1 when it cannot make a report, for example because the loader rejects the input. It then writes the error message to stderr. If an error stops the emulation outside a run, the CLI still gives the partial report and exits 1. The CLI also exits 1 when it cannot write the `--output` file or the `--dropped-files-path` archive after the run. It writes the other file when it can. An argument error gives exit status 2, for example `--raw` without `--arch`, a `--volume` host path that does not exist, or an `--output` or `--dropped-files-path` path in a directory that does not exist. The CLI checks these arguments before the emulation starts.

## Config flags

The CLI makes a flag for each config field with a boolean, number, string or string-to-string mapping value. The [config-file-only fields](#config-file-only-fields) have no flag. `speakeasy --help` shows the description and the default of each flag.

The CLI makes the flag name from the config path. It joins the parts of the path with `-` and replaces `_` with `-`, so `memory.accesses` gives `--memory-accesses` and `system.os_ver.major` gives `--system-os-ver-major`. A final `enabled` is not part of the flag, so `memory.dynamic_code_contents.enabled` gives `--memory-dynamic-code-contents`. `runs.children` also has the short flag `-k`. A boolean field has two flags, such as `--code-coverage` and `--no-code-coverage`.

A mapping flag takes `KEY=VALUE` and is repeatable. Each value adds the key to the mapping or replaces its value, and the other keys of the mapping do not change.

The boolean flags are `--runs-exports`, `--runs-children` (short form `-k`), `--memory-accesses`, `--memory-strings`, `--memory-final-contents`, `--memory-dynamic-code-contents`, `--memory-freed-regions`, `--code-coverage`, `--apis-stubs`, `--modules-stubs`, `--exceptions-dispatch` and `--user-admin`. Each one also has a `--no-` form. `--runs-exports` also runs the exports of a PE, and for a driver it sends IRPs to the dispatch functions and runs the unload routine. `--runs-children` emulates the processes that the input starts with `CreateProcess`, `CreateProcessAsUser`, `WinExec` or `ShellExecute`, after the input finishes.

All boolean flags are on by default, so use the `--no-` form to turn a feature off. [Feature options](configuration.md#feature-options) tells which flags change the report data and which change the behavior of the guest. For example, a fast triage run without the analysis data:

```bash
speakeasy --target sample.exe \
  --no-memory-accesses \
  --no-memory-final-contents \
  --no-memory-dynamic-code-contents \
  --no-code-coverage \
  --output report.json
```

Value flags: `--limits-per-run-time`, `--limits-total-time`, `--limits-api-calls`, `--limits-api-loop-calls`, `--limits-instructions`, `--runs-stack-size`, `--memory-dynamic-code-contents-limit`, `--modules-directory-x86`, `--modules-directory-x64`, `--system-os-ver-major`, `--system-os-ver-minor`, `--system-os-ver-build`, `--system-hostname`, `--system-domain`, `--system-start-time`, `--system-random-seed`, `--user-name`, `--user-sid`, `--process-command-line` and `--process-current-dir`. For each `--limits-` flag, 0 means "no limit".

Mapping flags: `--process-env KEY=VALUE` and `--network-dns-names KEY=VALUE`.

## Config precedence

The CLI builds the config of a run in this order:

1. the defaults of `SpeakeasyConfig`
2. the `--config` file
3. the `--volume` mappings
4. the config flags

The CLI reads the `--config` file in the same way as `Speakeasy(config=...)` reads a dict. A key in the file replaces the default value. This is also true for a mapping such as `process.env` or `network.dns.names`, and for a list. A key that the file leaves out keeps its default, also in a nested object. For example, `{"user": {"name": "bob"}}` keeps `user.admin` at `true`.

In this example, the flags change two values of the config file:

```bash
speakeasy --target sample.exe \
  --config profile.json \
  --limits-per-run-time 20 \
  --no-memory-strings \
  --output report.json
```

If `profile.json` sets `limits.per_run_time` to 120 and `memory.strings` to `true`, the run uses `limits.per_run_time` 20 and `memory.strings` `false`.

## Config-file-only fields

These fields hold nested objects or lists of objects, or describe the config itself. They have no flag, so set them in a `--config` file:

- `config_version`, `emu_engine`, `system.os_ver.name`
- `system.symlinks`, `system.drives`
- `filesystem.files`
- `registry.keys`
- `network.adapters`, `network.dns.txt`, `network.http.responses`, `network.winsock.responses`
- `processes`
- `modules.user`, `modules.system`

## Examples

Run a PE:

```bash
speakeasy --target sample.exe --output report.json
```

Run raw shellcode:

```bash
speakeasy --target shellcode.bin --raw --arch x86 --raw-offset 0x20 --output report.json
```

Write the dropped-files archive. The report has the final memory contents by default:

```bash
speakeasy --target sample.exe --dropped-files-path dropped.zip --output report.json
```

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [CLI execution controls](cli-execution-controls.md)
- [Configuration walkthrough](configuration.md)
- [Help and troubleshooting](help.md)
