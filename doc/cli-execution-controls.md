# CLI execution controls

This page covers runtime limits, execution mode, and debugging controls.

## Stopping conditions

Primary flags:
- `--max-run-time`: active execution cap in seconds per run (0 disables it)
- `--max-total-time`: active execution cap in seconds across all runs (0, the default, disables it)
- `--max-api-calls`: cap API calls per run
- `--max-instructions`: cap executed instructions per run

Use these together to bound long-running or looping samples.

The CLI emulates in a child process. It stops that process after the larger of `--max-run-time` and `--max-total-time` and saves the report that the process gives within 5 seconds of the stop. When both are 0, the CLI does not stop the process.

`--max-run-time` and `--max-total-time` measure host time, so the point where they stop a run depends on the speed of the host. Two runs with the same limits can stop at different instructions and give different reports. For a repeatable report, set `--max-run-time 0` and stop the run with `--max-instructions` or `--max-api-calls`:

```bash
speakeasy -t sample.exe --max-run-time 0 --max-instructions 3000000 --max-api-calls 10000 -o report.json
```

[Repeatable runs](limitations.md#repeatable-runs) lists the values that can still change between runs.

## Execution mode controls

Primary flags:
- `--raw`: emulate target as raw bytes
- `--arch`: shellcode architecture (`x86`, `x64`, `amd64`), required with `--raw`
- `--raw-offset`: raw-mode execution start offset (decimal, or hex with `0x`)
- `--emulate-children`: emulate spawned child processes
- `--no-mp`: run in current process instead of worker process

With `--emulate-children`, a child process runs after the process that started it stops. All processes share one address space and the loaded DLLs. Before a child runs, the image, PEB and heap blocks of the process that ran before it are unmapped. The child gets its own PEB, with its image first in the loader list, and a new TEB. A child whose image base is used by other memory is skipped with a warning. The child gets a copy of the current directory and the environment variables of its parent, and it starts with no vectored exception handlers, no unhandled exception filter and no function tables. When the guest calls `CreateProcess` with a `lpCurrentDirectory`, the child starts in that directory instead. The API handlers keep one state for all processes, for example the process heap handle and the C runtime data.

Example: raw shellcode run with bounded execution

```bash
speakeasy -t shellcode.bin \
  --raw --arch x86 --raw-offset 0x40 \
  --max-run-time 15 --max-api-calls 3000 --max-instructions 500000 \
  -o report.json
```

## Debugging controls

Primary flags:
- `--verbose`: DEBUG logging
- `--gdb`: start GDB stub and pause before first instruction
- `--gdb-host`: GDB stub bind host (default `127.0.0.1`)
- `--gdb-port`: GDB stub port

Notes:
- `--gdb` implies `--no-mp` automatically.
- Use `gdb` or `gdb-multiarch` to connect to `localhost:<port>`.

Example: debugger-first startup profile

```bash
speakeasy -t sample.dll --gdb --gdb-port 1234 --verbose
```

## Profiles

### Anti-loop containment profile

```bash
speakeasy -t sample.exe \
  --max-run-time 20 \
  --max-api-calls 4000 \
  --max-instructions 800000 \
  --no-analysis-memory-tracing \
  -o report.json
```

Use this as a fast triage baseline for samples that often spin in loops.

### Deep-debug profile

```bash
speakeasy -t sample.exe \
  --gdb --gdb-port 2345 \
  --no-mp \
  --analysis-coverage \
  --analysis-memory-tracing \
  --verbose \
  -o report.json
```

Use this when you want step control and richer telemetry during one run.

## Performance and telemetry tuning

Speakeasy is Python-based, so runtime is sensitive to telemetry scope and stop conditions.

Practical tuning:

- disable heavy collectors unless needed:
  - `--no-analysis-memory-tracing`
  - `--no-analysis-coverage`
  - `--no-snapshot-memory-regions`
- set hard stop limits for unstable or looping samples:
  - `--max-run-time`
  - `--max-api-calls`
  - `--max-instructions`
- run fast triage and deep telemetry as separate profiles

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [GDB debugging reference](gdb.md)
- [Help and troubleshooting](help.md)
