# CLI execution controls

This page tells you how to limit a run, select the execution mode and debug a run.

## Stopping conditions

These flags stop a run:

- `--max-run-time`: the active execution time of one run, in seconds. 0 disables the limit.
- `--max-total-time`: the active execution time of all runs, in seconds. 0 disables the limit.
- `--max-api-calls`: the number of API calls in one run.
- `--max-instructions`: the number of instructions in one run.

Use them together for samples that run for a long time or loop.

The CLI emulates in a child process. It stops the child process after `--max-total-time`, in case the process hangs in Python code. Then it saves the report that the child process sends in the next 5 seconds. `--max-run-time` applies to each run and gives no bound for all runs, so when `--max-total-time` is 0, the CLI does not stop the child process.

`--max-run-time` and `--max-total-time` measure host time, so the point where they stop a run depends on the speed of the host. Two runs with the same limits can stop at different instructions and give different reports. For a repeatable report, set `--max-run-time 0` and stop the run with `--max-instructions` or `--max-api-calls`:

```bash
speakeasy -t sample.exe --max-run-time 0 --max-instructions 3000000 --max-api-calls 10000 -o report.json
```

[Repeatable runs](limitations.md#repeatable-runs) lists the values that can still change between runs.

## Execution mode controls

These flags select what the emulator runs and where:

- `--raw`: emulate the input as raw bytes, for example shellcode.
- `--arch`: the architecture of the shellcode (`x86`, `x64` or `amd64`). `--raw` needs it.
- `--raw-offset`: the offset in the raw input where execution starts (decimal, or hex with `0x`).
- `--emulate-children`: emulate the child processes that the sample starts.
- `--no-mp`: emulate in the CLI process instead of a child process.

With `--emulate-children`, a child process runs after the process that started it stops. The child processes are the processes that the sample starts with `CreateProcess`, `CreateProcessAsUser`, `WinExec` or `ShellExecute` on a file with the extension `.exe`, `.com` or `.scr`. `ShellExecute` on a document or a URL does not start a child process. All processes share one address space and the loaded DLLs. Before a child runs, the emulator unmaps the image, the PEB and the heap blocks of the process that ran before it. It also closes the handles of that process. A named object that no other process has a handle to, such as a mutex, goes away, so `OpenMutex` in the child fails with `ERROR_FILE_NOT_FOUND`, as on Windows after that process exits. The child gets its own PEB, with its image first in the loader list, and a new TEB. If the child image cannot load, for example because the file is not a PE, or because other memory uses its base and it has no relocation data, the emulator skips the child and logs a warning. The loads and the runs of the child processes count against `--max-total-time`. When it runs out, the child processes that are left do not run, and the report has a top-level `max_total_time` error. The child gets a copy of the current directory and the environment variables of its parent. If the guest gives `lpCurrentDirectory` to `CreateProcess`, the child starts in that directory. The child does not get the vectored exception handlers, the unhandled exception filter or the function tables of its parent. The API handlers keep one state for all processes, for example the process heap handle and the C runtime data.

This command runs raw shellcode with limits:

```bash
speakeasy -t shellcode.bin \
  --raw --arch x86 --raw-offset 0x40 \
  --max-run-time 15 --max-api-calls 3000 --max-instructions 500000 \
  -o report.json
```

## Debugging controls

These flags control logging and the GDB stub:

- `--verbose`: log at the DEBUG level.
- `--gdb`: start the GDB stub and pause before the first instruction.
- `--gdb-host`: the address where the GDB stub listens.
- `--gdb-port`: the port of the GDB stub.

`--gdb` sets `--no-mp`. Connect `gdb` or `gdb-multiarch` to `localhost:<port>`. This command starts the stub and waits for the debugger:

```bash
speakeasy -t sample.dll --gdb --gdb-port 1234 --verbose
```

## Profiles

### Fast triage of looping samples

```bash
speakeasy -t sample.exe \
  --max-run-time 20 \
  --max-api-calls 4000 \
  --max-instructions 800000 \
  --no-analysis-memory-tracing \
  -o report.json
```

Use this profile first for samples that often loop.

### Debugging one run with full telemetry

```bash
speakeasy -t sample.exe \
  --gdb --gdb-port 2345 \
  --no-mp \
  --analysis-coverage \
  --analysis-memory-tracing \
  --verbose \
  -o report.json
```

Use this profile when you want to step through one run and get more data in the report.

## Performance and telemetry tuning

Speakeasy is written in Python, so the data that it collects and the stop limits have a large effect on the run time. Memory tracing, coverage and memory region snapshots make a run slower and the report larger. They are off by default. If your config file enables them, `--no-analysis-memory-tracing`, `--no-analysis-coverage` and `--no-snapshot-memory-regions` disable them for one run. For samples that loop or crash, set `--max-run-time`, `--max-api-calls` and `--max-instructions`. Run fast triage and the full telemetry as two different runs.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [GDB debugging reference](gdb.md)
- [Help and troubleshooting](help.md)
