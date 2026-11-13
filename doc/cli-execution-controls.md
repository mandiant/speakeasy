# CLI execution controls

This page tells you how to limit a run, select the execution mode and debug a run.

## Stopping conditions

These flags stop a run:

- `--limits-per-run-time`: the active execution time of one run, in seconds (default 60).
- `--limits-total-time`: the active execution time of all runs, in seconds (default 0).
- `--limits-api-calls`: the number of API calls in one run (default 10000).
- `--limits-api-loop-calls`: the number of API calls in one run with no call from a new call site (default 5000). A call site is an API and a return address.
- `--limits-instructions`: the number of instructions in one run (default 0).

For each flag, 0 means "no limit". Use them together for samples that run for a long time or loop.

A sample can call APIs in a loop to make emulation slow, for example `GetTickCount` and `Sleep` in a delay loop, or a loop that waits for a condition that the emulator never sets. When a run makes `--limits-api-loop-calls` API calls and none of them is from a call site that the run did not call before, the run ends with an `api_loop_limit` error. The `error.loop` key of the report has the call sites of the loop and the number of calls from each site. A loop that calls APIs from a new address in each iteration, for example from new code that it writes, continues until `--limits-api-calls` stops it. A loop with no API calls continues until `--limits-per-run-time` or `--limits-instructions` stops it.

The CLI emulates in a child process. It stops the child process after `--limits-total-time`, in case the process hangs in Python code. Then it saves the report that the child process sends in the next 5 seconds. `--limits-per-run-time` applies to each run and gives no bound for all runs, so when `--limits-total-time` is 0, the CLI does not stop the child process.

`--limits-per-run-time` and `--limits-total-time` measure host time, so the point where they stop a run depends on the speed of the host. Two runs with the same limits can stop at different instructions and give different reports. For a repeatable report, set `--limits-per-run-time 0` and stop the run with `--limits-instructions` or `--limits-api-calls`:

```bash
speakeasy -t sample.exe --limits-per-run-time 0 --limits-instructions 3000000 --limits-api-calls 10000 -o report.json
```

[Repeatable runs](limitations.md#repeatable-runs) lists the values that can still change between runs.

## Execution mode controls

These flags select what the emulator runs and where:

- `--raw`: emulate the input as raw bytes, for example shellcode.
- `--arch`: the architecture of the shellcode (`x86`, `x64` or `amd64`). `--raw` needs it.
- `--raw-offset`: the offset in the raw input where execution starts (decimal, or hex with `0x`).
- `-k`, `--runs-children`, `--no-runs-children`: emulate the child processes that the sample starts (default on).
- `--runs-exports`, `--no-runs-exports`: also run the exports of a PE, and for a driver its IRP dispatch functions and unload routine (default on).
- `--runs-stack-size`: the size in bytes of the stack of the input. 0 uses the stack size of the input (default 0).
- `--no-mp`: emulate in the CLI process instead of a child process.

By default, a child process runs after the process that started it stops, and `--no-runs-children` turns this off. The child processes are the processes that the sample starts with `CreateProcess`, `CreateProcessAsUser`, `WinExec` or `ShellExecute` on a file with the extension `.exe`, `.com` or `.scr`. `ShellExecute` on a document or a URL does not start a child process. All processes share one address space and the loaded DLLs. Before a child runs, the emulator unmaps the image, the PEB and the heap blocks of the process that ran before it. It also closes the handles of that process. A named object that no other process has a handle to, such as a mutex, goes away, so `OpenMutex` in the child fails with `ERROR_FILE_NOT_FOUND`, as on Windows after that process exits. The child gets its own PEB, with its image first in the loader list, and a new TEB. If the child image cannot load, for example because the file is not a PE, or because other memory uses its base and it has no relocation data, the emulator skips the child and logs a warning. The loads and the runs of the child processes count against `--limits-total-time`. When it runs out, the child processes that are left do not run, and the report has a top-level `total_time_limit` error. The child gets a copy of the current directory and the environment variables of its parent. If the guest gives `lpCurrentDirectory` to `CreateProcess`, the child starts in that directory. The child does not get the vectored exception handlers, the unhandled exception filter or the function tables of its parent. The API handlers keep one state for all processes, for example the process heap handle and the C runtime data.

This command runs raw shellcode with limits:

```bash
speakeasy -t shellcode.bin \
  --raw --arch x86 --raw-offset 0x40 \
  --limits-per-run-time 15 --limits-api-calls 3000 --limits-instructions 500000 \
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
  --limits-per-run-time 20 \
  --limits-api-calls 4000 \
  --limits-instructions 800000 \
  --no-memory-accesses \
  --no-memory-final-contents \
  --no-memory-dynamic-code-contents \
  --no-code-coverage \
  -o report.json
```

Use this profile first for samples that often loop.

### Debugging one run with full telemetry

```bash
speakeasy -t sample.exe \
  --gdb --gdb-port 2345 \
  --no-mp \
  --verbose \
  -o report.json
```

Use this profile when you want to step through one run. The report has the coverage and the memory access counts by default.

## Performance and telemetry tuning

Speakeasy is written in Python, so the data that it collects and the stop limits have a large effect on the run time. The memory access counts, the coverage, the dynamic code contents and the final memory contents make a run slower and the report larger. They are on by default. `--no-memory-accesses`, `--no-code-coverage`, `--no-memory-dynamic-code-contents` and `--no-memory-final-contents` turn them off for one run. These flags change only the report data, so the run executes the same code. With `--no-memory-accesses` and `--limits-instructions 0`, the dynamic code contents add a hook that counts each instruction, so turn off both for the fastest run. `--limits-api-loop-calls` stops most API loops early, and `--limits-api-calls` stops the API loops that it does not see. `--limits-per-run-time` and `--limits-instructions` stop loops with no API calls. For samples that loop or crash, set these limits lower. Run fast triage and the full telemetry as two different runs.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [GDB debugging reference](gdb.md)
- [Help and troubleshooting](help.md)
