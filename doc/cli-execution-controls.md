# CLI execution controls

This page covers runtime limits, execution mode, and debugging controls.

## Stopping conditions

Primary flags:
- `--timeout`: wall-clock timeout in seconds
- `--max-api-count`: cap API calls per run
- `--max-instructions`: cap executed instructions per run

Use these together to bound long-running or looping samples.

## Execution mode controls

Primary flags:
- `--raw`: emulate target as raw bytes
- `--arch`: architecture override (`x86`, `amd64`)
- `--raw-offset`: raw-mode execution start offset (hex)
- `--emulate-children`: emulate spawned child processes
- `--no-mp`: run in current process instead of worker process

Example: raw shellcode run with bounded execution

```bash
speakeasy -t shellcode.bin \
  --raw --arch x86 --raw-offset 0x40 \
  --timeout 15 --max-api-count 3000 --max-instructions 500000 \
  -o report.json
```

## Debugging controls

Primary flags:
- `--verbose`: DEBUG logging
- `--gdb`: start GDB stub and pause before first instruction
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
  --timeout 20 \
  --max-api-count 4000 \
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
