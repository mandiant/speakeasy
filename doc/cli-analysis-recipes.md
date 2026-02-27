# CLI analysis recipes

This page focuses on practical flag combinations for common analysis outputs.

## 1. Memory dump archive (`--dump`)

Command:

```bash
speakeasy -t sample.exe --dump memdump.zip
```

What you get:
- zip archive containing dumped memory blocks and manifest

Quick check:

```bash
unzip -l memdump.zip
```

Notes:
- archive size can be large for long runs or multi-process behavior

## 2. In-report memory bytes (`--capture-memory-dumps`)

Command:

```bash
speakeasy -t sample.exe --capture-memory-dumps -o report.json
```

What you get:
- `entry_points[*].memory.layout[*].data` populated with base64(zlib(raw bytes))

Quick check:

```bash
jq '.entry_points[].memory.layout[] | select(.data != null) | .tag' report.json
```

Notes:
- this can dramatically increase report size
- prefer archive dumps (`--dump`) when raw bytes are needed outside the report

## 3. Coverage collection (`--analysis-coverage`)

Command:

```bash
speakeasy -t sample.exe --analysis-coverage -o report.json
```

What you get:
- `entry_points[*].coverage` lists executed instruction addresses

Quick check:

```bash
jq '.entry_points[] | {start_addr, coverage_count: (.coverage // [] | length)}' report.json
```

Notes:
- adds runtime overhead due to additional tracing hooks

## 4. Memory tracing (`--analysis-memory-tracing`)

Command:

```bash
speakeasy -t sample.exe --analysis-memory-tracing -o report.json
```

What you get:
- memory access counters per region
- symbol access summaries when available

Quick check:

```bash
jq '.entry_points[] | {start_addr, sym_accesses: (.sym_accesses // [] | length)}' report.json
```

Notes:
- can significantly reduce execution speed on memory-heavy samples

## 5. String extraction controls (`--analysis-strings`)

Enable (default behavior):

```bash
speakeasy -t sample.exe --analysis-strings -o report.json
```

Disable:

```bash
speakeasy -t sample.exe --no-analysis-strings -o report.json
```

Quick check:

```bash
jq '.strings' report.json
```

Notes:
- disabling strings can reduce report size and post-processing time

## 6. Dropped files archive (`--dropped-files`)

Command:

```bash
speakeasy -t sample.exe --dropped-files dropped.zip
```

What you get:
- zip archive containing file artifacts written during emulation and manifest

Quick check:

```bash
unzip -l dropped.zip
```

Notes:
- useful for staging second-stage payload extraction workflows

## 7. Combined triage profile

Command:

```bash
speakeasy -t sample.exe \
  --timeout 30 \
  --analysis-coverage \
  --analysis-memory-tracing \
  --capture-memory-dumps \
  --dropped-files dropped.zip \
  --dump memdump.zip \
  -o report.json
```

Use this when you want one run with broad telemetry and artifact capture.
