# CLI analysis recipes

This page focuses on practical flag combinations for common analysis outputs.

<a id="recipe-memory-snapshots"></a>
## In-report memory snapshots (`--snapshot-memory-regions`)

Command:

```bash
speakeasy -t sample.exe --snapshot-memory-regions -o report.json
```

Expected artifact:
- `entry_points[*].memory.layout[*].data_ref` populated with SHA-256 refs
- top-level `data` populated with `base64(zlib(raw_bytes))` entries

Quick verification:

```bash
jq '.entry_points[].memory.layout[] | select(.data_ref != null) | .tag' report.json
```

Tradeoff:
- report size increases, but repeated payloads deduplicate across runs

<a id="recipe-analysis-coverage"></a>
## Coverage collection (`--analysis-coverage`)

Command:

```bash
speakeasy -t sample.exe --analysis-coverage -o report.json
```

Expected artifact:
- `entry_points[*].coverage` contains executed instruction addresses

Quick verification:

```bash
jq '.entry_points[] | {start_addr, coverage_count: (.coverage // [] | length)}' report.json
```

Tradeoff:
- extra tracing overhead increases runtime

<a id="recipe-memory-tracing"></a>
## Memory tracing (`--analysis-memory-tracing`)

Command:

```bash
speakeasy -t sample.exe --analysis-memory-tracing -o report.json
```

Expected artifact:
- per-region access counters in `memory.layout[*].accesses`
- symbol access summaries in `sym_accesses`

Quick verification:

```bash
jq '.entry_points[] | {start_addr, sym_accesses: (.sym_accesses // [] | length)}' report.json
```

Tradeoff:
- substantial runtime impact on memory-heavy samples

<a id="recipe-analysis-strings"></a>
## String extraction controls (`--analysis-strings` / `--no-analysis-strings`)

Enable:

```bash
speakeasy -t sample.exe --analysis-strings -o report.json
```

Disable:

```bash
speakeasy -t sample.exe --no-analysis-strings -o report.json
```

Quick verification:

```bash
jq '.strings' report.json
```

Tradeoff:
- disabling strings reduces report size and post-processing time

<a id="recipe-dropped-files"></a>
## Dropped files archive (`--dropped-files-path`)

Command:

```bash
speakeasy -t sample.exe --dropped-files-path dropped.zip
```

Expected artifact:
- `dropped.zip` with files written during emulation and a manifest

Quick verification:

```bash
unzip -l dropped.zip
```

Tradeoff:
- captures useful payload artifacts but adds archive creation overhead

<a id="recipe-combined-triage"></a>
## Combined triage profile

Command:

```bash
speakeasy -t sample.exe \
  --timeout 30 \
  --analysis-coverage \
  --analysis-memory-tracing \
  --snapshot-memory-regions \
  --dropped-files-path dropped.zip \
  -o report.json
```

Use this profile when you want broad telemetry and artifact capture in one run.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [CLI execution controls](cli-execution-controls.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [Help and troubleshooting](help.md)
