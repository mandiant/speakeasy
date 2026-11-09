# CLI analysis recipes

Each recipe gives the flags for one kind of analysis output and a command that checks the output.

<a id="recipe-memory-snapshots"></a>
## In-report memory snapshots (`--snapshot-memory-regions`)

```bash
speakeasy -t sample.exe --snapshot-memory-regions -o report.json
```

The memory regions in `entry_points[*].memory.layout` get a `data_ref`, the SHA-256 of their bytes. Stack and heap regions do not get one. The top-level `data` object maps each SHA-256 to the bytes, compressed with zlib and encoded with base64. To list the regions that have data:

```bash
jq '.entry_points[].memory.layout[] | select(.data_ref != null) | .tag' report.json
```

The report gets larger. Regions with the same bytes share one entry in `data`, also across runs.

<a id="recipe-analysis-coverage"></a>
## Coverage collection (`--analysis-coverage`)

```bash
speakeasy -t sample.exe --analysis-coverage -o report.json
```

`entry_points[*].coverage` has the addresses of the instructions that each run executed. To count them:

```bash
jq '.entry_points[] | {start_address, coverage_count: (.coverage // [] | length)}' report.json
```

The emulator runs a hook for each instruction, so emulation is slower.

<a id="recipe-memory-tracing"></a>
## Memory tracing (`--analysis-memory-tracing`)

```bash
speakeasy -t sample.exe --analysis-memory-tracing -o report.json
```

The regions in `entry_points[*].memory.layout` that the run accessed get `accesses`, with the counts of reads, writes and executes. `entry_points[*].symbol_accesses` has the counts for each symbol. To count the symbols that each run accessed:

```bash
jq '.entry_points[] | {start_address, symbol_accesses: (.symbol_accesses // [] | length)}' report.json
```

The emulator runs a hook for each instruction, memory read and memory write. A sample that accesses much memory runs much slower.

<a id="recipe-analysis-strings"></a>
## String extraction controls (`--analysis-strings` / `--no-analysis-strings`)

String extraction is on by default, so `--analysis-strings` has an effect only when a `--config` file turns it off:

```bash
speakeasy -t sample.exe --analysis-strings -o report.json
```

`--no-analysis-strings` turns it off:

```bash
speakeasy -t sample.exe --no-analysis-strings -o report.json
```

The strings are in the top-level `strings` object. Without string extraction, the report has no `strings`:

```bash
jq '.strings' report.json
```

Without string extraction, the report is smaller and Speakeasy finishes sooner.

<a id="recipe-dropped-files"></a>
## Dropped files archive (`--dropped-files-path`)

```bash
speakeasy -t sample.exe --dropped-files-path dropped.zip
```

`dropped.zip` has the files that the sample wrote, also the files that it deleted after the write, and `speakeasy_manifest.json`, which gives the emulated path, size and SHA-256 of each file. If the sample wrote no files, the CLI does not make the archive. To list the archive:

```bash
unzip -l dropped.zip
```

<a id="recipe-combined-triage"></a>
## Combined triage profile

This command collects all the outputs of this page in one run. `--max-run-time 30` limits each run to 30 seconds:

```bash
speakeasy -t sample.exe \
  --max-run-time 30 \
  --analysis-coverage \
  --analysis-memory-tracing \
  --snapshot-memory-regions \
  --dropped-files-path dropped.zip \
  -o report.json
```

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [CLI execution controls](cli-execution-controls.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [Help and troubleshooting](help.md)
