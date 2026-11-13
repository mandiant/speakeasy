# CLI analysis recipes

Each recipe gives the flags for one kind of analysis output and a command that checks the output. The final memory contents, the coverage, the memory access counts and the strings are on by default, so `speakeasy -t sample.exe -o report.json` gives all of them. The `--no-` form of each flag turns its output off.

<a id="recipe-memory-snapshots"></a>
## Final memory contents (`--memory-final-contents`)

At the end of each run, the regions of guest memory in `runs[].memory.layout` get a `data_ref`, the SHA-256 of their bytes. Guest memory is the image of the input and of the other modules that load from a file, the allocations and heaps of the guest, the regions with no tag and the static TLS data. The stacks, the stub images of the system modules and the other memory of the emulator do not get one. Kernel mode has no memory layout, so it has no contents. The top-level `data` object maps each SHA-256 to the bytes, compressed with zlib and encoded with base64. To list the regions that have data:

```bash
jq '.runs[].memory.layout[] | select(.data_ref != null) | {base, tag, module, section}' report.json
```

The report gets larger. Regions with the same bytes share one entry in `data`, also across runs. `--no-memory-final-contents` removes the data from the report.

<a id="recipe-code-coverage"></a>
## Coverage collection (`--code-coverage`)

`runs[].coverage` has the addresses of the instructions that each run executed. To count them:

```bash
jq '.runs[] | {start_address, coverage_count: (.coverage // [] | length)}' report.json
```

The emulator runs a hook for each instruction, so emulation is slower. `--no-code-coverage` removes this cost.

<a id="recipe-memory-accesses"></a>
## Memory access counts (`--memory-accesses`)

`runs[].accesses.regions` has the counts of reads, writes and executes of each region that the run used. `region` is the base of the region in `runs[].memory.layout`. `runs[].accesses.symbols` has the counts for each symbol. To count the symbols that each run accessed:

```bash
jq '.runs[] | {start_address, symbols: (.accesses.symbols // [] | length)}' report.json
```

The emulator runs a hook for each instruction, memory read and memory write. A sample that accesses much memory runs much slower. `--no-memory-accesses` removes this cost.

<a id="recipe-memory-strings"></a>
## String extraction controls (`--memory-strings` / `--no-memory-strings`)

String extraction is on by default, so `--memory-strings` has an effect only when a `--config` file turns it off:

```bash
speakeasy -t sample.exe --memory-strings -o report.json
```

`--no-memory-strings` turns it off:

```bash
speakeasy -t sample.exe --no-memory-strings -o report.json
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

`dropped.zip` has the files that the sample wrote and `speakeasy_manifest.json`, which gives the emulated path, size and SHA-256 of each file. The archive also has the files that the sample wrote and then deleted. If the sample wrote no files, the CLI does not make the archive. To list the archive:

```bash
unzip -l dropped.zip
```

<a id="recipe-combined-triage"></a>
## Combined triage profile

This command collects all the outputs of this page in one run, because they are on by default. `--limits-per-run-time 30` limits each run to 30 seconds:

```bash
speakeasy -t sample.exe \
  --limits-per-run-time 30 \
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
