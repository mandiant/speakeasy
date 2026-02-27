# Performance notes

Speakeasy is implemented in Python, so minimizing Python-side transitions is central to runtime speed.

By default, Python execution is mostly limited to cases where it is needed for behavior modeling, such as API hooks and memory fault handling. Import table and export-table interception are designed so normal instruction flow stays in the emulator engine as much as possible.

## Practical tuning

- disable heavy collectors unless needed:
  - `--no-analysis-memory-tracing`
  - `--no-analysis-coverage`
  - `--no-capture-memory-dumps`
- cap long-running samples:
  - `--timeout`
  - `--max-api-count`
  - `--max-instructions`
- keep deep telemetry runs separate from first-pass triage runs

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI execution controls](cli-execution-controls.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [Memory management](memory.md)
- [Help and troubleshooting](help.md)
