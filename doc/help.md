# Help and troubleshooting

This page tells you which page to read for a problem.

## Where to look

- All pages: [documentation index](index.md)
- Overview and quick start: [project README](../README.md)
- Installation: [install.md](install.md)
- CLI flags: [cli-reference.md](cli-reference.md)
- The emulated environment and repeatable runs: [cli-environment-overrides.md](cli-environment-overrides.md)
- Limits and stop conditions: [cli-execution-controls.md](cli-execution-controls.md)
- Report fields: [reporting.md](reporting.md)
- Interactive debugging: [gdb.md](gdb.md)

## Common issues

If the log shows `Unsupported API: <module>.<name>` and the report has an `unsupported_api` error, the sample called an API that has no handler and no signature. [limitations.md](limitations.md) tells you why the run stops, and [api-handlers.md](api-handlers.md) tells you how to add a handler. By default, `modules.functions_always_exist` is on, so a call to such an API returns 1, and the run continues without an `unsupported_api` error. To find these APIs, use `--no-modules-functions-always-exist`.

If the sample exits too early or takes a path that you do not expect, it can need a file, a registry key or another part of the environment. Read [configuration.md](configuration.md) and [cli-environment-overrides.md](cli-environment-overrides.md).

If a run is too slow or the report is too large, read [cli-analysis-recipes.md](cli-analysis-recipes.md) and [performance and telemetry tuning](cli-execution-controls.md#performance-and-telemetry-tuning).

To step through the code of a sample, read [gdb.md](gdb.md). To give host files to the sample, read [volumes.md](volumes.md) and [cli-reference.md](cli-reference.md).

## Before you open an issue

Include these items, so that others can reproduce the problem:

- the Speakeasy version (`speakeasy --version`) and how you installed it
- the full command line
- the config file, if you used one
- the type of the input (`exe`, `dll`, `sys` or raw shellcode)
- the `--verbose` log near the failure
- the `errors` and `entry_points[*].error` fields of the report

Report issues in the [issue tracker](https://github.com/mandiant/speakeasy/issues).
