# Help and troubleshooting

Use this page when you are blocked and need the fastest path to the right documentation.

## First step: route to the right page

- Unsure where to look: start at the [documentation index](index.md)
- Installation/runtime setup: [install.md](install.md)
- CLI flags and invocation rules: [cli-reference.md](cli-reference.md)
- Environment shaping and determinism: [cli-environment-overrides.md](cli-environment-overrides.md)
- Runtime controls and stop conditions: [cli-execution-controls.md](cli-execution-controls.md)
- Report schema and field semantics: [reporting.md](reporting.md)
- Interactive debugging: [gdb.md](gdb.md)

## Common issues

### Unsupported API errors

Symptom:
- `Unsupported API: <module>.<name>` in logs/report

Read:
- [limitations.md](limitations.md)
- [api-handlers.md](api-handlers.md)

### Sample exits too early or behaves differently than expected

Check:
- [configuration.md](configuration.md)
- [cli-environment-overrides.md](cli-environment-overrides.md)

### Run is too slow or produces very large artifacts

Check:
- [cli-analysis-recipes.md](cli-analysis-recipes.md)
- [cli-execution-controls.md](cli-execution-controls.md)
- [cli-execution-controls.md#performance-and-telemetry-tuning](cli-execution-controls.md#performance-and-telemetry-tuning)

### Need to step through execution interactively

Check:
- [gdb.md](gdb.md)
- [gdb-examples.md](gdb-examples.md)

### Need mounted files in emulated filesystem

Check:
- [volumes.md](volumes.md)
- [cli-reference.md](cli-reference.md)

## Before opening an issue

Include the following so others can reproduce quickly:

- Speakeasy version and install method
- full command line used
- config overlay (if any)
- target type (`exe`, `dll`, `sys`, raw shellcode)
- `--verbose` log excerpt around failure
- report excerpt (`errors`, `entry_points[*].error`)

## Need more help

- Documentation hub: [index.md](index.md)
- Project landing page: [../README.md](../README.md)
- Issue tracker: [github.com/mandiant/speakeasy/issues](https://github.com/mandiant/speakeasy/issues)
