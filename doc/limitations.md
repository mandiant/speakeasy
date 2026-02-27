# Limitations

Speakeasy does not delegate API calls, object management, or I/O to a real Windows kernel. Those behaviors are modeled by the emulator, so unsupported paths or environment mismatches can stop execution early.

## Unimplemented APIs

Samples call APIs with assumptions about arguments, return values, side effects, and stack behavior. If a required API handler is missing, the current run stops and records an error.

Expected error pattern:

- `Unsupported API: <module_name>.<api_name>`

Why execution stops:

- for unknown APIs, argument count/calling convention cannot be trusted
- continuing may corrupt stack state and generate misleading report data

Queued runs (for example additional entry points) can still execute.

## Environmental requirements

A sample may expect files, registry keys, network responses, loaded modules, or runtime structures that are not present in the active profile. These misses can look like anti-analysis behavior even when the issue is configuration drift.

Use config and CLI overrides to model the expected environment before concluding a sample is unsupported.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [Module resolution and decoy exports](module-resolution.md)
- [Adding API handlers](api-handlers.md)
- [Help and troubleshooting](help.md)
