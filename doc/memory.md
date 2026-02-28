# Memory management

Speakeasy layers a memory manager on top of the emulator engine and tracks each mapped region with tags and metadata that can be exported in reports.

## Memory tagging

Each allocation is tagged with this namespace format:

`<origin>.<object_type>.<object_name>.<base_address>`

Typical origins:

- `emu`: memory mapped by emulator internals (images, stacks, core runtime structures)
- `api`: memory allocated via API handlers (for example `VirtualAlloc` paths)

## Memory freezing

Set `keep_memory_on_free` (or `--keep-memory-on-free`) to keep mappings after free operations. This is useful when samples allocate, populate, and free buffers quickly but you still need to inspect resulting artifacts.

## Memory acquisition modes

Archive export:

- `--memory-dump-path <zip>` writes a dump archive

In-report bytes:

- `--capture-memory-dumps` embeds `base64(zlib(raw_bytes))` in report memory regions

You can use either mode or both together.

## Memory tracing

Set `analysis.memory_tracing` (or `--analysis-memory-tracing`) to track per-region read/write/execute counters and symbol access summaries.

This adds overhead, especially on memory-heavy samples.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [CLI execution controls](cli-execution-controls.md#performance-and-telemetry-tuning)
- [Help and troubleshooting](help.md)
