# Memory management

The Speakeasy memory manager wraps the memory functions of the CPU engine. It gives each mapped region a tag, and the report can include the regions with their tags.

## Memory tags

A tag starts with the origin, then names the object and ends with the base address, for example `api.VirtualAlloc.0x450000` or `emu.stack.0x1200000`. The origin `emu` marks memory that the emulator maps, such as images, stacks and system structures. The origin `api` marks memory that an API handler allocates, for example for `VirtualAlloc`.

## Keeping freed memory

Set `keep_memory_on_free` (or `--keep-memory-on-free`) to keep a region mapped after the sample frees it. Use this option when a sample frees a buffer soon after it writes the buffer, and you want to examine the buffer.

## Memory snapshots

With `--snapshot-memory-regions`, the report includes the content of each memory region at the end of a run. Each region in the report, except the stack, has a `data_ref`, which is a SHA-256 key in the top-level `data` section. The `data` section keeps the bytes as `base64(zlib(raw_bytes))`. The report keeps one copy of bytes that repeat across regions or runs, and it does not need other files.

An unpacker can run code in a buffer and then overwrite the buffer with the next stage, so the snapshot at the end of the run does not have the first stage. Set `analysis.dynamic_code_snapshots` (or `--analysis-dynamic-code-snapshots`) to add the contents of each dynamic code region, at the first time that code runs in it, to the report. Each entry of `dynamic_code_segments` then has a `data_ref`, and its `pos` gives the position of the snapshot in the timeline of events. If the guest then writes a new stage into the region and runs it, `dynamic_code_segments` has one more entry of the region for each stage, up to `analysis.dynamic_code_snapshot_limit` entries for each region. [Reporting](reporting.md) gives the rules.

## Memory tracing

Set `analysis.memory_tracing` (or `--analysis-memory-tracing`) to count the reads, writes and executes of each region and to record the accesses to symbols. Memory tracing makes the run slower, mostly for samples that access much memory.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [CLI execution controls](cli-execution-controls.md#performance-and-telemetry-tuning)
- [Help and troubleshooting](help.md)
