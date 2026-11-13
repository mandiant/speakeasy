# Memory management

The Speakeasy memory manager wraps the memory functions of the CPU engine. It gives each mapped region a tag, and the report can include the regions with their tags.

## Memory tags

A tag starts with the origin and then names the object, for example `api.VirtualAlloc` or `emu.stack`. The origin `emu` marks memory that the emulator maps, such as images, stacks and system structures. The origin `api` marks memory that an API handler allocates for the guest, for example for `VirtualAlloc`. Some small allocations of API handlers have no tag. In the memory manager, the tag of a map ends with its base address, for example `api.VirtualAlloc.0x450000`. The report leaves out the address: the region has `tag` `api.VirtualAlloc` and `base` `0x450000`.

The memory manager gives a module image one map. The report splits it into one region for the PE headers and one region for each section. Each of these regions has the tag `emu.module`, the file name of the module in `module`, and the section name or `headers` in `section`. [Reporting](reporting.md#memory-regions) gives the fields.

## Keeping freed memory

By default, `memory.freed_regions` keeps a region mapped after the sample frees it, so you can examine a buffer that the sample frees soon after it writes the buffer. Each region in the report then has `freed`, which is true for a freed region. The guest can also read and write the region after the free without a fault, which is different from Windows. `--no-memory-freed-regions` unmaps a freed region, as Windows does, when no other allocation of its page block is live. The report then has no `freed` and leaves out each freed allocation. This option changes what the guest sees, so it can change the result of the run.

## Memory contents

By default, `memory.final_contents` adds the content of each memory region at the end of each run to the report, and `--no-memory-final-contents` turns this off. Only user mode has these contents. Each region of guest memory has a `data_ref`, which is a SHA-256 key in the top-level `data` section. Guest memory is the image of the input and of the other modules that load from a file, the allocations and heaps of the guest, the regions with no tag and the static TLS data. The stacks, the stub images of the system modules and the other memory of the emulator have no `data_ref`. The `data` section keeps the bytes as `base64(zlib(raw_bytes))`. The report keeps one copy of bytes that repeat across regions or runs, and it does not need other files.

An unpacker can run code in a buffer and then overwrite the buffer with the next stage, so the snapshot at the end of the run does not have the first stage. By default, `memory.dynamic_code_contents` adds the contents of each dynamic code region, at the first time that code runs in it, to the report. `--no-memory-dynamic-code-contents` turns this off. When `memory.accesses` is off and `limits.instructions` is 0, this option adds a hook that counts each instruction, so that each snapshot has its position. Each entry of `dynamic_code[].contents` then has a `data_ref`, and its `pos` gives the position of the snapshot in the timeline of events. If the guest then writes a new stage into the region and runs it, `contents` has one more entry for each stage, up to `memory.dynamic_code_contents.limit` entries for each region. [Reporting](reporting.md) gives the rules.

## Memory access counts

By default, `memory.accesses` counts the reads, writes and executes of each region and of each symbol address, in `runs[].accesses`. It also counts the instructions for `instruction_count` and `pos.tick`. The counts make the run slower, mostly for samples that access much memory. `--no-memory-accesses` turns them off.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI analysis recipes](cli-analysis-recipes.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [CLI execution controls](cli-execution-controls.md#performance-and-telemetry-tuning)
- [Help and troubleshooting](help.md)
