# Memory Management
---
Speakeasy implements a lightweight memory manager on top of the emulator engine’s memory management. Each chunk of memory allocated by malware is tracked and tagged so that meaningful memory dumps can be acquired. Being able to attribute activity to specific chunks of memory can prove to be extremely useful for analysts. Logging memory reads and writes to sensitive data structures can reveal the true intent of malware not revealed by API call logging which is particularly useful for samples such as rootkits.

## Memory Tagging
Each memory allocation has a tag associated with it so its origin can be determined with the following namespacing:
`<origin>.<object_type>.<object_name>.<base_address>`

Typically, the "origin" is set to either `emu` or `api`. The `emu` origin means the emulator engine itself allocated the memory block. Examples of memory allocated by emulator are memory mapped images, stacks, or core data structures (e.g. TEB and PEB). When a memory mapping has the origin of `api` it means it was allocated by an API handler invoked by the emulated sample. For example, if a malware sample allocates memory with the VirtualAlloc API, the resulting memory mapping will begin with the following tag: `api.VirtualAlloc`.

---

## Memory Freezing
Generally, memory will be freed when the sample calls APIs that free blocks of memory. There is a configuration option named `keep_memory_on_free` that will instruct the emulator to not free memory blocks when requested. This can be useful when memory contents are important for analysis and a sample attempts to obfucate or remove memory.

---

## Acquiring memory
Full memory dumps can be acquired by calling the top level `get_memory_dumps()` api or using the standalone script with the `-d` option.

---

## Memory Tracing
A configuration option named `memory_tracing` exists that when enabled will track each read, write and execution to each memory block. Note: this can greatly decrease performance since hooks are setup to track these events. 

