# Migrating to 2.0

This page tells you how to move code, config files and scripts from Speakeasy 1.x to 2.0. It covers the Python library, the config file and the command line. Each section names a change to the interface and tells you what to change in your code or command.

## Report from 1.x

The report of 2.0 has `report_version` `7.0.0`. The report of 1.x has `1.1.0`. `Speakeasy.get_report` returns a `Report`, a pydantic model from `speakeasy.report`. In 1.x it returned a plain dict. The 2.0 pre-releases wrote report 6.x. For the changes from 6.x, see [Report schema 7.0.0](#report-schema-700).

In 1.x, the report had a list `entry_points`. In 2.0, this list is `runs`. Each entry point of 1.x had one list for each kind of event: `apis`, `file_access`, `registry_access`, `network_events` (with `dns` and `traffic`), `process_events` and `handled_exceptions`. It also had `mem_access`, `sym_accesses`, `dynamic_code_segments` and `dropped_files`. In 2.0, a run has one `events` list in execution order in place of the event lists. The `event` key of each event gives its kind, and `pos` gives the tick, thread, process and `pc` of the event. `mem_access` and `sym_accesses` move to `accesses`. `dynamic_code_segments` becomes `dynamic_code`, with one entry for each region. `base` of a region becomes `region`, and `contents` has the `pos` of the first time that code ran in the region. With `memory.dynamic_code_contents`, each entry of `contents` also has a `data_ref`, `contents` has one more entry for each later snapshot of the region, and `limit_reached` tells if the region got to the snapshot limit. `dropped_files` does not change.

Before:

```python
report = se.get_report()
for ep in report["entry_points"]:
    for fa in ep.get("file_access", []):
        if fa["event"] == "write":
            print(fa["path"], fa["size"])
```

After:

```python
report = se.get_report()
for ep in report.runs:
    for event in ep.events:
        if event.event == "file_write":
            print(event.path, event.size)
```

For a dict, use `json.loads(se.get_json_report())`. It has the same keys as the JSON report. A key is absent when Speakeasy did not collect its data, for example `coverage` when coverage collection is off. An empty list means that Speakeasy collected the data and found nothing, so `events` is always a list.

This table gives the `events` that hold the data of each 1.x list:

| 1.x | 2.0 |
|---|---|
| `apis[]` | `api` events |
| `handled_exceptions[]` | `exception` events |
| `network_events.dns[]` | `net_dns` events |
| `network_events.traffic[]` | `net_traffic` events, and `net_http` events for HTTP requests |
| `file_access[]`, `event` `create`, `open`, `read`, `write` | `file_create`, `file_open`, `file_read`, `file_write` events |
| `registry_access[]`, `event` `open_key`, `create_key`, `read_value`, `list_subkeys` | `reg_open_key`, `reg_create_key`, `reg_read_value`, `reg_list_subkeys` events |
| `process_events[]`, `event` `create` | `process_create` events |
| `process_events[]`, `event` `mem_alloc`, `mem_write`, `mem_read`, `mem_protect`, `thread_create`, `thread_inject` | events with the same `event` value |
| `mem_access[]` | `accesses.regions[]`, with the base of a region of `memory.layout[]` in `region` |

These keys have new names:

| 1.x | 2.0 |
|---|---|
| `filetype` | `file_type` |
| `entry_points` | `runs` |
| `entry_points[].ep_type` | `type` and `name`, see the table below |
| `entry_points[].start_addr` | `start_address` |
| `entry_points[].ep_args` | `args` |
| `entry_points[].instr_count` | `instruction_count` |
| `entry_points[].apihash` | `api_hash` |
| `entry_points[].sym_accesses` | `accesses.symbols` |
| `entry_points[].dynamic_code_segments` | `dynamic_code`, one entry for each region |
| `dynamic_code_segments[].base` | `dynamic_code[].region` |
| `entry_points[].error.regs` | `error.registers` |
| `entry_points[].error.instr`, `handled_exceptions[].instr` | `error.instruction`, `instruction` of the event |
| `entry_points[].ret_val`, `apis[].ret_val` | `return_value` |
| `apis[].pc`, `handled_exceptions[].pc` | `pos.pc` of the event |
| `process_events[].cmdline` | `command_line` |
| `process_events[].start_addr` | `start_address` |
| `data` of a file, registry, memory or network entry, `body` of an HTTP entry | `data_ref`, a key of the top-level `data` mapping |

The `data` mapping stores each payload one time, compressed with zlib and encoded with base64. In 1.x, `data` held the bytes encoded with base64 in the entry itself.

The report does not have the 1.x keys `emu_version`, `os_run` and `mem_tag`, or the `type` (allocation type) of a `mem_alloc` event.

The report writes each machine word as a hex string with a `0x` prefix and lowercase digits: addresses, pointers, handles, raw argument values, return values, register values, exception codes and coverage. A 64-bit word can be above 2\*\*53 or 2\*\*63. JavaScript, Go `interface{}`, jq and int64 stores such as SQLite lose such a value as a JSON number, and they give no error. In Python, `int(value, 16)` reads the string. The report writes each quantity, such as a size, a count, an offset, a tick or an ID, as a JSON number. The schema gives the pattern `^0x[0-9a-f]+$` for each hex string.

These values have a new format:

| 1.x | 2.0 | 1.x value | 2.0 value |
|---|---|---|---|
| `apis[].args[]` | `args[]` | `"0x1"` | `{"type": "int", "value": "0x1", "display": "0x1"}` |
| `file_access[].handle` | `handle` | `128` | `"0x80"` |
| `apis[].ret_val` of a handler that returns a negative number | `return_value` | `"-0x1"` | `"0xffffffff"` on x86, `"0xffffffffffffffff"` on x64 |
| `process_events[].protect` | `protect` | `"PAGE_READWRITE\|PAGE_GUARD"` | `["PAGE_READWRITE", "PAGE_GUARD"]` |
| `error.regs`, `handled_exceptions[].registers` values | `registers` values | `"0x012f8a34"` | `"0x12f8a34"` |
| `errors[]` | `errors[]` | traceback text | an object like `runs[].error` |
| `error.stack[]` | `error.stack[]` | `"sp+0x04: 0x0012ff80 -> emu.stack.0x1200000"` | `{"offset": 4, "value": "0x12ff80", "region": "0x1200000"}` |
| `network_events.traffic[].proto` of an HTTP request | `proto` of `net_http` | `tcp.http`, `tcp.https` | `http`, `https` |
| `error.type` | `error.type` | the text of the exception, for example `Invalid instruction (UC_ERR_INSN_INVALID)` | an identifier, for example `invalid_instruction` |
| `arch` | `arch` | `unknown` when not known | absent when not known |
| `filetype` | `file_type` | `unknown` when not known, absent for shellcode | absent when not known, `shellcode` for shellcode |

`args[]` of an `api` event has the parameter name in `name` when the signature is known. In 1.x a process event always had `pid`. In 2.0 it has `pid` only when the event changes another process.

These keys take one value from a fixed set. The schema lists them:

| 1.x | 2.0 | Values in 2.0 |
|---|---|---|
| `arch` | `arch` | `x86`, `x64` |
| `filetype` | `file_type` | `exe`, `dll`, `driver`, `shellcode` |
| `entry_points[].ep_type` | `type` | `module_entry`, `dll_entry`, `tls_callback`, `export`, `shellcode`, `thread`, `service_main`, `dependency_dll_entry`, `dependency_tls_callback`, `call`, `driver_entry`, `driver_unload`, `driver_reinit`, `irp` |
| `error.type` | `error.type` | `per_run_time_limit`, `total_time_limit`, `instruction_limit`, `api_call_limit`, `api_loop_limit`, `unsupported_api`, `internal_error`, `engine_stopped`, `invalid_image`, `dll_initialization_failed`, `api_handler_did_not_return`, `invalid_read`, `invalid_write`, `invalid_fetch`, `invalid_protect_read`, `invalid_protect_write`, `invalid_protect_fetch`, `guard_page_violation`, `privileged_instruction`, `invalid_instruction`, `unsupported_cpu_feature`, `unhandled_interrupt`, `unhandled_exception`, `hardware_breakpoint`, `bug_check` |
| `network_events.traffic[].type` | `type` of `net_traffic` | `connect`, `bind`, `accept`, `data_in`, `data_out` |
| `network_events.traffic[].proto` | `proto` of `net_traffic` | `tcp`, `udp`, `raw`, `unknown` |
| `network_events.traffic[].proto` of an HTTP request | `proto` of `net_http` | `http`, `https` |
| none | `error.access_type` | `read`, `write`, `fetch` |
| none | `compression` of a `data` entry | `zlib` |
| none | `encoding` of a `data` entry | `base64` |

In 1.x, `ep_type` was one string with the kind of run and a detail. In 2.0, `type` holds the kind and `name` holds the detail. The JSON report leaves out `name` when the run has no detail.

| 1.x `ep_type` | 2.0 `type` | 2.0 `name` |
|---|---|---|
| `module_entry` | `module_entry` | none |
| `dll_entry.DLL_PROCESS_ATTACH` | `dll_entry` | `DLL_PROCESS_ATTACH` |
| `tls_callback_<index>` | `tls_callback` | `<index>` |
| `export.<export>` | `export` | `<export>` |
| `export.no_name` | `export` | none |
| `shellcode` | `shellcode` | none |
| `call_0x<address>` | `call` | none, the address is in `start_address` |
| `thread`, `system_thread` | `thread` | none |
| `injected_thread_<process>_<pid>` | `thread` | file name of the target process, for example `notepad.exe` |
| `thread.<process>.<pid>` | `thread` | `<process>` |
| `apc_thread_<handle>` | `thread` | `apc` |
| `thread` of a service | `service_main` | service name |
| `entry_point` | `driver_entry` | none |
| `driver_unload` | `driver_unload` | none |
| `driver_reinit` | `driver_reinit` | none |
| `irp_mj_<function>`, for example `irp_mj_create` | `irp` | `IRP_MJ_<FUNCTION>`, for example `IRP_MJ_CREATE` |

2.0 also adds data. The top-level `image_base` gives the address where Speakeasy loaded the input. Each run has `pid`, `tid`, `api_call_count` and `memory`, the memory layout and the modules at the end of the run, and `coverage` with `code.coverage`. Each region of `memory.layout` has `module` and `section` when it is a part of a module image. An `api` event has `return_address`. The `dependency_dll_entry` and `dependency_tls_callback` runs execute the initializers of a DLL that the input loads. The new events are `mem_free`, `module_load`, `file_delete`, `directory_create`, `directory_delete`, `reg_write_value`, `reg_delete_key` and `reg_delete_value`. An `api_loop_limit` error has `loop`, the call sites of the API loop that ended the run.

The models reject unknown keys (`extra="forbid"`), so `Report.model_validate_json` fails for a 1.x report. `speakeasy/resources/report.schema.json` is the JSON schema of 7.0.0, and the [report walkthrough](reporting.md) describes each key.

## Report schema 7.0.0

The 2.0 pre-releases wrote report 6.x, and the last of them wrote `6.2.0`. 2.0 writes `7.0.0`. This section gives the changes from `6.2.0`. A 6.x report does not validate against the 7.0.0 models.

Before:

```python
for ep in report.entry_points:
    for sym in ep.symbol_accesses or []:
        print(sym.symbol, sym.execs)
    for seg in ep.dynamic_code_segments:
        print(hex(seg.base), seg.pos.tick, seg.data_ref)
```

After:

```python
for run in report.runs:
    if run.accesses is not None:
        for sym in run.accesses.symbols:
            print(sym.symbol, sym.execs)
    for region in run.dynamic_code:
        for contents in region.contents:
            print(hex(region.region), contents.pos.tick, contents.data_ref)
```

These keys have new names or move:

| 6.2.0 | 7.0.0 |
|---|---|
| `entry_points` | `runs` |
| `entry_points[].symbol_accesses[]` | `runs[].accesses.symbols[]` |
| `entry_points[].memory.layout[].accesses` | `runs[].accesses.regions[]`, with the `base` of the region in `region` |
| `entry_points[].dynamic_code_segments[]` | `runs[].dynamic_code[]`, one entry for each region |
| `dynamic_code_segments[].base` | `dynamic_code[].region` |
| `dynamic_code_segments[].pos`, `dynamic_code_segments[].data_ref` | `dynamic_code[].contents[].pos`, `dynamic_code[].contents[].data_ref`, one entry of `contents` for each snapshot |
| `dynamic_code_segments[].snapshot_limit_reached` | `dynamic_code[].limit_reached` |
| `memory.layout[].is_free` | `memory.layout[].freed` |
| `error.stack[].tag`, `stack[].tag` of an `exception` event | `stack[].region`, the base of the region in `memory.layout` |
| `memory.modules[].segments[]` | the regions in `memory.layout` with the `module` and `section` of the module |

These values have a new format:

| Key | 6.2.0 | 7.0.0 |
|---|---|---|
| `tag` of a region in `memory.layout`, `address_region` and `nearby_regions` | the tag of the memory manager and the base address, such as `api.VirtualAlloc.0x450000` | the tag of the memory manager, such as `api.VirtualAlloc` |
| `tag` of a part of a module image | `emu.module.<file>.<section>.0x<base>`, such as `emu.module.sample.exe..text.0x401000`, or `emu.module.<file>.headers.0x<base>` | `emu.module`, with the file name in `module` and the section name or `headers` in `section` |
| `tag` of a region with no tag | `""` | absent |
| `tag` of a `dynamic_code` entry | the tag of the memory manager and the base address | the tag of the memory manager, absent when the region has no tag |
| `perms` of a region | `???` for some protections, absent in `address_region` and `nearby_regions` when not known | always present, three characters such as `r-x` |
| `pc_module` of an error or an `exception` event | the name of the module, such as `kernel32` | the file name of the module, such as `kernel32.dll`, the same as `memory.modules[].name` |
| `name` of a `module_load` event | the name of the module, such as `urlmon` | the file name of the module, such as `urlmon.dll`, the same as `memory.modules[].name` |
| `error.type` | `timeout`, `max_total_time`, `max_api_count`, `max_instructions`, `api_loop` | `per_run_time_limit`, `total_time_limit`, `api_call_limit`, `instruction_limit`, `api_loop_limit` |
| `pos.pc` of an event that the code of an API adds, such as `file_create` | the address of the API | the address of the call, the same as the `pc` of the `api` event of the call |

The report no longer has the run type `callback` and the `open_flags` of a `reg_open_key` event. Speakeasy did not set them.

Some keys follow a new rule for absent, empty and zero values. A key is absent when Speakeasy did not collect its data, an empty list or object means that it collected the data and found nothing, and a counter or a boolean is present when Speakeasy collects it, also when it is 0 or false. So:

- `instruction_count` and `pos.tick` are present when an option counts the instructions (`memory.accesses`, `memory.dynamic_code_contents` or `limits.instructions` above 0), also when they are 0, and absent when no option counts them. In 6.2.0, `instruction_count` was absent when it was 0, and `tick` was always present.
- `freed` is present on each region only with `memory.freed_regions`. In 6.2.0, `is_free` was always present. With `memory.freed_regions` off, the layout leaves out each freed allocation.
- `limit_reached` is present on each `dynamic_code` entry with `memory.dynamic_code_contents`. In 6.2.0, `snapshot_limit_reached` was present only on the last entry of a region that got to the limit.
- `dropped_files` is absent in kernel mode. In 6.2.0 it was an empty list.
- `instruction` of an error or an `exception` event is absent when Speakeasy cannot disassemble the instruction, for example when the pc is not mapped. In 6.2.0 it was `disasm_failed`.

With `memory.final_contents`, only the regions of guest memory have a `data_ref`: the images of the modules that load from a file, the allocations and heaps of the guest, the regions with no tag and the static TLS data. In 6.2.0, each region except the stacks had one, also the stub images of the system modules and the structures of the emulator. An empty dropped file has no `data_ref`, and the top-level `data` has only the payloads that a `data_ref` refers to. The [report walkthrough](reporting.md#memory-regions) lists the regions.

7.0.0 adds `api_call_count` to each run, and `return_address` and `calls` to each `api` event. `calls` is the number of calls that the event stands for, also the repeats that the profiler leaves out. A handler event, such as `file_create`, comes just before the `api` event of its call, with the same `tick` and `pc`.

7.0.0 also adds the top-level `processes` list (`Report.processes`, a list of `ProcessInfo`), with the `pid`, `parent_pid`, `path`, `command_line` and run indexes of each process of the runs and of the events. In 6.2.0, a consumer built the process tree from the `process_create` events, the `pid` and `path` of the memory and thread events, and the entry point `name`, and only `memory.modules` gave the emulated path of the first process. See [Processes](reporting.md#processes).

Each API call that writes or reads process memory, such as `WriteProcessMemory`, gets its own `mem_write` or `mem_read` event, and its `data_ref` has all the bytes of the call. In 6.2.0 and 1.x, the profiler merged a write or a read into the last one when its range started at the end of the last range, and it kept only the first 1024 bytes.

`get_json_report()` and the CLI write compact JSON. 6.2.0 was indented. To indent a report, use `jq . report.json`.

These Python names change in `speakeasy` and `speakeasy.report`:

| 6.2.0 | 7.0.0 |
|---|---|
| `Report.entry_points` | `Report.runs` |
| `EntryPoint` | `RunReport` |
| `EntryPointType` | `RunType` |
| `EntryPoint.symbol_accesses`, `MemoryRegion.accesses` | `RunReport.accesses`, a `MemoryAccesses` with `regions` and `symbols` |
| `SymAccessReport` | `SymbolAccesses` |
| `MemoryAccesses` (the counts of one region) | `RegionAccesses`, with `region` |
| `DynamicCodeSegment` | `DynamicCodeRegion`, with a list of `DynamicCodeContents` |
| `ModuleSegment`, `LoadedModule.segments` | removed |
| `MemoryRegion.is_free` | `MemoryRegion.freed` |
| `StackEntry.tag` | `StackEntry.region` |
| `ErrorType.TIMEOUT`, `MAX_TOTAL_TIME`, `MAX_API_COUNT`, `MAX_INSTRUCTIONS`, `API_LOOP` | `ErrorType.PER_RUN_TIME_LIMIT`, `TOTAL_TIME_LIMIT`, `API_CALL_LIMIT`, `INSTRUCTION_LIMIT`, `API_LOOP_LIMIT` |

`MemoryRegion` is a subclass of `RegionInfo`, and both have `module` and `section`.

## Exceptions

The exceptions in `speakeasy.errors` form a tree. `SpeakeasyError` is the root, and `InputError`, `ConfigError`, `EmulationError` and `EngineError` are its subclasses. See [Python exceptions](errors.md).

Two classes have new names:

| 1.x | 2.0 |
|---|---|
| `EmuException` | `CpuError` |
| `EmuEngineError` | `EngineError` |

The old names are aliases of the new classes for one release, so `except EmuException` still works. Change it to the new name.

The `Speakeasy` constructor, `load_module` and `load_shellcode` check their arguments. They convert the exceptions of other packages to `InputError` or `ConfigError`:

| Call | 1.x | 2.0 |
|---|---|---|
| `load_shellcode` with an architecture that is not x86, x64 or amd64 | `unicorn.UcError` | `InputError` |
| `load_shellcode` with a missing file | `FileNotFoundError` | `InputError` |
| `load_module` with a missing file, or a file that is not a PE | `SpeakeasyError` | `InputError` |
| `load_module` with a PE that pefile cannot parse | `pefile.PEFormatError` | `InputError` |
| `load_module` with a PE that pefile parses but the loader cannot map | `ValueError` | `InputError` |
| `load_module` with an unknown machine type | `KeyError` | `InputError` |
| `load_module` with a PE that is not x86 or x64 | `SpeakeasyError` | `InputError` |
| `load_module` or `load_shellcode` on an object that already has an input | no error, and the new emulator does not have the user hooks | `InputError` |
| `Speakeasy(volumes=...)` with a malformed volume | `ValueError` | `ConfigError` |
| `Speakeasy(volumes=...)` with a missing host path | `FileNotFoundError` | `ConfigError` |

`load_shellcode` accepts the architecture name in upper or lower case, for example `"X64"`.

Before:

```python
import unicorn

try:
    addr = se.load_shellcode(path, arch)
except (FileNotFoundError, unicorn.UcError) as err:
    print(f"cannot load {path}: {err}")
```

After:

```python
from speakeasy import InputError

try:
    addr = se.load_shellcode(path, arch)
except InputError as err:
    print(f"cannot load {path}: {err}")
```

## Hooks

Every hook callback now gets the emulator (`Win32Emulator` or `WinKernelEmulator`) as its first argument. In 1.x, the memory read, memory write, invalid memory and interrupt hooks got the `Speakeasy` object, and the dynamic code hook got only the memory map. Every `add_*_hook` method returns a hook object, also before the load, and `remove_hook` removes it. A hook that you add before `call` or `resume` now fires. [Python library usage](library.md#hooks) lists the callback of each method.

Before:

```python
def on_write(se, access, address, size, value):
    print(se.disasm(se.reg_read("eip"), 0x10))


se.add_mem_write_hook(on_write)
module = se.load_module(path)
se.run_module(module)
```

After:

```python
def on_write(emu, access, address, size, value):
    print(emu.get_disasm(emu.reg_read("eip"), 0x10))
    se.remove_hook(hook)


hook = se.add_mem_write_hook(on_write)
module = se.load_module(path)
se.run_module(module)
```

These changes can break your code:

- A memory read, memory write, invalid memory or interrupt callback gets the emulator in place of the `Speakeasy` object. Some methods have other names on the emulator, or are only on `Speakeasy`:

  | `Speakeasy` | emulator |
  |---|---|
  | `disasm(addr, size)` | `get_disasm(addr, size)` |
  | `mem_alloc(size, base, tag)` | `mem_map(size, base=base, tag=tag)` |
  | `get_stack_base()` | `stack_base` |
  | `get_all_registers()` | `get_register_state()` |
  | `get_registry_key(handle, path)` | `reg_get_key(handle, path)` |
  | `get_memory_dumps()`, `create_file_archive()` | none, keep a reference to the `Speakeasy` object |

  `Speakeasy.mem_read` and `Speakeasy.mem_write` raise `SpeakeasyError` when the access fails. The emulator methods raise `unicorn.UcError`.
- A dynamic code callback gets `(emu, region)`. In 1.x it got only `region`.
- `remove_code_hook` is removed. Use `remove_hook`.
- `add_IN_instruction_hook` and `add_SYSCALL_instruction_hook` are now `add_in_instruction_hook` and `add_syscall_instruction_hook`. The old names give a `DeprecationWarning` for one release.
- The IN hook now calls its callback with `(emu, port, size)`, and the IN instruction reads the return value. In 1.x the callback did not run. The SYSCALL hook now fires for SYSCALL and SYSENTER. In 1.x it fired only for SYSENTER. Both hooks now use `begin` and `end`.

Code that uses the internals of hooks also changes. The emulator `add_*_hook` methods do not take the `emu` argument. `Speakeasy` keeps the hooks that you add before the load in one list, `pending_hooks`, in the order that you add them. It has no `api_hooks`, `code_hooks` or other list for each hook type. The `Hook` classes in `speakeasy.common` do not take `se_obj` and `emu_eng`, and the `se_obj` attribute is now `emu`.

## Public interface and keyword-only flags

`speakeasy.__all__` lists the public names, and [Python library usage](library.md#public-interface) tells which methods are public. Import the public names from `speakeasy`. The exceptions, `SpeakeasyConfig`, `Report` and the report models, `Hook` and the hook callback types are all available there.

`speakeasy` does not export `_PeParser`. It is internal. If you must use it, import it from `speakeasy.windows.common`. A minor release can change it.

The boolean parameters of the public methods of `Speakeasy`, `Win32Emulator` and `WinKernelEmulator`, and the parameters after them, are keyword-only. A call that gives them by position raises `TypeError`. In this table, a method without a class name is a method of both emulators:

| Method | Keyword-only parameters |
|---|---|
| `Speakeasy(...)` | `debug`, `exit_event`, `gdb_port`, `volumes`, `gdb_host`, `auto_mount` |
| `Speakeasy.run_module`, `Win32Emulator.run_module`, `WinKernelEmulator.run_module` | `entry_point` |
| `Speakeasy.disasm`, `disasm`, `get_disasm` | `fast` |
| `Win32Emulator(...)`, `WinKernelEmulator(...)` | `debug`, `exit_event`, `gdb_port`, `gdb_host` |
| `file_open` | `create`, `truncate`, `disposition`, `access` |
| `reg_open_key` | `create` |
| `create_process` | `child` |
| `create_thread` | `is_suspended` |
| `mem_map` | `shared`, `process` |
| `mem_reserve` | `shared` |

The `Hook` classes take `native_hook` only as a keyword.

`run_module` has no `all_entrypoints` or `emulate_children` parameter. Set `runs.exports` and `runs.children` in the config.

Before:

```python
import speakeasy
from speakeasy import _PeParser

se = speakeasy.Speakeasy(config, argv, True)
se.run_module(module, True, False)
```

After:

```python
import speakeasy
from speakeasy.windows.common import _PeParser

config["runs"] = {"exports": True, "children": False}
se = speakeasy.Speakeasy(config, argv, debug=True)
se.run_module(module)
```

## Config file

A config file of 2.0 has `config_version` `"2.0"`, and the options are in groups. `SpeakeasyConfig` rejects unknown keys, so a 1.x config file or a config file of a 2.0 pre-release gives a `ConfigError`. This table gives the 2.0 path of each key. A key that is not in the table, such as `emu_engine`, `user.name`, `filesystem`, `registry`, `network` or `processes`, does not change.

| 1.x | 2.0 pre-release | 2.0 |
|---|---|---|
| `config_version` `0.2` | `config_version` `"2.0"` | `config_version` `"2.0"` |
| `description` | none | none, remove it |
| `system` (`"windows"`) | none | none, remove it. `system` is now a group |
| `timeout` | `max_run_time` | `limits.per_run_time` |
| none | `max_total_time` | `limits.total_time` |
| `max_api_count` | `max_api_calls` | `limits.api_calls` |
| none | `max_api_loop_calls` | `limits.api_loop_calls` |
| none | `max_instructions` | `limits.instructions` |
| none | `stack_size` | `runs.stack_size` |
| `run_module(all_entrypoints=...)` | `run_module(all_entrypoints=...)` | `runs.exports` |
| `run_module(emulate_children=...)` | `run_module(emulate_children=...)` | `runs.children` |
| `analysis.memory_tracing` | `analysis.memory_tracing` | `memory.accesses` |
| `analysis.strings` | `analysis.strings` | `memory.strings` |
| none | `snapshot_memory_regions` | `memory.final_contents` |
| none | `analysis.dynamic_code_snapshots` | `memory.dynamic_code_contents.enabled` |
| none | `analysis.dynamic_code_snapshot_limit` | `memory.dynamic_code_contents.limit` |
| `keep_memory_on_free` | `keep_memory_on_free` | `memory.freed_regions` |
| `analysis.coverage` | `analysis.coverage` | `code.coverage` |
| `modules.functions_always_exist` | `modules.functions_always_exist` | `apis.stubs` |
| `api_hammering` | `api_hammering` | none, remove it |
| `modules.modules_always_exist` | `modules.modules_always_exist` | `modules.stubs` |
| `modules.module_directory_x86`, `_x64` | `modules.module_directory_x86`, `_x64` | `modules.directory_x86`, `modules.directory_x64` |
| `modules.user_modules`, `modules.system_modules` | `modules.user_modules`, `modules.system_modules` | `modules.user`, `modules.system` |
| `exceptions.dispatch_handlers` | `exceptions.dispatch_handlers` | `exceptions.dispatch` |
| `os_ver` | `os_ver` | `system.os_ver` |
| `hostname`, `domain` | `hostname`, `domain` | `system.hostname`, `system.domain` |
| none | `start_time`, `random_seed` | `system.start_time`, `system.random_seed` |
| `drives`, `symlinks` | `drives`, `symlinks` | `system.drives`, `system.symlinks` |
| `user.is_admin` | `user.is_admin` | `user.admin` |
| `command_line`, `current_dir`, `env` | `command_line`, `current_dir`, `env` | `process.command_line`, `process.current_dir`, `process.env` |

For each key of `limits`, 0 means "no limit", and a negative value gives a `ConfigError`. In 1.x and the 2.0 pre-releases, `max_api_count` and `max_api_calls` had no value for "no limit", and `max_instructions` used -1 for "no limit". Change a `max_instructions` of -1 to a `limits.instructions` of 0.

2.0 does not patch call sites that call an API many times, so `api_hammering` has no 2.0 key. `limits.api_loop_calls` (default 5000) ends a run that makes this number of API calls with no call from a new call site, with an `api_loop_limit` error.

No group accepts `null`. The 2.0 pre-releases accepted `null` for `registry`, `network.dns`, `network.http` and `network.winsock`. Replace each `null` with the value that turns the feature off:

| 2.0 pre-release | 2.0 |
|---|---|
| `"registry": null` | `"registry": {"keys": []}` |
| `"network": {"dns": null}` | `"network": {"dns": {"names": {}, "txt": []}}` |
| `"network": {"http": null}` | `"network": {"http": {"responses": []}}` |
| `"network": {"winsock": null}` | `"network": {"winsock": {"responses": []}}` |

`system.domain`, `system.os_ver.major`, `.minor` and `.build`, and `modules.directory_x86` and `_x64` still accept `null`.

In 1.x and the 2.0 pre-releases, Speakeasy accepted these values and then gave an error or wrong data during the run. 2.0 gives a `ConfigError` (in the CLI, a usage error) for each of them:

- a negative `base_addr`, `runs.stack_size` or `byte_fill.size`
- a `byte_fill.byte` that is not one hex byte, such as `"zz"` or `"0x100"`
- a file entry with no `path` and no `byte_fill`, or with both
- a registry value `type` other than `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_BINARY`, `REG_DWORD` and `REG_QWORD`, or `REG_DWORD` or `REG_QWORD` data that is not a number
- a `system.drives[].drive_type` that is not a `DRIVE_*` name that GetDriveType gives

To give an empty file, use `"byte_fill": {"byte": "0x00", "size": 0}`.

Before, a 1.x config file:

```json
{
  "config_version": 0.2,
  "description": "triage profile",
  "system": "windows",
  "timeout": 20,
  "max_api_count": 5000,
  "analysis": {"memory_tracing": false, "strings": true, "coverage": false},
  "keep_memory_on_free": false,
  "hostname": "WIN7-LAB",
  "env": {"temp": "C:\\Windows\\temp"},
  "user": {"name": "analyst", "is_admin": false},
  "modules": {"modules_always_exist": false, "functions_always_exist": false}
}
```

After:

```json
{
  "config_version": "2.0",
  "limits": {"per_run_time": 20, "api_calls": 5000},
  "memory": {"accesses": false, "strings": true, "freed_regions": false},
  "code": {"coverage": false},
  "system": {"hostname": "WIN7-LAB"},
  "process": {"env": {"temp": "C:\\Windows\\temp"}},
  "user": {"name": "analyst", "admin": false},
  "apis": {"stubs": false},
  "modules": {"stubs": false}
}
```

A 2.0 group that the file gives keeps the defaults of the keys that the file leaves out, so this file keeps `memory.final_contents` and the other features on. [Configuration walkthrough](configuration.md) describes each key.

## Defaults

In 2.0, the features that collect analysis data or emulate more of the sample are on by default. In 1.x they were off or did not exist. A run is slower and its report is larger than in 1.x. To get the 1.x behavior, turn the features off:

| Feature | Config field | CLI flag to turn it off |
|---|---|---|
| Memory access counts | `memory.accesses` | `--no-memory-accesses` |
| Coverage | `code.coverage` | `--no-code-coverage` |
| Dynamic code contents | `memory.dynamic_code_contents.enabled` | `--no-memory-dynamic-code-contents` |
| Final memory contents | `memory.final_contents` | `--no-memory-final-contents` |
| Freed memory stays mapped | `memory.freed_regions` | `--no-memory-freed-regions` |
| Unknown modules load | `modules.stubs` | `--no-modules-stubs` |
| Unknown functions resolve | `apis.stubs` | `--no-apis-stubs` |
| Child processes run | `runs.children` | `--no-runs-children` |
| Exports run | `runs.exports` | `--no-runs-exports` |

A config file that sets a field keeps its value. In 1.x, `run_module` took the `all_entrypoints` and `emulate_children` parameters, and both defaulted to `False`. In 2.0, `run_module` reads `runs.exports` and `runs.children` from the config, and both default to `true`. The 1.x CLI always ran the exports, and `--no-runs-exports` is new.

## Debug output

`Speakeasy(debug=True)` logs each instruction and the registers to the `speakeasy.windows.winemu` logger at the DEBUG level. In 1.x it wrote them to stdout. To see them, set the level of the `speakeasy` logger to `DEBUG` and add a handler.

## Environment variables

`process.env` names in a config are not case-sensitive. `SpeakeasyConfig` stores each name in lower case, so read `config.process.env["temp"]`, not `config.process.env["TEMP"]`. In 1.x, the API handlers looked up the lower-case name, so the emulated process did not see a config `env` name with upper-case letters.

## Command line

Many flags have new names, and some short flags are removed. The CLI rejects the 1.x names and abbreviated flags with an argument error and exit status 2.

| 1.x | 2.0 |
|---|---|
| `-p`, `--params` with one argument for each parameter | `--argv` with one quoted string, for example `--argv="-log -path out.txt"` |
| `-m`, `--mem-tracing` | `--memory-accesses` |
| `-r`, `--raw` | `--raw` |
| `--raw_offset` | `--raw-offset` |
| `-a`, `--arch` | `--arch` |
| `-q`, `--timeout` | `--limits-per-run-time` |
| `-z`, `--dropped-files` | `--dropped-files-path` |
| `-l`, `--module-dir` | `--modules-directory-x86` and `--modules-directory-x64` |
| `-d`, `--dump` | none, use `Speakeasy.get_memory_dumps()` |

`-t`, `-o`, `-c` and `--no-mp` do not change. `-k` stays as the short form of `--runs-children`, but it is the default now, and `--no-runs-children` turns it off.

The 2.0 pre-releases had other names for many flags. The `--no-` form of each boolean flag changes in the same way, for example `--no-analysis-coverage` to `--no-code-coverage`:

| 2.0 pre-release | 2.0 |
|---|---|
| `--timeout`, `--max-run-time` | `--limits-per-run-time` |
| `--max-total-time` | `--limits-total-time` |
| `--max-api-count`, `--max-api-calls` | `--limits-api-calls` |
| `--max-api-loop-calls` | `--limits-api-loop-calls` |
| `--max-instructions` | `--limits-instructions` |
| `--stack-size` | `--runs-stack-size` |
| `-k`, `--emulate-children` | `-k`, `--runs-children` |
| `--all-entrypoints` | `--runs-exports` |
| `--analysis-memory-tracing` | `--memory-accesses` |
| `--analysis-strings` | `--memory-strings` |
| `--analysis-coverage` | `--code-coverage` |
| `--analysis-dynamic-code-snapshots` | `--memory-dynamic-code-contents` |
| `--analysis-dynamic-code-snapshot-limit` | `--memory-dynamic-code-contents-limit` |
| `--snapshot-memory-regions` | `--memory-final-contents` |
| `--keep-memory-on-free` | `--memory-freed-regions` |
| `--exceptions-dispatch-handlers` | `--exceptions-dispatch` |
| `--modules-always-exist`, `--modules-modules-always-exist` | `--modules-stubs` |
| `--modules-functions-always-exist` | `--apis-stubs` |
| `--module-directory-x86`, `--modules-module-directory-x86` | `--modules-directory-x86` |
| `--module-directory-x64`, `--modules-module-directory-x64` | `--modules-directory-x64` |
| `--os-ver-major`, `--os-ver-minor`, `--os-ver-build` | `--system-os-ver-major`, `--system-os-ver-minor`, `--system-os-ver-build` |
| `--os-ver-release` | none |
| `--hostname`, `--domain` | `--system-hostname`, `--system-domain` |
| `--start-time`, `--random-seed` | `--system-start-time`, `--system-random-seed` |
| `--user-is-admin` | `--user-admin` |
| `--current-dir`, `--command-line`, `--env` | `--process-current-dir`, `--process-command-line`, `--process-env` |

`--raw-offset` takes a decimal number, like `--entry-point`. Write `0x` before a hex offset. In 1.x, `--raw_offset` was always hex, so `--raw_offset 10` started at offset 0x10.

Before:

```bash
speakeasy -t shellcode.bin -r -a x86 --raw_offset 10 -o report.json
```

After:

```bash
speakeasy -t shellcode.bin --raw --arch x86 --raw-offset 0x10 -o report.json
```

These changes can also break a script:

- `--raw` without `--arch` is an argument error, and the CLI exits 2. `--arch` takes only `x86`, `x64` or `amd64`.
- Without `-o`, the CLI writes the report JSON to stdout. In 1.x it wrote no report.
- The CLI stops the emulation process after `--limits-total-time`. `--limits-per-run-time` applies to each run, so it does not stop the process. In 1.x, `--timeout 0` did not stop the process.

[CLI reference](cli-reference.md#output-and-exit-status) gives the exit status of each result.
