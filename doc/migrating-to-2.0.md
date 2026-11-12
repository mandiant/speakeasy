# Migrating to 2.0

This page tells you how to move code and scripts from Speakeasy 1.x to 2.0. It covers the Python library and the command line. Each section names a change to the interface and tells you what to change in your code or command.

## Report schema 6.1.0

The report of 2.0 has `report_version` `6.1.0`. The report of 1.x has `1.1.0`. `Speakeasy.get_report` returns a `Report`, a pydantic model from `speakeasy.report`. In 1.x it returned a plain dict.

In 1.x, each entry point had one list for each kind of event: `apis`, `file_access`, `registry_access`, `network_events` (with `dns` and `traffic`), `process_events` and `handled_exceptions`. It also had `mem_access`, `sym_accesses`, `dynamic_code_segments` and `dropped_files`. In 2.0, an entry point has one `events` list in execution order in place of the event lists. The `event` key of each event gives its kind, and `pos` gives the tick, thread, process and `pc` of the event. `mem_access` moves to `memory`, and `sym_accesses` has a new name. Each entry of `dynamic_code_segments` has the new `pos`, and with `--analysis-dynamic-code-snapshots` a `data_ref`, one more entry for each later snapshot of the region, and `snapshot_limit_reached` on the last entry of a region that got to the limit. `dropped_files` does not change.

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
for ep in report.entry_points:
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
| `mem_access[]` | `memory.layout[]`, with the counts in `accesses` |

These keys have new names:

| 1.x | 2.0 |
|---|---|
| `filetype` | `file_type` |
| `entry_points[].ep_type` | `type` and `name`, see the table below |
| `entry_points[].start_addr` | `start_address` |
| `entry_points[].ep_args` | `args` |
| `entry_points[].instr_count` | `instruction_count` |
| `entry_points[].apihash` | `api_hash` |
| `entry_points[].sym_accesses` | `symbol_accesses` |
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
| `errors[]` | `errors[]` | traceback text | an object like `entry_points[].error` |
| `error.stack[]` | `error.stack[]` | `"sp+0x04: 0x0012ff80 -> emu.stack.0x1200000"` | `{"offset": 4, "value": "0x12ff80", "tag": "emu.stack.0x1200000"}` |
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
| `entry_points[].ep_type` | `type` | `module_entry`, `dll_entry`, `tls_callback`, `export`, `shellcode`, `thread`, `service_main`, `dependency_dll_entry`, `dependency_tls_callback`, `call`, `callback`, `driver_entry`, `driver_unload`, `driver_reinit`, `irp` |
| `error.type` | `error.type` | `timeout`, `max_total_time`, `max_instructions`, `max_api_count`, `unsupported_api`, `internal_error`, `engine_stopped`, `invalid_image`, `dll_initialization_failed`, `api_handler_did_not_return`, `invalid_read`, `invalid_write`, `invalid_fetch`, `invalid_protect_read`, `invalid_protect_write`, `invalid_protect_fetch`, `guard_page_violation`, `privileged_instruction`, `invalid_instruction`, `unsupported_cpu_feature`, `unhandled_interrupt`, `unhandled_exception`, `hardware_breakpoint`, `bug_check` |
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

2.0 also adds data. The top-level `image_base` gives the address where Speakeasy loaded the input. Each entry point has `pid`, `tid` and `memory`, the memory layout and the modules at the end of the run, and `coverage` with `--analysis-coverage`. The `dependency_dll_entry` and `dependency_tls_callback` runs execute the initializers of a DLL that the input loads. The new events are `mem_free`, `module_load`, `file_delete`, `directory_create`, `directory_delete`, `reg_write_value`, `reg_delete_key` and `reg_delete_value`.

The models reject unknown keys (`extra="forbid"`), so `Report.model_validate_json` fails for a 1.x report. `speakeasy/resources/report.schema.json` is the JSON schema of 6.1.0, and the [report walkthrough](reporting.md) describes each key.

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
| `Speakeasy(...)` | `debug`, `exit_event`, `gdb_port`, `volumes`, `gdb_host` |
| `Speakeasy.run_module`, `Win32Emulator.run_module` | `all_entrypoints`, `emulate_children`, `entry_point` |
| `WinKernelEmulator.run_module` | `all_entrypoints`, `entry_point` |
| `Speakeasy.disasm`, `disasm`, `get_disasm` | `fast` |
| `Win32Emulator(...)`, `WinKernelEmulator(...)` | `debug`, `exit_event`, `gdb_port`, `gdb_host` |
| `file_open` | `create`, `truncate`, `disposition`, `access` |
| `reg_open_key` | `create` |
| `create_process` | `child` |
| `create_thread` | `is_suspended` |
| `mem_map` | `shared`, `process` |
| `mem_reserve` | `shared` |

The `Hook` classes take `native_hook` only as a keyword.

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

se = speakeasy.Speakeasy(config, argv, debug=True)
se.run_module(module, all_entrypoints=True, emulate_children=False)
```

## Defaults

In 2.0, the features that collect analysis data or emulate more of the sample are on by default. In 1.x they were off or did not exist. A run is slower and its report is larger than in 1.x. To get the 1.x behavior, turn the features off:

| Feature | Config field or parameter | CLI flag to turn it off |
|---|---|---|
| Memory tracing | `analysis.memory_tracing` | `--no-analysis-memory-tracing` |
| Coverage | `analysis.coverage` | `--no-analysis-coverage` |
| Dynamic code snapshots | `analysis.dynamic_code_snapshots` | `--no-analysis-dynamic-code-snapshots` |
| Memory region snapshots | `snapshot_memory_regions` | `--no-snapshot-memory-regions` |
| Freed memory stays mapped | `keep_memory_on_free` | `--no-keep-memory-on-free` |
| API hammering mitigation | `api_hammering.enabled` | `--no-api-hammering-enabled` |
| Unknown modules load | `modules.modules_always_exist` | `--no-modules-always-exist` |
| Unknown functions resolve | `modules.functions_always_exist` | `--no-modules-functions-always-exist` |
| Child processes run | `run_module(emulate_children=...)` | `--no-emulate-children` |
| Exports run | `run_module(all_entrypoints=...)` | `--no-all-entrypoints` |

A config file that sets a field keeps its value. In the library, `Speakeasy.run_module`, `Win32Emulator.run_module` and `WinKernelEmulator.run_module` default to `all_entrypoints=True`, and the user mode `run_module` methods default to `emulate_children=True`. In 1.x both were `False`. The CLI always ran the exports, and `--no-all-entrypoints` is new.

## Debug output

`Speakeasy(debug=True)` logs each instruction and the registers to the `speakeasy.windows.winemu` logger at the DEBUG level. In 1.x it wrote them to stdout. To see them, set the level of the `speakeasy` logger to `DEBUG` and add a handler.

## Environment variables

`env` names in a config are not case-sensitive. `SpeakeasyConfig` stores each name in lower case, so read `config.env["temp"]`, not `config.env["TEMP"]`. In 1.x, the API handlers looked up the lower-case name, so the emulated process did not see a config `env` name with upper-case letters.

## Command line

Many flags have new names, and some short flags are removed. The CLI rejects the 1.x names and abbreviated flags with an argument error and exit status 2.

| 1.x | 2.0 |
|---|---|
| `-p`, `--params` with one argument for each parameter | `--argv` with one quoted string, for example `--argv="-log -path out.txt"` |
| `-m`, `--mem-tracing` | `--analysis-memory-tracing` |
| `-r`, `--raw` | `--raw` |
| `--raw_offset` | `--raw-offset` |
| `-a`, `--arch` | `--arch` |
| `-q`, `--timeout` | `--max-run-time` |
| `-z`, `--dropped-files` | `--dropped-files-path` |
| `-l`, `--module-dir` | `--module-directory-x86` and `--module-directory-x64` |
| `-d`, `--dump` | none, use `Speakeasy.get_memory_dumps()` |

`-t`, `-o`, `-c` and `--no-mp` do not change. `-k` stays, but it is the default now, and `--no-emulate-children` turns it off. The 2.0 pre-releases had other names for some flags:

| 2.0 pre-release | 2.0 |
|---|---|
| `--timeout` | `--max-run-time` |
| `--max-api-count` | `--max-api-calls` |
| `--modules-module-directory-x86`, `--modules-module-directory-x64` | `--module-directory-x86`, `--module-directory-x64` |
| `--modules-modules-always-exist`, `--no-modules-modules-always-exist` | `--modules-always-exist`, `--no-modules-always-exist` |
| `--os-ver-release` | none |

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
- The CLI stops the emulation process after `--max-total-time`. `--max-run-time` applies to each run, so it does not stop the process. In 1.x, `--timeout 0` did not stop the process.

[CLI reference](cli-reference.md#output-and-exit-status) gives the exit status of each result.
