# Python library usage

To use Speakeasy from Python, create a `speakeasy.Speakeasy` object. One object emulates one input. If the object already has an input, `load_module` and `load_shellcode` raise `InputError`. To emulate a different input, create a new object.

## Public interface

The public interface is the names in `speakeasy.__all__`, and the methods of `Win32Emulator` and `WinKernelEmulator` (including the methods they inherit) whose names do not start with `_`. Speakeasy follows semantic versioning for this interface: only a major release removes a name or changes a signature in a way that breaks a caller. Import these names from `speakeasy`, for example `from speakeasy import Speakeasy, InputError`.

All other modules, such as `speakeasy.windows.winemu` or `speakeasy.winenv.api`, are internal, and a minor release can change them. You can use `speakeasy.defs` and `speakeasy.arch` for the structures and constants of the Windows API, but they are internal too.

The boolean parameters of the public methods are keyword-only, for example `se.disasm(addr, size, fast=False)`. `run_module` takes only `entry_point` as a keyword. The config controls which runs it starts.

## Minimal DLL emulation flow

```python
import speakeasy

se = speakeasy.Speakeasy()
module = se.load_module("sample.dll")
se.run_module(module)
report = se.get_report()
se.shutdown()
```

## Calling a specific export

```python
import speakeasy

se = speakeasy.Speakeasy(config={"runs": {"exports": False}})
module = se.load_module("sample.dll")
se.run_module(module)

for export in module.get_exports():
    if export.name == "myexport":
        se.call(export.address, [0x0, 0x1])

report = se.get_report()
se.shutdown()
```

## Options

The `Speakeasy` constructor takes these arguments. `config=` sets the emulated environment and the analysis options, as a dict or a `SpeakeasyConfig` (see [Configuration walkthrough](configuration.md)). `argv=` sets the arguments of the emulated program. `volumes=` mounts host paths into the emulated file system, and it requires a dict or no `config=`. With `gdb_port=`, the first run waits for a GDB client before it starts (see [GDB debugging reference](gdb.md)). `gdb_host=` sets the address on which the GDB server listens, and its default is `127.0.0.1`.

The defaults turn on all the features. The [feature options](configuration.md#feature-options) of the config are on, so the report has coverage, memory access counts and the final memory contents. `run_module` runs the exports of a DLL (`runs.exports`) and the child processes that the sample starts (`runs.children`). To get a faster run or a smaller report, set an option to `False`.

## Hooks

The emulator calls each hook callback with the emulator as the first argument. You can add a hook before or after `load_module`. Each `add_*_hook` method returns a hook object, and `se.remove_hook(hook)` removes the hook. `speakeasy` has a `Protocol` for each callback type, for example `CodeHookCallback`.

| Method | Callback | Return value of the callback |
|---|---|---|
| `add_api_hook(cb, module, api_name)` | `cb(emu, api_name, func, params)` | the return value of the API |
| `add_code_hook(cb, begin, end)` | `cb(emu, address, size)` | not used |
| `add_mem_read_hook(cb, begin, end)` | `cb(emu, access, address, size, value)` | not used |
| `add_mem_write_hook(cb, begin, end)` | `cb(emu, access, address, size, value)` | not used |
| `add_mem_invalid_hook(cb)` | `cb(emu, access, address, size, value)` | `False` fails the access and stops the hooks after it |
| `add_mem_map_hook(cb, begin, end)` | `cb(emu, base, size, tag, perms, flags)` | not used |
| `add_interrupt_hook(cb)` | `cb(emu, number)` | not used |
| `add_invalid_instruction_hook(cb)` | `cb(emu)` | `True` if the callback handled the instruction |
| `add_dyn_code_hook(cb)` | `cb(emu, region)` | not used |
| `add_in_instruction_hook(cb, begin, end)` | `cb(emu, port, size)` | the value that the IN instruction reads |
| `add_syscall_instruction_hook(cb, begin, end)` | `cb(emu)` | not used |

The emulator calls a SYSCALL hook for SYSCALL and SYSENTER. For an IN instruction, the emulator calls only the first IN hook that is enabled and covers the address. When `exceptions.dispatch` is set, the user mode emulator adds its own IN hook at the start of the first run. That hook raises a privileged instruction exception, as Windows does. If you add an IN hook before the run, your hook comes first, so the exception does not occur.

This code hook runs one time, then removes itself:

```python
def on_first_instruction(emu, address, size):
    print(f"first instruction at 0x{address:x}")
    se.remove_hook(hook)


hook = se.add_code_hook(on_first_instruction)
```

After `se.add_api_hook(cb, "user32", "MessageBox*")`, the emulator calls `cb(emu, api_name, func, params)` in place of the handler. `params` holds the raw argument slots, and `func(params)` runs the handler. `func` is `None` when the API has no handler. After `func(params)`, `emu.get_api_args()` returns the arguments as the report shows them, with the values that the handler decoded:

```python
def hook_messagebox(emu, api_name, func, params):
    rv = func(params)
    print(emu.get_api_args()[1].display)  # the lpText string
    return rv
```

For runnable scripts, see [../examples](../examples/).

## Errors

The library raises the exceptions that `speakeasy` exports, which all derive from `SpeakeasyError`. A missing or unsupported input raises `InputError`, and a configuration or volume that is not valid raises `ConfigError`. [Python exceptions](errors.md) lists the tree and the exceptions of each method.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [Python exceptions](errors.md)
- [Mounting host files with --volume](volumes.md)
- [GDB debugging reference](gdb.md)
- [Help and troubleshooting](help.md)
