# Python library usage

You can use Speakeasy as a Python library through the `speakeasy.Speakeasy` interface.

## Minimal DLL emulation flow

```python
import speakeasy

se = speakeasy.Speakeasy()
module = se.load_module("sample.dll")
se.run_module(module, all_entrypoints=True)
report = se.get_report()
se.shutdown()
```

## Calling a specific export

```python
import speakeasy

se = speakeasy.Speakeasy()
module = se.load_module("sample.dll")
se.run_module(module)

for export in module.get_exports():
    if export.name == "myexport":
        se.call(export.address, [0x0, 0x1])

report = se.get_report()
se.shutdown()
```

## Library options you may want

- pass `config=` to control environment and analysis
- pass `argv=` to populate emulated process arguments
- pass `volumes=` to mount host paths into emulated filesystem
- pass `gdb_port=` to block for GDB attach before execution; `gdb_host=` controls the bind address and defaults to `127.0.0.1`

## Hooks

Each `add_*_hook` method calls its callback with the emulator as the first argument. You can add a hook before or after `load_module`. The method returns a hook object, and `se.remove_hook(hook)` removes the hook. `speakeasy.hooks` has a `Protocol` for each callback type.

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

The SYSCALL hook fires for SYSCALL and SYSENTER. Only one IN hook runs for an instruction: the first hook that is enabled and covers the address. When `exceptions.dispatch_handlers` is set, the user mode emulator adds its own IN hook at the start of the first run. That hook raises a privileged instruction exception, as Windows does. An IN hook that you add before the run comes first, so it replaces the exception.

This code hook runs one time, then removes itself:

```python
def on_first_instruction(emu, address, size):
    print(f"first instruction at 0x{address:x}")
    se.remove_hook(hook)


hook = se.add_code_hook(on_first_instruction)
```

`se.add_api_hook(cb, "user32", "MessageBox*")` calls `cb(emu, api_name, func, params)` in place of the handler. `params` holds the raw argument slots, and `func(params)` runs the handler. After that call, `emu.get_api_args()` returns the arguments as the report shows them, with the values the handler decoded:

```python
def hook_messagebox(emu, api_name, func, params):
    rv = func(params)
    print(emu.get_api_args()[1].display)  # the lpText string
    return rv
```

For runnable scripts, see [../examples](../examples/).

## Errors

The library raises the exceptions in `speakeasy.errors`, which all derive from `SpeakeasyError`. A missing or unsupported input raises `InputError`, and a configuration or volume that is not valid raises `ConfigError`. [Python exceptions](errors.md) lists the tree and the exceptions of each method.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [Python exceptions](errors.md)
- [Mounting host files with --volume](volumes.md)
- [GDB debugging reference](gdb.md)
- [Help and troubleshooting](help.md)
