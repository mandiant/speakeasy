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
- pass `gdb_port=` to block for GDB attach before execution

For runnable scripts, see [../examples](../examples/).

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [Mounting host files with --volume](volumes.md)
- [GDB debugging reference](gdb.md)
- [Help and troubleshooting](help.md)
