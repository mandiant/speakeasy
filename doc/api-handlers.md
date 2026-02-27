# Adding API handlers

Like most emulators, Speakeasy handles OS API calls in framework code. You can add a handler by defining a function with the expected API name in the corresponding emulated module.

Handler rules:

- specify `argc` so stack cleanup is correct
- if calling convention is omitted, stdcall is assumed
- `argv` contains raw integer arguments
- return the value expected by the sample path

For some APIs, returning a success code is enough to keep execution on a useful path.

## Example: HeapAlloc in kernel32

```python
@apihook("HeapAlloc", argc=3)
def HeapAlloc(self, emu, argv, ctx={}):
    hHeap, dwFlags, dwBytes = argv

    chunk = self.heap_alloc(dwBytes, heap="HeapAlloc")
    if chunk:
        emu.set_last_error(windefs.ERROR_SUCCESS)

    return chunk
```

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Limitations](limitations.md)
- [Configuration walkthrough](configuration.md)
- [Help and troubleshooting](help.md)
