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

## What happens without a handler

Imports that have no `@apihook` are not necessarily fatal. Speakeasy ships a signature database generated from Microsoft's [win32metadata](https://github.com/microsoft/win32metadata) (via the [win32json](https://github.com/marlersoft/win32json) export, vendored as the `deps/win32json` submodule). When an import misses every handler, `Win32Emulator.handle_import_func` looks the function up there and, if it is declared, emulates the call from its prototype: it reads the right number of argument slots, decodes `PSTR`/`PWSTR`/`BOOL` arguments for the trace, renders enum and flag parameters symbolically (`dwCreationDisposition: CREATE_ALWAYS`, `dwShareMode: FILE_SHARE_WRITE|FILE_SHARE_READ`), expands pointers to known structs into a JSON-like rendering with typed fields (`lpSecurityAttributes: {nLength: 0xc, lpSecurityDescriptor: 0x0, bInheritHandle: TRUE}`, following nested pointers one level so `OBJECT_ATTRIBUTES.ObjectName` shows its string), zero-fills `Out` buffers whose size the prototype declares, returns a type-appropriate success value, and cleans up the stack according to the calling convention. Such calls are logged with parameter names (`lpFileName: "C:\\x"`) so they are easy to tell apart from handled APIs in a report.

Hand-written handlers always take precedence, and are still required whenever a sample depends on the *behavior* of an API (output parameters, objects, files, network). The fallback only keeps emulation coherent and the trace informative.

### Regenerating the signature database

The database lives at `speakeasy/resources/win32/signatures.json.gz`. It is a build artifact, not committed: `python -m build` regenerates it (see `setup.py`), and for a source checkout run

```console
just gen-signatures
# or
git submodule update --init deps/win32json
python scripts/gen_win32_signatures.py --stats
```

Without it Speakeasy still works; it just logs a warning and falls back to the previous `Unsupported API` behavior.

win32metadata records neither calling conventions nor variadic parameters, so those are supplied by hand in `scripts/win32_overrides.json` (`cdecl_dlls`, `cdecl`, `variadic`, plus `dll_aliases`/`name_prefixes` for forwarders such as `psapi!EnumProcesses` -> `kernel32!K32EnumProcesses`). Edit that file and regenerate to correct a declaration; never patch the generated file.

`tests/test_apihook_signatures.py` cross-checks every `@apihook`'s `argc` against the database, so a hook that disagrees with the documented prototype fails CI.

The rendering logic lives in `speakeasy.winenv.api.sigfmt.ArgFormatter`; it caps nesting depth, array length and total output size so a trace line stays readable.

Additional signature sources (for example undocumented `ntdll` natives) can be plugged in by implementing `speakeasy.winenv.api.sigdb.SignatureSource` and adding it to `emu.get_signature_db()`.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Limitations](limitations.md)
- [Configuration walkthrough](configuration.md)
- [Help and troubleshooting](help.md)
