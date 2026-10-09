# Adding API handlers

Like most emulators, Speakeasy handles OS API calls in framework code. You can add a handler by defining a function with the expected API name in the corresponding emulated module.

Handler rules:

- specify `argc` so stack cleanup is correct
- if calling convention is omitted, stdcall is assumed
- `argv` contains the raw integer argument slots; handlers do not change it
- to show a decoded value in the report, set the `display` of the argument in `ctx.args` (for example `ctx.args["lpFileName"].display = path`)
- return the value expected by the sample path

For some APIs, returning a success code is enough to keep execution on a useful path.

## Example: HeapAlloc in kernel32

```python
@apihook("HeapAlloc", argc=3)
def HeapAlloc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
    hHeap, dwFlags, dwBytes = argv

    chunk = self.heap_alloc(dwBytes, heap="HeapAlloc")
    if chunk:
        emu.set_last_error(windefs.ERROR_SUCCESS)

    return chunk
```

## What happens without a handler

Imports that have no `@apihook` are not necessarily fatal. Speakeasy ships a signature database generated from Microsoft's [win32metadata](https://github.com/microsoft/win32metadata) (via the [win32json](https://github.com/marlersoft/win32json) export, vendored as the `deps/win32json` submodule). When an import misses every handler, `Win32Emulator.handle_import_func` looks the function up there and, if it is declared, emulates the call from its prototype: it reads the right number of argument slots, decodes `PSTR`/`PWSTR`/`BOOL` arguments for the trace, renders enum and flag parameters symbolically (`dwCreationDisposition: CREATE_ALWAYS`, `dwShareMode: FILE_SHARE_WRITE|FILE_SHARE_READ`), expands pointers to known structs into a JSON-like rendering with typed fields (`lpSecurityAttributes: {nLength: 0xc, lpSecurityDescriptor: 0x0, bInheritHandle: TRUE}`, following nested pointers one level so `OBJECT_ATTRIBUTES.ObjectName` shows its string), zero-fills `Out` buffers whose size the prototype declares, returns a type-appropriate success value, and cleans up the stack according to the calling convention. Each argument in the event of such a call has the parameter name, its type, the raw value, and the rendering (see [reporting](reporting.md)).

Calls served by a handler use the same signature to name and render their arguments when its slot count equals the handler's `argc`. The arguments are rendered before the handler runs. `ctx.args` gives the handler one entry per parameter, by name (`ctx.args["hKey"]`) or by parameter index. A handler that sets `display` replaces the rendering of that parameter. The type of the argument becomes `str` if the parameter is declared as a string, and `text` otherwise. A display for a parameter that the signature renders as an enum or flags does not replace that rendering, so all such values have one format. A value that is not a string, such as `None` from a failed lookup or a NULL pointer the handler did not decode, keeps the current display.

Handlers without a matching signature (the C runtime, kernel-mode APIs, COM methods) record one unnamed argument per slot. These handlers use the slot index (`ctx.args[0]`), because a name finds no argument. A name or index that matches no argument gives a detached entry, and its changes are not recorded. Variadic handlers add entries with `ctx.args.append(text)` and remove all entries with `ctx.args.clear()`. `tests/test_handler_arg_access.py` checks that each name a handler uses is a parameter of every signature of that function, and that each index means the same parameter on x86 and x64.

Hand-written handlers always take precedence, and are still required whenever a sample depends on the *behavior* of an API (output parameters, objects, files, network). The fallback only keeps emulation coherent and the trace informative.

Undocumented native APIs (`Nt*`/`Zw*`, `Rtl*`, `Ldr*`, `Csr*`, `Dbg*` ...) come from a second source generated from the [phnt](https://github.com/winsiderss/phnt) headers (MIT, vendored as `deps/phnt`) by `scripts/gen_phnt_signatures.py`: about 2,500 prototypes with SAL-derived direction and buffer-size annotations and the information-class enums (`SystemInformationClass: SystemProcessInformation`). phnt struct layouts are not parsed; a `ps:` pointer resolves against every loaded source, so structs win32metadata also declares (`OBJECT_ATTRIBUTES`, `UNICODE_STRING`, `LARGE_INTEGER`, `CLIENT_ID`) still render and phnt-only structs show as pointers. The win32metadata source is consulted first.

### Regenerating the signature databases

The databases live at `speakeasy/resources/win32/win32json_signatures.json.gz` (win32metadata) and `speakeasy/resources/win32/phnt_signatures.json.gz` (phnt). They are build artifacts, not committed: `python -m build` regenerates them (see `setup.py`), and for a source checkout run

```console
just gen-signatures
# or
git submodule update --init deps/win32json deps/phnt
python scripts/gen_win32_signatures.py --stats
python scripts/gen_phnt_signatures.py --stats
```

Without them Speakeasy still works; it logs a warning per missing database and falls back to the previous `Unsupported API` behavior for the imports that database would have covered.

win32metadata records neither calling conventions nor variadic parameters, so those are supplied by hand in `scripts/win32_overrides.json` (`cdecl_dlls`, `cdecl`, `variadic`, plus `dll_aliases`/`name_prefixes` for forwarders such as `psapi!EnumProcesses` -> `kernel32!K32EnumProcesses`). For prototypes whose header declares no parameter names, win32metadata records `param0`, `param1`, and so on; `param_names` gives the names from the documentation. Edit that file and regenerate to correct a declaration; never patch the generated file.

`tests/test_apihook_signatures.py` cross-checks every `@apihook`'s `argc` against the database, so a hook that disagrees with the documented prototype fails CI.

The rendering logic lives in `speakeasy.winenv.api.sigfmt.ArgFormatter`; it caps nesting depth, array length and total output size so a trace line stays readable.

Additional signature sources (for example vendor-specific DLLs) can be plugged in by implementing `speakeasy.winenv.api.sigdb.SignatureSource` and adding it to `emu.get_signature_db()`.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Limitations](limitations.md)
- [Configuration walkthrough](configuration.md)
- [Help and troubleshooting](help.md)
