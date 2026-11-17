# Adding API handlers

Speakeasy emulates Windows APIs with Python handlers. Each emulated DLL has a handler class in `speakeasy/winenv/api/usermode` or `speakeasy/winenv/api/kernelmode`. To add a handler, add a method with the `@apihook` decorator and the API name to the class of the DLL.

Follow these rules when you write a handler:

- give `argc`, so that the emulator removes the correct number of arguments from the stack
- give `conv` if the API does not use stdcall. The decorator uses stdcall by default
- `argv` has the raw integer argument slots. Do not change it
- annotate `argv` as `list[int]` and `emu` as the emulator that runs the handler: `Win32Emulator` in `usermode` modules and `WinKernelEmulator` in `kernelmode` modules. msvcrt and ntoskrnl handlers run in both modes, so they use `WindowsEmulator`
- unpack `argv` into locals with the parameter names of the prototype, as in the example below. When a name is a Python keyword or hides a builtin that the handler uses, use a similar name (`in_` for `in`, `blen` for `len`)
- to show a decoded value in the report, set the `display` of the argument in `ctx.args` (for example `ctx.args["lpFileName"].display = path`)
- import Windows constants from `speakeasy/winenv/defs`, and do not define them again in a handler module. An SDK enum or flag set is an `IntEnum` or `IntFlag` class in `speakeasy/winenv/defs/enums.py`. `scripts/gen_win32_enums.py` writes that module from win32json. To add a class, add its name to `scripts/win32_enums.json` and run the script again. To get the name of a value, call `decode(PAGE_PROTECTION_FLAGS, flProtect)` from `speakeasy.winenv.defs.lookup`.
- a struct class in `speakeasy/winenv/defs` must have the size and the field offsets of the Windows struct on x86 and x64. Declare each field at class level in the C order, as `cb: Annotated[int, ct.c_uint32]`, or with its struct class for a nested struct (`Name: UNICODE_STRING`). Declare a pointer-sized field (`HANDLE`, `SIZE_T`, `ULONG_PTR`) as `Ptr`. `tests/test_struct_layouts.py` checks the layouts against win32json (`deps/win32json`) and against a table of kernel structs.
- write integers to guest memory with `self.write_dword`, `self.write_qword` or `self.write_ptr`, and read them with `self.read_dword` or `self.read_ptr`. The write helpers call `ApiHandler.mem_write`, which also writes to the other views of a shared file mapping
- return the value that the API returns on Windows for the same input
- one handler instance serves all processes and threads, so put state that the guest can see on the `Process` or `Thread` object, for example `Process.command_line_buffers`
- read and write `A` strings with `read_mem_string`, `write_mem_string`, `decode_string` and `encode_string`, These functions use the ANSI code page (1252) for a character width of 1. Do not select a Python codec for guest text
- to compare two strings, call `get_string_order` from `speakeasy.winenv.api.compare` with the case fold (`Fold`) of the API. `get_string_order` returns -1, 0 or 1
- start the docstring with the C prototype from the SDK, DDK, phnt or CRT headers, as in the example below. Put one parameter on each line, leave out the calling convention, the linkage and the SAL annotations, and put the closing `);` on its own line. Use the hook name as the function name. A hook without the `A` or `W` suffix uses the generic name and TCHAR types (`LPCTSTR`). Take the parameter names from the Microsoft documentation. When the signature database has other names, use those, because the report and `ctx.args` use them. Put notes about the emulation after a blank line. In a handler for exported data (`@impdata`), give the C declaration of the variable

For some APIs, a handler that only returns a success code is sufficient for the sample to continue.

A handler gets the object of a handle with a typed lookup, for example `emu.get_handle_table().get(hEvent, objman.Event)`. The lookup returns None when the handle is not open or when the object has a different type. Then the handler returns the failure value of its API and sets the last error as Windows does. For example, `SetEvent` sets `ERROR_INVALID_HANDLE` and returns 0.

When a module has no handler for a name, Speakeasy tries related names. `get_handler_candidates` in `speakeasy/windows/api_resolution.py` gives them in order. For example, a handler without the `A` or `W` suffix serves both variants, and `Nt` and `Zw` names share a handler.

An API set uses the handlers of the module that implements it. `DLL_HOSTS` in `speakeasy/windows/common.py` lists the modules for each name prefix. For example, `api-ms-win-core-com-*` uses ole32. When a set has functions in more than one module, an import uses the first module that has a handler for the name.

`DLL_HOSTS` also lists some DLLs that use the handlers of a related DLL. For example, wsock32 uses ws2_32.

## Example: HeapAlloc in kernel32

```python
@apihook("HeapAlloc", argc=3)
def HeapAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
    """
    LPVOID HeapAlloc(
        HANDLE hHeap,
        DWORD dwFlags,
        SIZE_T dwBytes
    );
    """
    hHeap, dwFlags, dwBytes = argv

    chunk = self.heap_alloc(dwBytes, heap="HeapAlloc")
    if chunk:
        emu.set_last_error(windefs.ERROR_SUCCESS)

    return chunk
```

## What happens without a handler

A call to an import without an `@apihook` does not always stop the run. Speakeasy has a signature database that it generates from Microsoft's [win32metadata](https://github.com/microsoft/win32metadata), through the [win32json](https://github.com/marlersoft/win32json) export in the `deps/win32json` submodule. When no handler matches an import, `WindowsEmulator.dispatch_api_call` looks for the function in the database. If the database declares it, the emulator emulates the call from the prototype:

- It reads the correct number of argument slots.
- It decodes `PSTR`, `PWSTR` and `BOOL` arguments for the trace.
- It shows enum and flag parameters by name (`dwCreationDisposition: CREATE_ALWAYS`, `dwShareMode: FILE_SHARE_WRITE|FILE_SHARE_READ`).
- It shows a pointer to a known struct as its typed fields (`lpSecurityAttributes: {nLength: 0xc, lpSecurityDescriptor: 0x0, bInheritHandle: TRUE}`). It follows nested pointers one level, so `OBJECT_ATTRIBUTES.ObjectName` shows its string.
- It writes zeros to the `Out` buffers whose size the prototype declares, up to 4 KiB and only to pages that the guest can write. A string buffer gets only a terminator.
- It returns a success value for the return type and removes the arguments from the stack as the calling convention requires.

Each argument in the event of such a call has the parameter name, the type, the raw value and the rendering (see [reporting](reporting.md)).

When the slot count of the signature is equal to the `argc` of a handler, the emulator also uses the signature to name and show the arguments of the handler call. `ctx.args` gives the handler one entry per parameter, by name (`ctx.args["hKey"]`) or by parameter index. A handler that sets `display` replaces the rendering of that parameter.

If no signature matches a handler, for example a C runtime, kernel mode or COM method handler, the emulator records one unnamed argument per slot. These handlers use the slot index (`ctx.args[0]`). Variadic handlers add entries with `ctx.args.append(text)` and remove all entries with `ctx.args.clear()`. `tests/test_handler_arg_access.py` checks that each name a handler uses is a parameter of every signature of that function, and that each index means the same parameter on x86 and x64.

A handler always comes before the signature. A sample that depends on the behavior of an API (output parameters, objects, files, network) needs a handler. The signature only keeps the stack correct and the trace readable.

The signatures of undocumented native APIs (`Nt*`, `Zw*`, `Rtl*`, `Ldr*`, `Csr*`, `Dbg*` ...) come from a second database. `scripts/gen_phnt_signatures.py` generates it from the [phnt](https://github.com/winsiderss/phnt) headers (MIT license, in the `deps/phnt` submodule). This database has the parameter directions and buffer sizes from the SAL annotations, and the information class enums (`SystemInformationClass: SystemProcessInformation`).

### Regenerating the signature databases

The databases are `speakeasy/resources/win32/win32json_signatures.json.gz` (win32metadata) and `speakeasy/resources/win32/phnt_signatures.json.gz` (phnt). Git does not track them. `python -m build` generates them (see `setup.py`). In a source checkout, run

```console
just gen-signatures
# or
git submodule update --init deps/win32json deps/phnt
python scripts/gen_win32_signatures.py --stats
python scripts/gen_phnt_signatures.py --stats
```

If a database is missing, Speakeasy logs a warning and continues. The imports that the database declares are then unknown APIs (see [Unknown APIs](limitations.md#unknown-apis)).

win32metadata does not record calling conventions or variadic parameters. `scripts/win32_overrides.json` gives them (`cdecl_dlls`, `cdecl`, `variadic`), and also the forwarders (`dll_aliases`, `name_prefixes`), such as `psapi!EnumProcesses` -> `kernel32!K32EnumProcesses`. When a header declares no parameter names, win32metadata records `param0`, `param1` and so on, and `param_names` gives the names from the documentation. To correct a declaration, edit that file and generate the database again. Do not edit the generated file.

`tests/test_apihook_signatures.py` compares the `argc` of each `@apihook` with the database. If a hook does not agree with the documented prototype, CI fails.

To add signatures from another source, for example for a third-party DLL, write a subclass of `speakeasy.winenv.api.sigdb.SignatureSource` and add it with `emu.get_signature_db().add_source()`.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Limitations](limitations.md)
- [Configuration walkthrough](configuration.md)
- [Help and troubleshooting](help.md)
