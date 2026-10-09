# Export manifests

Each `<arch>/<module>.json` file records the export directory of one real Windows binary. When a module has a manifest, speakeasy builds the export table of its synthetic module from the manifest names and ordinals.

The binaries come from the emulation root of [sogen](https://github.com/momo5502/sogen) (`root.zip`), which sogen collects from a GitHub Actions Windows Server 2025 runner, build 10.0.26100. The `x64` files come from `Windows\System32` and the `x86` files from `Windows\SysWOW64`. The root holds only a subset of the system modules: it has no `ntoskrnl.exe`, no `drivers\*.sys` and no `mfc42.dll`.

The files were extracted once with `pefile`, from every PE file in those directories that has an export directory. The extraction followed these rules:

1. `module` is the lower-case file stem. It is also the file name.
2. An export address table entry with RVA 0 is skipped.
3. A forwarded export keeps its forwarder string, for example `NTDLL.RtlAcquireSRWLockExclusive`.
4. `kind` is `data` when the RVA is in a section without `IMAGE_SCN_MEM_EXECUTE`. Otherwise it is `function`.
5. Exports are sorted by ordinal, then by name. Each export is on its own line, so diffs stay small.

There are no files for the CRT modules other than `msvcrt` (`ucrtbase`, `vcruntime*`, `msvcp*`, `msvcr*`) or for `wsock32`. Speakeasy maps those names to `msvcrt` and `ws2_32` before it looks for a manifest.

There is no generator script. To add or correct a module, edit its file or write a new one with the same format:

```json
{
  "module": "ws2_32",
  "file": "ws2_32.dll",
  "arch": "x86",
  "file_version": "10.0.26100.32684",
  "timestamp": 314141788,
  "size_of_image": 397312,
  "sha256": "4241d922af646020cac603d7ce1e1e8046f0bfbe751d016aa40ba8127b68f171",
  "exports": [
    {"ordinal": 1, "name": "accept"},
    {"ordinal": 2, "name": "bind"}
  ]
}
```

An export can also have `"forwarder": "<DLL>.<name>"` or `"forwarder": "<DLL>.#<ordinal>"`, and `"kind": "data"`. An export with only an ordinal has no `name`. `timestamp`, `size_of_image` and `sha256` identify the source binary. With `timestamp` and `size_of_image`, the binary can be downloaded again from the Microsoft symbol server. `tests/test_export_manifests.py` checks that every file follows this format, and that every handler ordinal matches the manifest of its module.
