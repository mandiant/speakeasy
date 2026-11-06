# Ordinal names

Each `<arch>/<module>.json` file gives the exported name of each ordinal of a module that has no [export manifest](../exports/README.md). Speakeasy builds the export table of the synthetic module from these names and ordinals, as it does from a manifest. An import by ordinal then binds to a named export, so the report and the `unsupported_api` error show the name, for example `mfc42.?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ`, and not `mfc42.ordinal_1168`.

A file does not identify a source binary, and it does not tell code exports from data exports. Each export is a function, unless a data handler of the module has its name.

The x86 files `mfc42.json` and `mfc42u.json` come from `Ghidra/Features/Base/data/symbols/win32/mfc42.exports` and `mfc42u.exports` of [Ghidra](https://github.com/NationalSecurityAgency/ghidra), commit `e45e5a62fd66c2e48514931f6e356aff33a79fcb`. Ghidra uses the Apache License 2.0, and its `certification.manifest` gives that license for these files. The Ghidra NOTICE file says: "This product includes software developed at National Security Agency (https://www.nsa.gov)". The `ORDINAL` and `NAME` attributes of each `EXPORT` element give `ordinal` and `name`. The names are sorted by ordinal.

`mfc42.dll` (ANSI) and `mfc42u.dll` (Unicode) use different ordinals: ordinal 1168 is `AfxGetModuleState` in `mfc42.dll` and `AfxGetParentOwner` in `mfc42u.dll`. The x64 builds of these DLLs also use different ordinals and decorated names, and there are no x64 files.

The format is:

```json
{
  "module": "mfc42",
  "arch": "x86",
  "names": [
    {"ordinal": 1168, "name": "?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ"}
  ]
}
```

`module` is the lower-case file stem and the file name. `arch` is the directory name. Each name is on its own line. The pydantic model `OrdinalNames` in `speakeasy/windows/export_manifest.py` defines the format. `tests/test_export_manifests.py` validates every file, and checks that every handler ordinal matches the file of its module.
