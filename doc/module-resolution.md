# Module resolution and decoy exports

Some samples (especially shellcode) parse PE export tables directly to resolve API pointers. If expected modules or exports are missing, these samples may stop early.

Speakeasy supports decoy module directories for this case:

- `modules.module_directory_x86`
- `modules.module_directory_x64`

CLI overrides:

- `--modules-module-directory-x86`
- `--modules-module-directory-x64`

Related policy toggles:

- `--modules-modules-always-exist` / `--no-modules-modules-always-exist`
- `--modules-functions-always-exist` / `--no-modules-functions-always-exist`

Use these controls when you need stricter realism or more permissive triage behavior for unresolved module/function lookups.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [Limitations](limitations.md)
- [Help and troubleshooting](help.md)
