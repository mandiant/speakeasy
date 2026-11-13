# CLI environment overrides

These flags set the identity of the emulated host, the process environment, DNS answers and module loading. At the start of each emulation, Speakeasy logs the active config to stderr, so you can check the values in the log.

## Host, user and OS identity

The flags are `--system-hostname`, `--system-domain`, `--user-name`, `--user-admin` / `--no-user-admin`, `--user-sid`, `--system-os-ver-major`, `--system-os-ver-minor` and `--system-os-ver-build`. This example gives a workstation in a corporate domain, with a user that is not an administrator:

```bash
speakeasy -t sample.exe \
  --system-hostname WS-3471 \
  --system-domain CORP \
  --user-name jdoe \
  --user-sid S-1-5-21-1111111111-2222222222-3333333333-1107 \
  --no-user-admin \
  --system-os-ver-major 10 \
  --system-os-ver-minor 0 \
  --system-os-ver-build 19045 \
  -v -o report.json 2> run.log
```

To check the values:

```bash
rg "(system\.(hostname|domain|os_ver\.)|user\.)" run.log
```

## Process context and environment variables

The flags are `--process-current-dir`, `--process-command-line` and `--process-env KEY=VALUE`. `--process-env` is repeatable, and each value adds or replaces one variable. The config stores variable names in lower case, because Windows variable names are not case-sensitive. So `--process-env TEMP=...` replaces the default `temp`.

```bash
speakeasy -t sample.exe \
  --process-current-dir 'C:\ProgramData\Microsoft' \
  --process-command-line 'svchost.exe -k netsvcs -p' \
  --process-env TEMP=C:\\Windows\\Temp \
  --process-env APPDATA=C:\\Users\\jdoe\\AppData\\Roaming \
  --process-env COMPUTERNAME=WS-3471 \
  -v -o report.json 2> run.log
```

To check the values:

```bash
rg "process\." run.log
```

## DNS override mappings

`--network-dns-names HOST=IP` sets the address that a DNS lookup gives for a host name. The flag is repeatable. This example gives addresses for two C2 hosts:

```bash
speakeasy -t sample.exe \
  --network-dns-names c2-a.example=203.0.113.10 \
  --network-dns-names c2-b.example=203.0.113.11 \
  -o report.json
```

Each lookup gives a `net_dns` event in the report:

```bash
jq '.entry_points[].events[]? | select(.event == "net_dns") | {query, response}' report.json
```

## Module load policy and module directories

By default, the emulator makes a synthetic module for a DLL that Speakeasy does not know, so `LoadLibrary` succeeds. With `--no-modules-stubs`, `LoadLibrary` fails for such a DLL, as on Windows.

By default, `GetProcAddress` gives an address for a function that Speakeasy does not know, and a call to it returns 1. With `--no-apis-stubs`, `GetProcAddress` fails for such a function, and a call to it ends the run with an `unsupported_api` error. Use this flag to find the APIs that the emulator does not support.

`--modules-directory-x86` and `--modules-directory-x64` give the directories of real x86 and x64 DLLs. The emulator loads a DLL from the directory of the input architecture in place of its synthetic API module.

This example rejects unknown modules and functions, and loads real DLLs from two directories:

```bash
speakeasy -t sample.exe \
  --no-modules-stubs \
  --no-apis-stubs \
  --modules-directory-x86 /opt/dlls/x86 \
  --modules-directory-x64 /opt/dlls/x64 \
  -o report.json
```

Use the `--no-` flags when a sample checks for a fake module or function to detect the emulator.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Configuration walkthrough](configuration.md)
- [Help and troubleshooting](help.md)
