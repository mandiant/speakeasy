# CLI environment overrides

These flags set the identity of the emulated host, the process environment, DNS answers, module loading and API hammering mitigation. At the start of each emulation, Speakeasy logs the active config to stderr, so you can check the values in the log.

## Host, user and OS identity

The flags are `--hostname`, `--domain`, `--user-name`, `--user-is-admin` / `--no-user-is-admin`, `--user-sid`, `--os-ver-major`, `--os-ver-minor` and `--os-ver-build`. This example gives a workstation in a corporate domain, with a user that is not an administrator:

```bash
speakeasy -t sample.exe \
  --hostname WS-3471 \
  --domain CORP \
  --user-name jdoe \
  --user-sid S-1-5-21-1111111111-2222222222-3333333333-1107 \
  --no-user-is-admin \
  --os-ver-major 10 \
  --os-ver-minor 0 \
  --os-ver-build 19045 \
  -v -o report.json 2> run.log
```

To check the values:

```bash
rg "(hostname|domain|user\.name|user\.sid|user\.is_admin|os_ver\.)" run.log
```

## Process context and environment variables

The flags are `--current-dir`, `--command-line` and `--env KEY=VALUE`. `--env` is repeatable, and each value adds or replaces one variable. The config stores variable names in lower case, because Windows variable names are not case-sensitive. So `--env TEMP=...` replaces the default `temp`.

```bash
speakeasy -t sample.exe \
  --current-dir 'C:\ProgramData\Microsoft' \
  --command-line 'svchost.exe -k netsvcs -p' \
  --env TEMP=C:\\Windows\\Temp \
  --env APPDATA=C:\\Users\\jdoe\\AppData\\Roaming \
  --env COMPUTERNAME=WS-3471 \
  -v -o report.json 2> run.log
```

To check the values:

```bash
rg "(current_dir|command_line|env =)" run.log
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

By default, `LoadLibrary` fails for a DLL that Speakeasy does not know. With `--modules-always-exist`, the emulator makes a synthetic module for the DLL.

By default, `GetProcAddress` fails for a function that Speakeasy does not know, and a call to such a function ends the run with an `unsupported_api` error. With `--modules-functions-always-exist`, `GetProcAddress` gives an address for the function, and a call to it returns 1.

`--module-directory-x86` and `--module-directory-x64` give the directories of real x86 and x64 DLLs. The emulator loads a DLL from the directory of the input architecture in place of its synthetic API module.

This example allows unknown modules and functions, and loads real DLLs from two directories:

```bash
speakeasy -t sample.exe \
  --modules-always-exist \
  --modules-functions-always-exist \
  --module-directory-x86 /opt/dlls/x86 \
  --module-directory-x64 /opt/dlls/x64 \
  -o report.json
```

Use these flags when a sample stops early because a module or a function is missing.

## API hammering controls

Some samples call an API many times in a loop to make emulation slow. With `--api-hammering-enabled`, the emulator counts the calls to each API from each call site. When the count reaches `--api-hammering-threshold`, the emulator patches an x86 call site so that the call gives 0 and does not run the API. The emulator does not patch x64 code. `--api-hammering-allow-list` gives an API in the form `dll.name` that the emulator does not patch. The flag is repeatable, and its values replace the default allow list.

```bash
speakeasy -t sample.exe \
  --api-hammering-enabled \
  --api-hammering-threshold 5000 \
  --api-hammering-allow-list kernel32.WriteFile \
  --api-hammering-allow-list kernel32.ReadFile \
  -o report.json
```

Increase the threshold if the emulator patches calls that the sample needs.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Configuration walkthrough](configuration.md)
- [Help and troubleshooting](help.md)
