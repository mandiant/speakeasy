# CLI environment overrides

This page covers flags that shape the emulated host environment and behavior determinism.

## Host, user, and OS identity

Primary flags:
- `--hostname`
- `--domain`
- `--user-name`
- `--user-is-admin` / `--no-user-is-admin`
- `--user-sid`
- `--os-ver-major`, `--os-ver-minor`, `--os-ver-release`, `--os-ver-build`

Example: enterprise-like identity profile

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

Quick verification:

```bash
rg "(hostname|domain|user\.name|user\.sid|user\.is_admin|os_ver\.)" run.log
```

## Process context and environment variables

Primary flags:
- `--current-dir`
- `--command-line`
- `--env KEY=VALUE` (repeatable)

Example:

```bash
speakeasy -t sample.exe \
  --current-dir 'C:\\ProgramData\\Microsoft' \
  --command-line 'svchost.exe -k netsvcs -p' \
  --env TEMP=C:\\Windows\\Temp \
  --env APPDATA=C:\\Users\\jdoe\\AppData\\Roaming \
  --env COMPUTERNAME=WS-3471 \
  -v -o report.json 2> run.log
```

Quick verification:

```bash
rg "(current_dir|command_line|env =)" run.log
```

## DNS override mappings

Primary flag:
- `--network-dns-names HOST=IP` (repeatable)

Example: force known C2 host resolutions

```bash
speakeasy -t sample.exe \
  --network-dns-names c2-a.example=203.0.113.10 \
  --network-dns-names c2-b.example=203.0.113.11 \
  -o report.json
```

Quick verification:

```bash
jq '.entry_points[].events[]? | select(.event == "net_dns") | {query, response}' report.json
```

## Module load policy and decoy module directories

Primary flags:
- `--modules-modules-always-exist` / `--no-modules-modules-always-exist`
- `--modules-functions-always-exist` / `--no-modules-functions-always-exist`
- `--modules-module-directory-x86`
- `--modules-module-directory-x64`

Example: relaxed unresolved-import policy with custom decoys

```bash
speakeasy -t sample.exe \
  --modules-modules-always-exist \
  --modules-functions-always-exist \
  --modules-module-directory-x86 /opt/decoys/x86 \
  --modules-module-directory-x64 /opt/decoys/x64 \
  -o report.json
```

Use this when triaging samples that otherwise stop early on missing modules/APIs.

## API hammering controls

Primary flags:
- `--api-hammering-enabled` / `--no-api-hammering-enabled`
- `--api-hammering-threshold`
- `--api-hammering-allow-list VALUE` (repeatable)

Example:

```bash
speakeasy -t sample.exe \
  --api-hammering-enabled \
  --api-hammering-threshold 5000 \
  --api-hammering-allow-list kernel32.WriteFile \
  --api-hammering-allow-list kernel32.ReadFile \
  -o report.json
```

This is useful when balancing anti-loop containment with legitimate hot API usage.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Configuration walkthrough](configuration.md)
- [Module resolution and decoy exports](module-resolution.md)
- [Help and troubleshooting](help.md)
