# Mounting host files with --volume

The `-V` / `--volume` flag maps host files or directories into the emulated Windows filesystem.

Format:

- `host_path:guest_path`
- repeat `-V` to provide multiple mappings

## Mount a single file

```python
from speakeasy.volumes import parse_volume_spec

host, guest = parse_volume_spec("/data/payload.dll:c:\\windows\\system32\\payload.dll")
print(f"Host:  {host}")
print(f"Guest: {guest}")

host, guest = parse_volume_spec("C:\\samples\\mal.exe:D:\\staging\\mal.exe")
print(f"Host:  {host}")
print(f"Guest: {guest}")
```

```output
Host:  /data/payload.dll
Guest: c:\windows\system32\payload.dll
Host:  C:\samples\mal.exe
Guest: D:\staging\mal.exe
```

## Mount a directory recursively

```python
from pathlib import Path, PureWindowsPath

from speakeasy.volumes import expand_volume_to_entries

entries = expand_volume_to_entries(Path("/tmp/vol_demo"), PureWindowsPath("c:\\appdata"))
for entry in entries:
    print(f"{entry['emu_path']}  <-  {entry['path']}")
```

```output
c:\appdata\configs\settings.ini  <-  /tmp/vol_demo/configs/settings.ini
c:\appdata\sample.bin  <-  /tmp/vol_demo/sample.bin
```

## CLI examples

Mount one file:

```console
speakeasy -t malware.exe -V /data/config.dat:c:\appdata\config.dat
```

Mount one directory:

```console
speakeasy -t malware.exe -V /data/samples:c:\windows\temp
```

Mount multiple paths:

```console
speakeasy -t malware.exe \
  -V /data/configs:c:\programdata \
  -V /data/payload.dll:c:\windows\system32\payload.dll
```

## Programmatic usage

```python
import speakeasy

se = speakeasy.Speakeasy(
    volumes=[
        "/data/config.dat:c:\\appdata\\config.dat",
        "/data/samples:c:\\windows\\temp",
    ]
)
module = se.load_module("malware.exe")
se.run_module(module)
```

## Notes

- Volume entries are injected as filesystem `full_path` rules.
- When loading from a host file path, Speakeasy can also auto-mount immediate sibling files from the target directory into the emulated current directory.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Configuration walkthrough](configuration.md)
- [Speakeasy 2 walkthrough outline](speakeasy2-walkthrough.md)
- [Help and troubleshooting](help.md)
