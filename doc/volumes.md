# Mounting host files with --volume

The `-V` / `--volume` flag maps host files or directories into the emulated Windows filesystem. The interface is this flag and the `volumes` parameter of `Speakeasy`. The functions in `speakeasy.volumes` are internal, and a minor release can change them (see [Public interface](library.md#public-interface)).

Format:

- `host_path:guest_path`
- repeat `-V` to provide multiple mappings

Both paths can start with a drive letter, for example `C:\samples\mal.exe:D:\staging\mal.exe`. The separator is the first `:` that is not part of a drive letter.

## Mount a directory recursively

A directory mount maps each file below the host directory, at any depth, to the same relative path below the guest path. With `-V /tmp/vol_demo:c:\appdata`, the emulated filesystem has these files:

```text
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
