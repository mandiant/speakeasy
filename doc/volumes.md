# Mounting host files with --volume

The `-V` / `--volume` flag maps host files or directories into the emulated Windows file system. The `volumes` parameter of `Speakeasy` does the same in Python. The functions in `speakeasy.volumes` are internal, and a minor release can change them (see [Public interface](library.md#public-interface)).

A volume has the format `host_path:guest_path`. Repeat `-V` for more than one volume. Both paths can start with a drive letter, for example `C:\samples\mal.exe:D:\staging\mal.exe`. The separator is the first `:` that is not part of a drive letter.

## Mount a directory recursively

A directory mount maps each file below the host directory, at any depth, to the same relative path below the guest path. With `-V /tmp/vol_demo:c:\appdata`, the emulated file system has these files:

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

Mount more than one path:

```console
speakeasy -t malware.exe \
  -V /data/configs:c:\programdata \
  -V /data/payload.dll:c:\windows\system32\payload.dll
```

## Python example

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

## How Speakeasy applies volumes

Speakeasy adds a `full_path` file entry to the config for each mounted file. It puts these entries before the file entries of the config, so a volume file wins over a config entry for the same path.

## Automatic mount of the target directory

When `load_module` loads the input from a host path, Speakeasy also maps each file in the directory of the input into the emulated current directory (`process.current_dir`, default `C:\Windows\system32`). It does not map the subdirectories. Speakeasy puts these entries before the volume entries, so a file next to the input wins over a volume for the same guest path. The log shows an `Auto-mounted N file(s) from target directory ...` line, and with `-v` one line for each file. Speakeasy does not mount a directory for shellcode (`--raw` or `load_shellcode`) or for a PE that `load_module` loads from bytes.

The guest can read every file in the directory of the input, for example all of `~/Downloads`. To turn off the automatic mount, give `--no-auto-mount` on the CLI or `auto_mount=False` to `Speakeasy`. You can also put the sample in a directory of its own.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Configuration walkthrough](configuration.md)
- [What's new in 2.0](speakeasy2-walkthrough.md)
- [Help and troubleshooting](help.md)
