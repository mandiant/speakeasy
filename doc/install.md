# Installation and Docker usage

Speakeasy requires Python 3.10+.

## Install from PyPI

```console
python3 -m pip install speakeasy-emulator
```

Optional GDB support:

```console
python3 -m pip install "speakeasy-emulator[gdb]"
```

Verify installation:

```console
speakeasy -h
```

## Install from source

```console
git clone https://github.com/mandiant/speakeasy.git
cd speakeasy
python3 -m pip install -e ".[dev]"
```

Optional GDB support from source:

```console
python3 -m pip install -e ".[dev,gdb]"
```

## Run in Docker

Build image:

```console
cd <repo_base_dir>
docker build -t speakeasy:local .
```

Run container with a host sample directory mounted at `/sandbox`:

```console
docker run -v <path_containing_samples>:/sandbox -it speakeasy:local
```

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Help and troubleshooting](help.md)
