# Installation and Docker usage

Speakeasy requires Python 3.10+.

## Install from PyPI

```console
python3 -m pip install speakeasy-emulator
```

Verify installation:

```console
speakeasy -h
```

## Install from source

```console
git clone --recurse-submodules https://github.com/mandiant/speakeasy.git
cd speakeasy
python3 -m pip install -e ".[dev]"
python3 scripts/gen_win32_signatures.py
python3 scripts/gen_phnt_signatures.py
```

The last two steps build the API signature databases from the `deps/win32json` and `deps/phnt` submodules (see [Adding API handlers](api-handlers.md)). Wheels built with `python -m build` include them automatically; an editable install needs them generated once, and again after updating the submodules.

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
