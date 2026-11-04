# Installation

Speakeasy requires Python 3.10+.

## Install from PyPI

```console
python3 -m pip install speakeasy-emulator
```

Check the installation:

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

The last two steps build the API signature databases from the `deps/win32json` and `deps/phnt` submodules (see [Adding API handlers](api-handlers.md)). `python -m build` builds the databases and puts them in the wheel. For an editable install, run the two scripts once, and again after you update the submodules.

[GDB debugging](gdb.md) needs no extra packages.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Help and troubleshooting](help.md)
