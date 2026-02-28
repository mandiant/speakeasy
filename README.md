# Speakeasy

Speakeasy is a Windows malware emulation framework that executes binaries, drivers, and shellcode in a modeled Windows runtime instead of a full VM. It emulates APIs, process/thread behavior, filesystem, registry, and network activity so samples can keep moving through realistic execution paths. You can run it from the `speakeasy` CLI for fast triage or embed it as a Python library and consume structured JSON reports.

Background context: [Mandiant's overview post](https://www.fireeye.com/blog/threat-research/2020/08/emulation-of-malicious-shellcode-with-speakeasy.html).

## Quick start

Install from PyPI:

```console
python3 -m pip install speakeasy-emulator
```

Run a sample and inspect high-level report fields (replace `sample.dll` with your target):

```console
speakeasy -t sample.dll --no-mp -o report.json 2>/dev/null
jq '{sha256, arch, filetype, entry_points: (.entry_points | length)}' report.json
```

```json
{
  "sha256": "30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45",
  "arch": "x86",
  "filetype": "dll",
  "entry_points": 3
}
```

Executable proof for this snippet: [doc/readme-quickstart-showboat.md](doc/readme-quickstart-showboat.md).

## Documentation map

### Start here

- [Installation and Docker usage](doc/install.md)
- [Python library usage](doc/library.md)
- [Help and troubleshooting](doc/help.md)
- [Documentation index](doc/index.md)

### CLI usage

- [CLI reference](doc/cli-reference.md)
- [CLI analysis recipes](doc/cli-analysis-recipes.md)
- [CLI environment overrides](doc/cli-environment-overrides.md)
- [CLI execution controls](doc/cli-execution-controls.md)
- [CLI help snapshot (showboat)](doc/cli-help-showboat.md)

### Reports, configuration, and runtime behavior

- [Configuration walkthrough](doc/configuration.md)
- [Report walkthrough](doc/reporting.md)
- [Memory management](doc/memory.md)
- [Limitations](doc/limitations.md)

### Debugging and extension

- [GDB debugging reference](doc/gdb.md)
- [GDB sessions (showboat)](doc/gdb-examples.md)
- [Mounting host files with `--volume`](doc/volumes.md)
- [Adding API handlers](doc/api-handlers.md)
- [Examples directory](examples/)
- [Speakeasy 2 walkthrough outline](doc/speakeasy2-walkthrough.md)

## Questions and help

Start with [doc/help.md](doc/help.md).

If you still need help, open an issue at [github.com/mandiant/speakeasy/issues](https://github.com/mandiant/speakeasy/issues).
