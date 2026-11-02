# Speakeasy

Speakeasy is a Windows malware emulation framework that executes binaries, drivers, and shellcode in a modeled Windows runtime instead of a full VM. It emulates APIs, process/thread behavior, filesystem, registry, and network activity so samples can keep moving through realistic execution paths. You can run it from the `speakeasy` CLI for fast triage or embed it as a Python library and consume structured JSON reports.

Background context: [Mandiant's overview post](https://cloud.google.com/blog/topics/threat-intelligence/emulation-of-malicious-shellcode-with-speakeasy/).

## Quick start

Install from PyPI:

```console
python3 -m pip install speakeasy-emulator
```

Run a sample and inspect high-level report fields (replace `sample.dll` with your target):

```console
speakeasy -t sample.dll --no-mp -o report.json 2>/dev/null
jq '{sha256, arch, file_type, entry_points: (.entry_points | length)}' report.json
```

```json
{
  "sha256": "30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45",
  "arch": "x86",
  "file_type": "dll",
  "entry_points": 3
}
```

Executable proof for this snippet: [doc/readme-quickstart-showboat.md](https://github.com/mandiant/speakeasy/blob/master/doc/readme-quickstart-showboat.md).

## Documentation map

### Start here

- [Installation and Docker usage](https://github.com/mandiant/speakeasy/blob/master/doc/install.md)
- [Python library usage](https://github.com/mandiant/speakeasy/blob/master/doc/library.md)
- [Help and troubleshooting](https://github.com/mandiant/speakeasy/blob/master/doc/help.md)
- [Documentation index](https://github.com/mandiant/speakeasy/blob/master/doc/index.md)

### CLI usage

- [CLI reference](https://github.com/mandiant/speakeasy/blob/master/doc/cli-reference.md)
- [CLI analysis recipes](https://github.com/mandiant/speakeasy/blob/master/doc/cli-analysis-recipes.md)
- [CLI environment overrides](https://github.com/mandiant/speakeasy/blob/master/doc/cli-environment-overrides.md)
- [CLI execution controls](https://github.com/mandiant/speakeasy/blob/master/doc/cli-execution-controls.md)
- [CLI help snapshot (showboat)](https://github.com/mandiant/speakeasy/blob/master/doc/cli-help-showboat.md)

### Reports, configuration, and runtime behavior

- [Configuration walkthrough](https://github.com/mandiant/speakeasy/blob/master/doc/configuration.md)
- [Report walkthrough](https://github.com/mandiant/speakeasy/blob/master/doc/reporting.md)
- [Memory management](https://github.com/mandiant/speakeasy/blob/master/doc/memory.md)
- [Limitations](https://github.com/mandiant/speakeasy/blob/master/doc/limitations.md)

### Debugging and extension

- [GDB debugging reference](https://github.com/mandiant/speakeasy/blob/master/doc/gdb.md)
- [GDB sessions (showboat)](https://github.com/mandiant/speakeasy/blob/master/doc/gdb-examples.md)
- [Mounting host files with `--volume`](https://github.com/mandiant/speakeasy/blob/master/doc/volumes.md)
- [Adding API handlers](https://github.com/mandiant/speakeasy/blob/master/doc/api-handlers.md)
- [Examples directory](https://github.com/mandiant/speakeasy/tree/master/examples)
- [Speakeasy 2 walkthrough outline](https://github.com/mandiant/speakeasy/blob/master/doc/speakeasy2-walkthrough.md)

## Questions and help

Start with [doc/help.md](https://github.com/mandiant/speakeasy/blob/master/doc/help.md).

If you still need help, open an issue at [github.com/mandiant/speakeasy/issues](https://github.com/mandiant/speakeasy/issues).
