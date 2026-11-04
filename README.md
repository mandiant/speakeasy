# Speakeasy

Speakeasy is a Windows malware emulation framework that executes binaries, drivers and shellcode in a modeled Windows runtime instead of a full VM. It emulates the Windows APIs, processes, threads, file system, registry and network that a sample uses, so the sample runs further than in a bare CPU emulator. The `speakeasy` CLI writes the report as JSON for triage, and the Python library returns the same report to your code.

For background, see Mandiant's [introduction to Speakeasy](https://cloud.google.com/blog/topics/threat-intelligence/emulation-of-malicious-shellcode-with-speakeasy/).

## Quick start

Install from PyPI:

```console
python3 -m pip install speakeasy-emulator
```

Emulate a sample and print some fields of the report. Replace `sample.dll` with your file:

```console
speakeasy -t sample.dll --no-mp -o report.json 2>/dev/null
jq '{sha256, arch, file_type, entry_points: (.entry_points | length)}' report.json
```

The values depend on the sample:

```json
{
  "sha256": "…",
  "arch": "x86",
  "file_type": "dll",
  "entry_points": 3
}
```

## Documentation

Start with [installation](https://github.com/mandiant/speakeasy/blob/master/doc/install.md), [Python library usage](https://github.com/mandiant/speakeasy/blob/master/doc/library.md) and the [CLI reference](https://github.com/mandiant/speakeasy/blob/master/doc/cli-reference.md). The [documentation index](https://github.com/mandiant/speakeasy/blob/master/doc/index.md) lists all pages.

For help, see [doc/help.md](https://github.com/mandiant/speakeasy/blob/master/doc/help.md) or open an issue at [github.com/mandiant/speakeasy/issues](https://github.com/mandiant/speakeasy/issues).
