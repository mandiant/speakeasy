# Speakeasy 2 walkthrough outline

Here are the major new features/changes in Speakeasy v2.

## Runtime baseline updates: Python 3.10 and Unicorn 2.1.4+

Speakeasy now targets Python 3.10+ and Unicorn 2.1.4+. Unicorn 2.1.3 and below have significant issues and should not be used.

## Unified loader and module model

The module system was reorganized around explicit Loader types, a LoadedImage data model, and a consistent RuntimeModule representation. This replaces multiple parallel module registries and consolidates image loading, import hookup, and bookkeeping into one path. The change makes behavior more predictable across PE files, shellcode, decoys, and API modules.

Under the hood, Loader is just the source adapter layer. Each loader type (PE, shellcode, API-generated module, decoy, etc.) takes its own input format and normalizes it into one common LoadedImage object. LoadedImage is intentionally “just data”: arch, base/size, regions to map, imports/exports, section metadata, TLS info, and visibility flags, with no emulator side effects yet.

The actual side effects happen in `load_image()`, which materializes that data into emulator state: map/write memory, patch IAT entries with sentinels, register imports in the global `import_table`, apply section protections, and install symbol/access hooks. The returned RuntimeModule is the stable runtime handle used everywhere else (`self.modules`, module lookups, PEB population), so the rest of Speakeasy can treat PE files, shellcode, and synthetic modules the same way.

## Docker-style host mounts with --volume

A new -V/--volume CLI option maps host files or directories into the emulated Windows filesystem using host_path:guest_path syntax. Volume entries are expanded and injected with precedence so mounted data is resolved before default file mappings. This gives analysts a direct, repeatable way to stage sample dependencies without rewriting config files.

Here is a showboat-verified CLI run using `-V` to mount a host file as `c:\myfile.txt` inside the emulator. I ran with `-v` so you can see exactly where the mapping lands and what the sample reads.

```console
speakeasy -t /tmp/se_vol_demo2/target/file_access_test_x86.exe --no-mp -v -V /tmp/se_vol_demo2/mount/myfile.txt:c:\myfile.txt
```

```text
INFO     Auto-mounted 1 file(s) from target directory /private/tmp/se_vol_demo2/target into C:\Windows\system32
INFO     Emulated filesystem: 6 full_path entries
DEBUG      emu_path=c:\myfile.txt  host_path=/private/tmp/se_vol_demo2/mount/myfile.txt
DEBUG    file_file_open: c:\myfile.txt
INFO     0x40119b: 'ntdll.NtReadFile("c:\\myfile.txt", 0x0, 0x0, 0x0, 0x0, 0x12ffb98, 0x400, 0x12ffb8c, 0x0)' -> 0x0
INFO     0x40102e: 'api-ms-win-crt-stdio-l1-1-0.__stdio_common_vfprintf(0x0, 0x1, "File contained: 0x7266206f6c6c6568\\n")' -> 0x23
```

The key line is `emu_path=c:\myfile.txt  host_path=...`: that is the `--volume` mapping being injected as a `full_path` rule. Then you can see the sample open and read `c:\myfile.txt`, and print back bytes from the mounted file, which confirms the mount is active during emulation.

## Automatic target-directory mounting

When a target sample is loaded from disk, Speakeasy now auto-mounts immediate sibling files from that directory into the emulated current directory. This covers common malware assumptions that companion payloads or config files sit next to the executable. The result is fewer setup failures caused by missing local artifacts.

I ran a concrete CLI check with `file_access_test_x86.exe` and a sibling `myfile.txt`, using `--no-mp -v` and a config with `current_dir` set to `c:\`. Startup logs showed `Auto-mounted 3 file(s) ... into c:\` and debug mappings for each direct child file, including `c:\myfile.txt -> /tmp/.../myfile.txt`. Right after that, file manager logged the mounted entry in the `full_path` list, which confirms the auto-mount is applied before execution starts.

The sample then opened and read `c:\myfile.txt` without any `--volume` flag (`file_file_open: c:\myfile.txt`, followed by successful `NtReadFile` and `File contained: ...` output). So the behavior is: this only triggers when you load by host path (not raw bytes), it mounts only immediate child files (not recursive), it maps into `current_dir`, and these entries are prepended so they win first-match file resolution.

## AMD64 thread context get/set

AMD64 thread context retrieval and restoration now covers full register state instead of returning empty or unimplemented results. This includes general-purpose registers, RIP, segment registers, and EFLAGS. The change improves correctness for x64 samples that manipulate thread context during process replacement.

When Speakeasy was first written, many malware samples were still 32-bits. These days 64-bit samples are much more prevalent. So we have better support for that now.

## Hook imports for injected/replaced child processes

Injected PEs written with WriteProcessMemory can bypass normal loader IAT patching, so imports were not always hooked. Speakeasy now parses the in-memory PE import directory and patches IAT slots with sentinel handlers before resumed execution. This restores API interception and trace visibility for hollowed payloads.

## Config gate for memory byte capture

A new capture_memory_dumps configuration option controls whether raw memory content is included directly in reports. This capture happens at the end of each entry-point run (module entry, TLS callback, export run, etc.) when Speakeasy snapshots memory layout for that run. If enabled, each non-excluded region gets a `data` field with `base64(zlib(raw_bytes))`; module-backed regions are emitted as headers + per-section slices, while non-module maps are emitted as one region each.

This is separate from the archive-style memory dumper behind `-d/--dump`. The report path embeds compressed bytes into `entry_points[*].memory.layout[*].data`, while the archive path writes standalone `.mem` files into a zip package with a manifest. They are independent switches, so you can use report-only, archive-only, or both depending on whether you want one self-contained JSON report or larger raw artifacts for external tooling.

```json
{
  "capture_memory_dumps": true
}
```

```console
speakeasy -t sample.exe --capture-memory-dumps -o report.json
speakeasy -t sample.exe -d memdump.zip --no-capture-memory-dumps -o report.json
speakeasy -t sample.exe --capture-memory-dumps -d memdump.zip -o report.json
```

## Per-section memory layout and broader dump coverage

Memory layout reporting now emits module headers and sections as distinct regions instead of a single module-wide block. Dump capture also includes non-excluded regions even when write counters are absent, which covers API-populated memory not tracked as direct writes. This makes reported layout and content closer to actual runtime state.

Here is what that looks like in a real report from `dll_test_x86.dll` with `analysis.memory_tracing=true` and `capture_memory_dumps=true`. In `entry_points[0].memory.layout`, the sample module is split into `headers`, `.text`, `.rdata`, and `.data` records, each with its own protection, size, and counters instead of one merged module region. In this run, `.text` recorded only execution (`execs: 677`), `.rdata` recorded reads (`reads: 15`), and `.data` recorded both reads and writes (`reads: 30`, `writes: 26`).

The same snapshot also shows the broader dump rule: non-excluded regions get `data` even if `writes == 0`, while excluded regions like stack still keep counters but skip raw bytes. So you end up with section-level activity you can reason about directly in JSON, plus embedded bytes for module sections when capture is enabled.

```json
{
  "entry_points": [
    {
      "memory": {
        "layout": [
          {
            "tag": "emu.module.<hash>.exe.headers.0x10000000",
            "address": "0x10000000",
            "size": "0x1000",
            "prot": "r--",
            "accesses": null,
            "data": "..."
          },
          {
            "tag": "emu.module.<hash>.exe..text.0x10001000",
            "address": "0x10001000",
            "size": "0xce4",
            "prot": "r-x",
            "accesses": {"reads": 0, "writes": 0, "execs": 677},
            "data": "..."
          },
          {
            "tag": "emu.module.<hash>.exe..rdata.0x10002000",
            "address": "0x10002000",
            "size": "0x876",
            "prot": "r--",
            "accesses": {"reads": 15, "writes": 0, "execs": 0},
            "data": "..."
          },
          {
            "tag": "emu.module.<hash>.exe..data.0x10003000",
            "address": "0x10003000",
            "size": "0x388",
            "prot": "rw-",
            "accesses": {"reads": 30, "writes": 26, "execs": 0},
            "data": "..."
          },
          {
            "tag": "emu.stack.0x1200000",
            "address": "0x1200000",
            "size": "0x100000",
            "prot": "rwx",
            "accesses": {"reads": 170, "writes": 210, "execs": 0},
            "data": null
          }
        ]
      }
    }
  ]
}
```

## First-class sections and per-section memory protections

Section metadata is now first-class on loaded images/modules across loader types, and PE section permissions are applied with per-section mem_protect calls. Permission mapping was expanded so NONE, EXEC, RX, and related combinations are handled explicitly. This improves protection fidelity and supports section-aware analysis logic.

There is no dedicated config toggle for this one: section metadata and per-section protections are applied automatically for PE images during load. To make it visible in the report, run with normal settings plus `analysis.memory_tracing=true`.

Here is an actual report excerpt from `tests/bins/dll_test_x86.dll.xz` showing section-level protections in both `memory.modules[*].segments` and `memory.layout`:

```json
{
  "config": {
    "analysis": {
      "memory_tracing": true,
      "strings": false
    }
  },
  "module": {
    "name": "30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe",
    "base": "0x10000000",
    "size": "0x7000",
    "segments": [
      {"name": ".text", "address": "0x10001000", "size": "0xce4", "prot": "r-x"},
      {"name": ".rdata", "address": "0x10002000", "size": "0x876", "prot": "r--"},
      {"name": ".data", "address": "0x10003000", "size": "0x388", "prot": "rw-"}
    ]
  },
  "layout": [
    {"tag": "emu.module.30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe.headers.0x10000000", "address": "0x10000000", "size": "0x1000", "prot": "r--"},
    {"tag": "emu.module.30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe..text.0x10001000", "address": "0x10001000", "size": "0xce4", "prot": "r-x"},
    {"tag": "emu.module.30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe..rdata.0x10002000", "address": "0x10002000", "size": "0x876", "prot": "r--"},
    {"tag": "emu.module.30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe..data.0x10003000", "address": "0x10003000", "size": "0x388", "prot": "rw-"}
  ]
}
```

## Per-section read/write/execute access tracking

Memory hooks now track access counters at section granularity for module-backed memory, with map-level fallback for non-module regions. Report generation reads these counters from section-specific state instead of module-wide aggregates. Analysts can now see which sections were executed or modified, not just which module was touched.

There is no separate toggle for this feature; it is part of `analysis.memory_tracing`. If you run with memory tracing enabled, Speakeasy installs code/read/write hooks and records access counts per section key `(module_base, section_rva)`, then writes them into each section entry in `entry_points[*].memory.layout[*].accesses`.

```json
{
  "analysis": {
    "memory_tracing": true,
    "strings": false
  }
}
```

A concrete run against `tests/bins/dll_test_x86.dll.xz` produced section-level counters like these: `.text` had execution only (`execs: 677`), `.rdata` had reads only (`reads: 15`), and `.data` had reads and writes (`reads: 30`, `writes: 26`). That is the key behavior change: different sections of one module now show different activity profiles instead of one module-wide aggregate.

```json
[
  {
    "tag": "emu.module.<sample>.exe..text.0x10001000",
    "prot": "r-x",
    "accesses": {"reads": 0, "writes": 0, "execs": 677}
  },
  {
    "tag": "emu.module.<sample>.exe..rdata.0x10002000",
    "prot": "r--",
    "accesses": {"reads": 15, "writes": 0, "execs": 0}
  },
  {
    "tag": "emu.module.<sample>.exe..data.0x10003000",
    "prot": "rw-",
    "accesses": {"reads": 30, "writes": 26, "execs": 0}
  }
]
```

## Unique TID/PID attribution per entry-point run

Each entry-point evaluation now gets distinct thread attribution, and entry-point records include pid/tid metadata. TLS callbacks, module entry, and export runs can be separated by execution context instead of being merged under one thread identity. This improves timeline interpretation for multi-run samples.

Here is a real `entry_points` excerpt from a run of `dll_test_x86.dll` with `all_entrypoints=True`. The important part is that each run has its own `tid`, so module entry and each export call can be separated cleanly in timelines and downstream tooling.

```json
[
  {
    "ep_type": "dll_entry.DLL_PROCESS_ATTACH",
    "start_addr": "0x10001383",
    "pid": 1056,
    "tid": 1076
  },
  {
    "ep_type": "export.emu_test_one",
    "start_addr": "0x10001030",
    "pid": 1056,
    "tid": 1200
  },
  {
    "ep_type": "export.emu_test_two",
    "start_addr": "0x10001050",
    "pid": 1056,
    "tid": 1212
  }
]
```

How to read this: `tid` changes on each queued run (`1076 -> 1200 -> 1212`), while the export runs stay in the same process (`pid=1056`).

## Interactive debugging with --gdb

Speakeasy now provides a built-in GDB remote stub via udbserver and can pause before first instruction until a client connects. The flow is available from both CLI and library usage, with explicit port selection. This enables interactive stepping, breakpoints, and memory/register inspection during emulation.

Quick way to use it: in terminal 1 run `speakeasy -t sample.dll --gdb --gdb-port 1234` and wait for the listener message; Speakeasy will force `--no-mp` automatically so the stub stays attached to the same Unicorn instance. In terminal 2 run `gdb-multiarch`, then `set architecture i386` (or `i386:x86-64` for 64-bit), and `target remote localhost:1234`; from there standard commands like `info registers`, `x/10i $pc`, `break *0x...`, `stepi`, and `continue` work as expected.

For the full reference and caveats, use [doc/gdb.md](gdb.md), and for copy/paste real sessions use [doc/gdb-examples.md](gdb-examples.md) plus the README section [Debugging with GDB](../README.md#debugging-with-gdb). Those docs cover the practical details this summary skips, including IDA Remote GDB setup, one-session-per-process limits, and how breakpoints behave across multi-run flows like DllMain plus exports.

## Timeout enforcement across multi-run and parent supervision

Timeout handling was tightened so configured limits apply consistently across chained entry-point runs and parent-process control logic. This closes cases where retry loops or queue waits could effectively outlive the requested timeout. Users should now see more predictable stop behavior on long or stalled analyses.
