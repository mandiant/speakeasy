# What's new in Speakeasy 2.0

This page shows the main new features and changes in Speakeasy 2. For the changes that can break your code or scripts, see [Migrating to 2.0](migrating-to-2.0.md).

## Python 3.10 and Unicorn 2.1.4

Speakeasy 2 needs Python 3.10 or later and Unicorn 2.1.4 or later.

## Loader and module model

Speakeasy loads PE files, shellcode and the synthetic API modules through one code path. A loader (`PeLoader`, `ShellcodeLoader` or `ApiModuleLoader`) reads its input and returns a `LoadedImage`. A `LoadedImage` holds only data: the architecture, the preferred base and size, the regions to map, the imports and exports, the sections and the TLS data. A loader does not change the state of the emulator.

`load_image` puts the `LoadedImage` into the emulator. It maps and writes the regions, binds the IAT slots to the API addresses, registers the exports of the module, sets the section protections and adds the module to the PEB. It returns a `RuntimeModule`. The rest of Speakeasy, for example the `modules` list and the PEB code, uses the `RuntimeModule` and does not need to know the kind of image. See [Architecture](architecture.md#loader).

## Host mounts with --volume

`-V host_path:guest_path` (or `--volume`) maps a host file or directory into the emulated file system. For a directory, Speakeasy mounts all files below it. Speakeasy puts the volume entries before the `filesystem.files` entries of the config and uses the first entry that matches a path. So you can give a sample its dependencies without a change to the config file. See [Mounting host files with --volume](volumes.md).

This run mounts a host file as `c:\myfile.txt`. With `-v`, the log shows the mapping and the file reads of the sample.

```console
speakeasy -t /tmp/se_vol_demo2/target/file_access_test_x86.exe --no-mp -v -V /tmp/se_vol_demo2/mount/myfile.txt:c:\myfile.txt
```

```text
INFO     Auto-mounted 1 file(s) from target directory /private/tmp/se_vol_demo2/target into C:\Windows\system32
INFO     Emulated filesystem: 6 full_path entries
DEBUG      emu_path=c:\myfile.txt  host_path=/private/tmp/se_vol_demo2/mount/myfile.txt
DEBUG    file_open: c:\myfile.txt
INFO     0x40119b: 'ntdll.NtReadFile("c:\\myfile.txt", 0x0, 0x0, 0x0, 0x0, 0x12ffb98, 0x400, 0x12ffb8c, 0x0)' -> 0x0
INFO     0x40102e: 'api-ms-win-crt-stdio-l1-1-0.__stdio_common_vfprintf(0x0, 0x1, "File contained: 0x7266206f6c6c6568\\n")' -> 0x23
```

The `emu_path=c:\myfile.txt  host_path=...` line shows the volume as a `full_path` entry of the emulated file system. Then the sample opens and reads `c:\myfile.txt`, and prints bytes from the mounted file.

## Automatic mount of the target directory

When you load a PE file from a host path, Speakeasy mounts the other files in the same host directory into the emulated current directory (`current_dir` in the config). Malware often expects payloads or config files next to the executable. Speakeasy does not mount subdirectories. It also does not mount a directory for shellcode or for a PE that you load from bytes. Speakeasy puts these entries before the volume and config entries, so they take priority when more than one entry matches a path.

For example, put `file_access_test_x86.exe` and `myfile.txt` in one directory, set `current_dir` to `c:\` in the config and run with `--no-mp -v`. At startup, the log shows an `Auto-mounted ... into c:\` line and a debug line for each file, such as `c:\myfile.txt -> /tmp/.../myfile.txt`. The file manager then lists the file in its `full_path` entries. The sample opens and reads `c:\myfile.txt` without a `--volume` flag: the log shows `file_open: c:\myfile.txt`, a successful `NtReadFile` and the `File contained: ...` output.

## AMD64 thread context

`GetThreadContext` and `SetThreadContext` support the x64 `CONTEXT`: the general purpose registers, `Rip`, the segment registers, `EFlags`, `MxCsr` and the debug registers. In 1.x these APIs returned an empty context or were not implemented for x64. x64 samples that do process hollowing read and write the thread context of the target, for example to set the new entry point.

## Import hooks for injected and replaced child processes

When a sample writes a PE into a child process with `WriteProcessMemory`, the loader does not see that PE, so 1.x did not bind its imports. In 2.0, when the sample resumes the modified child process with `ResumeThread`, the emulator reads the import directory of the PE from emulated memory. It binds the IAT slots to the same API addresses that the loader uses. Speakeasy then intercepts and reports the API calls of the hollowed payload.

## Memory snapshots in the report

The `snapshot_memory_regions` config field (`--snapshot-memory-regions` on the command line) adds the memory content at the end of each run to the report. At the end of each run, for example a module entry, a TLS callback or an export, Speakeasy records the memory layout. When this field is set, each region gets a `data_ref`, except the stack regions. The `data_ref` is a key of the top-level `data` mapping, which stores each payload one time, compressed with zlib and encoded with base64.

Speakeasy stores dropped files and other binary data in the same `data` mapping, so the report holds each payload one time, even when many runs or files contain it.

```json
{
  "snapshot_memory_regions": true
}
```

```console
speakeasy -t sample.exe --snapshot-memory-regions -o report.json
```

## Memory layout for each section

The memory layout of a run has one region for the headers of a module and one region for each section, in place of one region for the whole module. With `snapshot_memory_regions`, Speakeasy captures each region that is not excluded, also when no write was counted. This includes memory that an API handler wrote, because the memory hooks do not count these writes.

This excerpt comes from a run of `dll_test_x86.dll` with `analysis.memory_tracing` and `snapshot_memory_regions` set. In `entry_points[0].memory.layout`, the module has separate `headers`, `.text`, `.rdata` and `.data` regions. Each region has its own protection, size and counters. In this run, code in `.text` executed, the sample read `.rdata` and it read and wrote `.data`. The stack region has counters but no `data_ref`, because Speakeasy does not capture the stack.

```json
{
  "entry_points": [
    {
      "memory": {
        "layout": [
          {
            "tag": "emu.module.<hash>.exe.headers.0x10000000",
            "base": "0x10000000",
            "size": 4096,
            "perms": "r--",
            "accesses": null,
            "data_ref": "<sha256>"
          },
          {
            "tag": "emu.module.<hash>.exe..text.0x10001000",
            "base": "0x10001000",
            "size": 3300,
            "perms": "r-x",
            "accesses": {"reads": 0, "writes": 0, "execs": 677},
            "data_ref": "<sha256>"
          },
          {
            "tag": "emu.module.<hash>.exe..rdata.0x10002000",
            "base": "0x10002000",
            "size": 2166,
            "perms": "r--",
            "accesses": {"reads": 15, "writes": 0, "execs": 0},
            "data_ref": "<sha256>"
          },
          {
            "tag": "emu.module.<hash>.exe..data.0x10003000",
            "base": "0x10003000",
            "size": 904,
            "perms": "rw-",
            "accesses": {"reads": 30, "writes": 26, "execs": 0},
            "data_ref": "<sha256>"
          },
          {
            "tag": "emu.stack.0x1200000",
            "base": "0x1200000",
            "size": 1048576,
            "perms": "rwx",
            "accesses": {"reads": 170, "writes": 210, "execs": 0}
          }
        ]
      }
    }
  ]
}
```

## Sections and section protections

`LoadedImage` and `RuntimeModule` have the sections of the image. When `load_image` loads a PE, it sets the protection of each section from the section characteristics with `mem_protect`. A section can have any combination of read, write and execute access, or no access. If two sections share a page, the page gets the protections of both.

You do not need a config setting for this. The report always has the sections in `memory.modules[*].segments` and the regions in `memory.layout`. This excerpt from `tests/bins/dll_test_x86.dll.xz` shows the section protections in both places:

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
    "size": 28672,
    "segments": [
      {"name": ".text", "base": "0x10001000", "size": 3300, "perms": "r-x"},
      {"name": ".rdata", "base": "0x10002000", "size": 2166, "perms": "r--"},
      {"name": ".data", "base": "0x10003000", "size": 904, "perms": "rw-"}
    ]
  },
  "layout": [
    {"tag": "emu.module.30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe.headers.0x10000000", "base": "0x10000000", "size": 4096, "perms": "r--"},
    {"tag": "emu.module.30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe..text.0x10001000", "base": "0x10001000", "size": 3300, "perms": "r-x"},
    {"tag": "emu.module.30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe..rdata.0x10002000", "base": "0x10002000", "size": 2166, "perms": "r--"},
    {"tag": "emu.module.30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45.exe..data.0x10003000", "base": "0x10003000", "size": 904, "perms": "rw-"}
  ]
}
```

## Access counts for each section

With `analysis.memory_tracing`, the memory hooks count reads, writes and executes for each section of a module. Outside modules, they count for each memory map. Speakeasy writes the counts to `entry_points[*].memory.layout[*].accesses`, so the report shows which sections of a module ran code or had writes.

```json
{
  "analysis": {
    "memory_tracing": true,
    "strings": false
  }
}
```

In a run of `tests/bins/dll_test_x86.dll.xz`, each section of the module has different counts:

```json
[
  {
    "tag": "emu.module.<sample>.exe..text.0x10001000",
    "perms": "r-x",
    "accesses": {"reads": 0, "writes": 0, "execs": 677}
  },
  {
    "tag": "emu.module.<sample>.exe..rdata.0x10002000",
    "perms": "r--",
    "accesses": {"reads": 15, "writes": 0, "execs": 0}
  },
  {
    "tag": "emu.module.<sample>.exe..data.0x10003000",
    "perms": "rw-",
    "accesses": {"reads": 30, "writes": 26, "execs": 0}
  }
]
```

## Thread and process ID for each run

Each entry in `entry_points` has a `pid` and a `tid`. The TLS callbacks and the module entry run on the main thread, as on Windows, so the module entry sees the TLS slots and static TLS data that the callbacks set. Speakeasy runs each export on a new thread. So you can tell the export calls apart in the timeline of a sample with many runs.

This excerpt comes from a run of `dll_test_x86.dll` with `all_entrypoints=True`:

```json
[
  {
    "type": "dll_entry",
    "name": "DLL_PROCESS_ATTACH",
    "start_address": "0x10001383",
    "pid": 1056,
    "tid": 1076
  },
  {
    "type": "export",
    "name": "emu_test_one",
    "start_address": "0x10001030",
    "pid": 1056,
    "tid": 1200
  },
  {
    "type": "export",
    "name": "emu_test_two",
    "start_address": "0x10001050",
    "pid": 1056,
    "tid": 1212
  }
]
```

Each run has a different `tid` (`1076`, `1200`, `1212`), and all runs are in process `1056`.

## Debugging with --gdb

`--gdb` starts a GDB remote stub. Speakeasy stops before the first instruction and waits for a client. Then you can pause, step, set breakpoints and watchpoints, and read memory and registers. In Python, the `gdb_port` argument of `Speakeasy` starts the same stub.

In one terminal, run `speakeasy -t sample.dll --gdb --gdb-port 1234` and wait for the listener message. `--gdb` turns on `--no-mp`, because the stub must stay attached to the Unicorn engine in the same process. In a second terminal, start `gdb-multiarch`, run `set architecture i386` (or `i386:x86-64` for x64) and then `target remote localhost:1234`. The usual commands work, such as `info registers`, `x/10i $pc`, `break *0x...`, `stepi` and `continue`.

[GDB debugging](gdb.md) tells you how to connect IDA with its Remote GDB debugger. It also gives the limits, for example one client for each Speakeasy instance and breakpoints that stay set across runs such as DllMain and the exports.

## Time limits across runs

`max_run_time` limits the active time of each run. `max_total_time` limits the active time of all runs of one call, such as `run_module`. Retry loops and waits in the run queue cannot make emulation run longer than these limits. The CLI also stops the emulation process after `max_total_time`, if it is not 0. See [CLI execution controls](cli-execution-controls.md).

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [Memory management](memory.md)
- [Unified Windows API addresses](unified-api-addresses.md)
- [Help and troubleshooting](help.md)
