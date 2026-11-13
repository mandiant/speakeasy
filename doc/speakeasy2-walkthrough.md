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

When you load a PE file from a host path, Speakeasy mounts the other files in the same host directory into the emulated current directory (`process.current_dir` in the config). Malware often expects payloads or config files next to the executable. Speakeasy does not mount subdirectories. It also does not mount a directory for shellcode or for a PE that you load from bytes. Speakeasy puts these entries before the volume and config entries, so they take priority when more than one entry matches a path. To turn off the automatic mount, give `--no-auto-mount`, or `auto_mount=False` to `Speakeasy`.

For example, put `file_access_test_x86.exe` and `myfile.txt` in one directory, set `process.current_dir` to `c:\` in the config and run with `--no-mp -v`. At startup, the log shows an `Auto-mounted ... into c:\` line and a debug line for each file, such as `c:\myfile.txt -> /tmp/.../myfile.txt`. The file manager then lists the file in its `full_path` entries. The sample opens and reads `c:\myfile.txt` without a `--volume` flag: the log shows `file_open: c:\myfile.txt`, a successful `NtReadFile` and the `File contained: ...` output.

## AMD64 thread context

`GetThreadContext` and `SetThreadContext` support the x64 `CONTEXT`: the general purpose registers, `Rip`, the segment registers, `EFlags`, `MxCsr` and the debug registers. In 1.x these APIs returned an empty context or were not implemented for x64. x64 samples that do process hollowing read and write the thread context of the target, for example to set the new entry point.

## Import hooks for injected and replaced child processes

When a sample writes a PE into a child process with `WriteProcessMemory`, the loader does not see that PE, so 1.x did not bind its imports. In 2.0, when the sample resumes the modified child process with `ResumeThread`, the emulator reads the import directory of the PE from emulated memory. It binds the IAT slots to the same API addresses that the loader uses. Speakeasy then intercepts and reports the API calls of the hollowed payload.

## Final memory contents in the report

The `memory.final_contents` config field (`--memory-final-contents` on the command line) adds the memory content at the end of each run to the report. It is on by default. At the end of each run, for example a module entry, a TLS callback or an export, Speakeasy records the memory layout. When this field is set, each region of guest memory gets a `data_ref`: the images of the modules that load from a file, such as the input, the allocations and heaps of the guest, the regions with no tag and the static TLS data. The stacks, the stub images of the system modules and the other memory of the emulator get no `data_ref`. The `data_ref` is a key of the top-level `data` mapping, which stores each payload one time, compressed with zlib and encoded with base64.

Speakeasy stores dropped files and other binary data in the same `data` mapping, so the report holds each payload one time, even when many runs or files contain it.

To leave out the memory content, set the field to false:

```json
{
  "memory": {
    "final_contents": false
  }
}
```

```console
speakeasy -t sample.exe --no-memory-final-contents -o report.json
```

## Memory layout for each section

The memory layout of a run has one region for the headers of a module and one region for each section, in place of one region for the whole module. With `memory.final_contents`, Speakeasy captures each region of guest memory, also when no write was counted. This includes memory that an API handler wrote, because the memory hooks do not count these writes.

This excerpt comes from `speakeasy -t dll_test_x86.dll`, with the default config. The module also has `.gfids`, `.rsrc` and `.reloc` regions, which the excerpt leaves out. In `runs[0].memory.layout`, the module has separate `headers`, `.text`, `.rdata` and `.data` regions. Each region has its own permissions and size, and `runs[0].accesses.regions` has its own counters. In this run, code in `.text` executed, the sample read `.rdata` and it read and wrote `.data`. The stack region has counters but no `data_ref`, because Speakeasy does not capture the stacks.

```json
{
  "runs": [
    {
      "memory": {
        "layout": [
          {
            "base": "0x10000000",
            "size": 4096,
            "permissions": "r--",
            "tag": "emu.module",
            "module": "dll_test_x86.dll",
            "section": "headers",
            "freed": false,
            "data_ref": "<sha256>"
          },
          {
            "base": "0x10001000",
            "size": 3584,
            "permissions": "r-x",
            "tag": "emu.module",
            "module": "dll_test_x86.dll",
            "section": ".text",
            "freed": false,
            "data_ref": "<sha256>"
          },
          {
            "base": "0x10002000",
            "size": 2560,
            "permissions": "r--",
            "tag": "emu.module",
            "module": "dll_test_x86.dll",
            "section": ".rdata",
            "freed": false,
            "data_ref": "<sha256>"
          },
          {
            "base": "0x10003000",
            "size": 904,
            "permissions": "rw-",
            "tag": "emu.module",
            "module": "dll_test_x86.dll",
            "section": ".data",
            "freed": false,
            "data_ref": "<sha256>"
          },
          {
            "base": "0x1200000",
            "size": 1048576,
            "permissions": "rw-",
            "tag": "emu.stack",
            "freed": false
          }
        ]
      },
      "accesses": {
        "regions": [
          {"region": "0x1200000", "reads": 184, "writes": 224, "execs": 0},
          {"region": "0x10001000", "reads": 0, "writes": 0, "execs": 677},
          {"region": "0x10002000", "reads": 15, "writes": 0, "execs": 0},
          {"region": "0x10003000", "reads": 30, "writes": 26, "execs": 0}
        ]
      }
    }
  ]
}
```

## Sections and section protections

`LoadedImage` and `RuntimeModule` have the sections of the image. When `load_image` loads a PE, it sets the protection of each section from the section characteristics with `mem_protect`. A section can have any combination of read, write and execute access, or no access. If two sections share a page, the page gets the protections of both.

You do not need a config setting for this. The report always has one region for each section in `memory.layout`, with the `module` and `section` fields. This excerpt of `runs[0].memory` from a run of `dll_test_x86.dll` shows the section permissions. It leaves out `freed`, `data_ref` and the other regions and modules:

```json
{
  "layout": [
    {"base": "0x10000000", "size": 4096, "permissions": "r--", "tag": "emu.module", "module": "dll_test_x86.dll", "section": "headers"},
    {"base": "0x10001000", "size": 3584, "permissions": "r-x", "tag": "emu.module", "module": "dll_test_x86.dll", "section": ".text"},
    {"base": "0x10002000", "size": 2560, "permissions": "r--", "tag": "emu.module", "module": "dll_test_x86.dll", "section": ".rdata"},
    {"base": "0x10003000", "size": 904, "permissions": "rw-", "tag": "emu.module", "module": "dll_test_x86.dll", "section": ".data"}
  ],
  "modules": [
    {"name": "dll_test_x86.dll", "path": "C:\\Windows\\system32\\dll_test_x86.dll", "base": "0x10000000", "size": 28672}
  ]
}
```

## Access counts for each section

With `memory.accesses`, the memory hooks count reads, writes and executes for each section of a module. Outside modules, they count for each memory map. Speakeasy writes the counts to `runs[].accesses.regions`, so the report shows which sections of a module ran code or had writes. `region` is the base of the region in `runs[].memory.layout`.

```json
{
  "memory": {
    "accesses": true,
    "strings": false
  }
}
```

In a run of `dll_test_x86.dll`, each section of the module (`.text` at `0x10001000`, `.rdata` at `0x10002000` and `.data` at `0x10003000`) has different counts:

```json
[
  {"region": "0x10001000", "reads": 0, "writes": 0, "execs": 677},
  {"region": "0x10002000", "reads": 15, "writes": 0, "execs": 0},
  {"region": "0x10003000", "reads": 30, "writes": 26, "execs": 0}
]
```

## Thread and process ID for each run

Each entry in `runs` has a `pid` and a `tid`. The TLS callbacks and the module entry run on the main thread, as on Windows, so the module entry sees the TLS slots and static TLS data that the callbacks set. Speakeasy runs each export on a new thread. So you can tell the export calls apart in the timeline of a sample with many runs.

This excerpt comes from a run of `dll_test_x86.dll` with `runs.exports` set:

```json
[
  {
    "type": "dll_entry",
    "name": "DLL_PROCESS_ATTACH",
    "start_address": "0x10001383",
    "pid": 1240,
    "tid": 1260
  },
  {
    "type": "export",
    "name": "emu_test_one",
    "start_address": "0x10001030",
    "pid": 1240,
    "tid": 1448
  },
  {
    "type": "export",
    "name": "emu_test_two",
    "start_address": "0x10001050",
    "pid": 1240,
    "tid": 1460
  }
]
```

Each run has a different `tid` (`1260`, `1448`, `1460`), and all runs are in process `1240`.

## Debugging with --gdb

`--gdb` starts a GDB remote stub. Speakeasy stops before the first instruction and waits for a client. Then you can pause, step, set breakpoints and watchpoints, and read memory and registers. In Python, the `gdb_port` argument of `Speakeasy` starts the same stub.

In one terminal, run `speakeasy -t sample.dll --gdb --gdb-port 1234` and wait for the listener message. `--gdb` turns on `--no-mp`, because the stub must stay attached to the Unicorn engine in the same process. In a second terminal, start `gdb-multiarch`, run `set architecture i386` (or `i386:x86-64` for x64) and then `target remote localhost:1234`. The usual commands work, such as `info registers`, `x/10i $pc`, `break *0x...`, `stepi` and `continue`.

[GDB debugging](gdb.md) tells you how to connect IDA with its Remote GDB debugger. It also gives the limits, for example one client for each Speakeasy instance and breakpoints that stay set across runs such as DllMain and the exports.

## Time limits across runs

`limits.per_run_time` limits the active time of each run. `limits.total_time` limits the active time of all runs of one call, such as `run_module`. Retry loops and waits in the run queue cannot make emulation run longer than these limits. The CLI also stops the emulation process after `limits.total_time`, if it is not 0. See [CLI execution controls](cli-execution-controls.md).

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI reference](cli-reference.md)
- [Configuration walkthrough](configuration.md)
- [Report walkthrough](reporting.md)
- [Memory management](memory.md)
- [Unified Windows API addresses](unified-api-addresses.md)
- [Help and troubleshooting](help.md)
