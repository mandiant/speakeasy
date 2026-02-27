# Speakeasy

Speakeasy is a portable, modular, binary emulator designed to emulate Windows kernel and user mode malware.

Check out the overview in the first [Speakeasy blog post](https://www.fireeye.com/blog/threat-research/2020/08/emulation-of-malicious-shellcode-with-speakeasy.html).

Instead of attempting to perform dynamic analysis using an entire virtualized operating system, Speakeasy will emulate specific components of Windows. Specifically, by emulating operating system APIs, objects, running processes/threads, filesystems, and networks it should be possible to present an environment where samples can fully "execute". Samples can be easily emulated in a container or in cloud services which allow for great scalability of many samples to be simultaneously analyzed. Currently, Speakeasy supports both user mode and kernel mode Windows applications.

Before emulating, entry points are identified within the binary. For example, exported functions are all identified and emulated sequentially. Additionally, dynamic entry points (e.g. new threads, registered callbacks, IRP handlers) that are discovered at runtime are also emulated. The goal here is to have as much code coverage as possible during emulation. Events are logged on a per-entry-point basis so that functionality can be attributed to specific functions or exports.

Speakeasy is currently written entirely in Python 3 and relies on the [Unicorn emulation engine](https://github.com/unicorn-engine/unicorn) in order to emulate CPU instructions. The CPU emulation engine can be swapped out and there are plans to support other engines in the future.

APIs are emulated in Python code in order to handle their expected inputs and outputs in order to keep malware on their "happy path". These APIs and their structure should be consistent with the API documentation provided by Microsoft.

---

## Installation

Speakeasy can be executed in a docker container, as a stand-alone script, or in cloud services. The easiest method of installation is by first installing the required package dependencies, and then running the included setup.py script (replace "python3" with your current Python3 interpreter):

```console
cd <repo_base_dir>
python3 -m pip install -r requirements.txt
python3 setup.py install
```

A docker file is also included in order to build a docker image, however, Speakeasy's dependencies can be installed on the local system and run from Python directly.

---

### Running within a docker container

The included Dockerfile can be used to generate a docker image.

---

#### Building the docker image

1. Build the Docker image; the following commands  will create a container with the tag named "my_tag":

```console
cd <repo_base_dir>
docker build -t "my_tag" .
```

2. Run the Docker image and create a local volume in `/sandbox`:

```console
docker run -v <path_containing_malware>:/sandbox -it "my_tag"
```

## Usage

---

### As a library

Speakeasy can be imported and used as a general purpose Windows emulation library. The main public interface named `Speakeasy` should be used when interacting with the framework. The lower level emulator objects can also be used, however their interfaces may change in the future and may lack documentation.

Below is a quick example of how to emulate a Windows DLL:

```python
    import speakeasy

    # Get a speakeasy object
    se = speakeasy.Speakeasy()

    # Load a DLL into the emulation space
    module = se.load_module("myfile.dll")

    # Emulate the DLL's entry point (i.e. DllMain)
    se.run_module(module)

    # Set up some args for the export
    arg0 = 0x0
    arg1 = 0x1
    # Walk the DLLs exports
    for exp in module.get_exports():
        if exp.name == 'myexport':
            # Call an export named 'myexport' and emulate it
            se.call(exp.address, [arg0, arg1])

    # Get the emulation report
    report = se.get_report()

    # Do something with the report; parse it or save it off for post-processing
```

For more examples, see the [examples](examples/) directory.

---

### As a standalone command line tool

For users who don't wish to programatically interact with the speakeasy framework as a library, a standalone script is provided to automatically emulate Windows binaries. Speakeasy can be invoked by running the command `speakeasy`. This command will parse a specified PE and invoke the appropriate emulator (kernel mode or user mode). The script's parameters are shown below.

```
usage: speakeasy [-h] [-t TARGET] [-o OUTPUT] [--argv [ARGV ...]] [-c CONFIG]
                 [--dump-default-config] [--raw] [--raw-offset RAW_OFFSET]
                 [--arch ARCH] [--memory-dump-path MEMORY_DUMP_PATH]
                 [--dropped-files-path DROPPED_FILES_PATH] [-k] [--no-mp] [-v]
                 [--gdb] [--gdb-port GDB_PORT] [-V HOST:GUEST]
                 [config-derived flags...]
```

Most scalar and toggle fields from `SpeakeasyConfig` are exposed automatically as CLI flags. Flag names are derived from config paths using dashes, for example:

- `analysis.memory_tracing` -> `--analysis-memory-tracing` / `--no-analysis-memory-tracing`
- `analysis.coverage` -> `--analysis-coverage`
- `modules.module_directory_x86` -> `--modules-module-directory-x86`
- `user.is_admin` -> `--user-is-admin` / `--no-user-is-admin`

Mapping fields are repeatable with `KEY=VALUE` syntax:

- `--env KEY=VALUE`
- `--network-dns-names HOST=IP`

Runtime config precedence is:

1. built-in `SpeakeasyConfig` defaults
2. optional `--config` overlay
3. explicit CLI overrides

Use `--dump-default-config` to print the full built-in default profile as JSON.

At execution start, speakeasy logs the active configuration values at INFO level.

CLI deep references:
- [CLI reference](doc/cli-reference.md)
- [CLI analysis recipes](doc/cli-analysis-recipes.md)
- [CLI environment overrides](doc/cli-environment-overrides.md)
- [CLI execution controls](doc/cli-execution-controls.md)
- [CLI help snapshot (showboat)](doc/cli-help-showboat.md)

---

### Examples

Emulating a Windows driver:

```console
user@mybox:~/speakeasy$ speakeasy -t ~/drivers/MyDriver.sys
```

Emulating 32-bit Windows shellcode:

```console
user@mybox:~/speakeasy$ speakeasy --target ~/sc.bin --raw --arch x86
```

Emulating 64-bit Windows shellcode and create a full memory dump:

```console
user@mybox:~/speakeasy$ speakeasy --target ~/sc.bin --raw --arch x64 --memory-dump-path memdump.zip
```

---

## Debugging with GDB

Speakeasy supports interactive debugging via the GDB Remote Serial Protocol. When you pass `--gdb`, the emulator pauses before the first instruction and waits for a GDB client to connect. Install the optional dependency first:

```
pip install speakeasy-emulator[gdb]
```

### Debugging a 32-bit DLL

Start speakeasy with `--gdb` in one terminal. It will pause before the first instruction and wait for a GDB connection:

```console
speakeasy -t sample.dll --gdb --gdb-port 1234
```

In a second terminal, connect with `gdb` (or `gdb-multiarch`) and set the architecture to `i386`. From there you can inspect registers, disassemble, single-step, set breakpoints, and continue:

```
$ gdb-multiarch
(gdb) set architecture i386
The target architecture is set to "i386".
(gdb) target remote localhost:1234
0x10001383 in ?? ()
(gdb) info registers
eax            0x0                 0
ecx            0x0                 0
edx            0x0                 0
ebx            0x0                 0
esp            0x12fffec           0x12fffec
ebp            0x1300000           0x1300000
esi            0x0                 0
edi            0x0                 0
eip            0x10001383          0x10001383
eflags         0x2                 [ ]
cs             0x8b                139
ss             0x90                144
ds             0x83                131
es             0x0                 0
fs             0x9b                155
gs             0x0                 0
(gdb) x/5i $pc
=> 0x10001383:	push   %ebp
   0x10001384:	mov    %esp,%ebp
   0x10001386:	cmpl   $0x1,0xc(%ebp)
   0x1000138a:	jne    0x10001391
   0x1000138c:	call   0x100017f9
(gdb) stepi
0x10001384 in ?? ()
(gdb) stepi
0x10001386 in ?? ()
(gdb) info registers eip esp ebp
eip            0x10001386          0x10001386
esp            0x12fffe8           0x12fffe8
ebp            0x12fffe8           0x12fffe8
(gdb) x/10i $pc
=> 0x10001386:	cmpl   $0x1,0xc(%ebp)
   0x1000138a:	jne    0x10001391
   0x1000138c:	call   0x100017f9
   0x10001391:	push   0x10(%ebp)
   0x10001394:	push   0xc(%ebp)
   0x10001397:	push   0x8(%ebp)
   0x1000139a:	call   0x1000125d
   0x1000139f:	add    $0xc,%esp
   0x100013a2:	pop    %ebp
   0x100013a3:	ret    $0xc
(gdb) continue
```

### Debugging a 64-bit DLL

For 64-bit binaries, set the GDB architecture to `i386:x86-64`:

```
$ gdb-multiarch
(gdb) set architecture i386:x86-64
The target architecture is set to "i386:x86-64".
(gdb) target remote localhost:1234
0x0000000180001410 in ?? ()
(gdb) info registers rip rsp rbp rdi rsi rcx rdx
rip            0x180001410         0x180001410
rsp            0x12fffb0           0x12fffb0
rbp            0x12fffd8           0x12fffd8
rdi            0x0                 0
rsi            0x0                 0
rcx            0x180000000         6442450944
rdx            0x1                 1
(gdb) x/5i $pc
=> 0x180001410:	mov    %rbx,0x8(%rsp)
   0x180001415:	mov    %rsi,0x10(%rsp)
   0x18000141a:	push   %rdi
   0x18000141b:	sub    $0x20,%rsp
   0x18000141f:	mov    %r8,%rdi
(gdb) stepi
0x0000000180001415 in ?? ()
(gdb) stepi
0x000000018000141a in ?? ()
(gdb) x/4xg $rsp
0x12fffb0:	0x00000000feedf000	0x0000000000000000
0x12fffc0:	0x0000000000000000	0x0000000000000000
(gdb) continue
```

### Setting breakpoints and inspecting memory

Set a breakpoint at an address, continue to it, then examine the stack:

```
(gdb) break *0x1000139a
Breakpoint 1 at 0x1000139a
(gdb) continue

Breakpoint 1, 0x1000139a in ?? ()
(gdb) x/5i $pc
=> 0x1000139a:	call   0x1000125d
   0x1000139f:	add    $0xc,%esp
   0x100013a2:	pop    %ebp
   0x100013a3:	ret    $0xc
   0x100013a6:	push   %ebp
(gdb) x/8xw $esp
0x12fffdc:	0x10000000	0x00000001	0x00000000	0x01300000
0x12fffec:	0xfeedf000	0x10000000	0x00000001	0x00000000
(gdb) info registers eip esp eax
eip            0x1000139a          0x1000139a
esp            0x12fffdc           0x12fffdc
eax            0x12fffdc           19922908
(gdb) continue
```

### Programmatic usage

The GDB server can also be enabled when using speakeasy as a Python library:

```python
import speakeasy

se = speakeasy.Speakeasy(gdb_port=1234)
module = se.load_module("sample.dll")
# Blocks here waiting for GDB to connect, then emulates under GDB control
se.run_module(module)
```

See [doc/gdb](doc/gdb.md) for the full reference, including IDA Pro integration and limitations.

---

## Configuration

A Speakeasy config is the emulated machine profile. It controls the OS identity, user identity, process/module inventory, filesystem/registry/network behavior, and analysis collectors. The sample path and the quality of the final report are strongly influenced by this file.

Common high-impact fields:
- `analysis.memory_tracing`, `analysis.coverage`, `analysis.strings`: trade execution speed for deeper telemetry.
- `timeout`, `max_api_count`, `max_instructions`: stop conditions for long or looping paths.
- `modules.modules_always_exist`, `modules.functions_always_exist`: strictness of unresolved module/function lookups.
- `filesystem.files`, `registry.keys`, `network.dns/http/winsock`: deterministic environment responses for I/O-heavy samples.
- `processes[*].is_main_exe`, `modules.user_modules/system_modules`: process and loader context presented to the sample.
- `capture_memory_dumps`, `keep_memory_on_free`: memory artifact retention and report size.

Start from `speakeasy --dump-default-config` output and then tune only the fields needed for the target sample family.

Deep reference:
- [Configuration walkthrough](doc/configuration.md)

---

## Reports

A report is the structured output of one emulation session. It includes top-level metadata plus an ordered `entry_points` list, where each entry point represents one execution primitive (for example module entry, export call, callback, or injected thread).

Common high-value fields:
- top level `arch`, `sha256`, `filetype`, `emulation_total_runtime`: sample identity and run timing.
- `entry_points[*].apihash`: behavior fingerprint from unique API names.
- `entry_points[*].events`: chronological behavior stream (API, process, file, registry, network, exception).
- `entry_points[*].error`: per-run termination reason.
- `entry_points[*].dynamic_code_segments`, `sym_accesses`, `coverage`: unpacking and execution-structure indicators.
- `entry_points[*].dropped_files`: file artifacts written by the sample.
- `entry_points[*].memory`: run-end memory layout and optional compressed memory bytes.

Report content is directly influenced by config toggles such as `analysis.*`, `capture_memory_dumps`, and execution limits.

Deep reference:
- [Report walkthrough](doc/reporting.md)

---

## Memory Management

Speakeasy implements a lightweight memory manager on top of the emulator engine’s memory management. Each chunk of memory allocated by malware is tracked and tagged so that meaningful memory dumps can be acquired. Being able to attribute activity to specific chunks of memory can prove to be extremely useful for analysts. Logging memory reads and writes to sensitive data structures can reveal the true intent of malware not revealed by API call logging which is particularly useful for samples such as rootkits.

---

## Speed

Because Speakeasy is written in Python, speed is an obvious concern. Transitioning between native code and Python is extremely expensive and should be done as little as possible. Therefore, the goal is to only execute Python code when it is absolutely necessary. By default, the only events handled in Python are memory access exceptions or Windows API calls. In order to catch Windows API calls and emulate them in Python, import tables are doped with invalid memory addresses so that Python code is only executed when import tables are accessed. Similar techniques are used for when shellcode accesses the export tables of DLLs loaded within the emulated address space of shellcode. By executing as little Python code as possible, reasonable speeds can be achieved while still allowing users to rapidly develop capabilities for the framework.

---

## Limitations

Since we do not rely on a physical OS to handle API calls, object and memory allocation, and I/O operations, these responsibilities fall to the emulator. Upon emulating multiple samples, users are likely to encounter samples that do not fully emulate. This can most likely be attributed to missing API handlers, specific OS implementation  details, or environmental factors. For more details see [doc/limitations](doc/limitations.md).

---

## Module export parsing

Many malware samples such as shellcode will attempt to manually parse the export tables of PE modules in order resolve API function pointers. An attempt is made to make "decoy" export tables using the emulated function names currently supported but this may not be enough for some samples. The configuration files support two fields named `module_directory_x86` and `module_directory_x64`. These fields are directories that can contain DLLs or other modules that are loaded into the virtual address space of the emulated sample. They can also be overridden at runtime with `--modules-module-directory-x86` and `--modules-module-directory-x64`.

---

## Adding API handlers

 Like most emulators, API calls made to the OS are handled by the framework. Emulated API handlers can be added by simply defining a function with the correct name in its corresponding emulated module. Depending on the outputs expected by the API, it may be sufficient enough to simply return a success code. The argument count must be specified in order for the stack to be cleaned up correctly. If no calling convention is specified, stdcall is assumed. The argument list is passed to the emulated function as raw integers. 
 
 Below is an example of an API handler for the HeapAlloc function in the kernel32 module.

```python
    @apihook('HeapAlloc', argc=3)
    def HeapAlloc(self, emu, argv, ctx={}):
        '''
        DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
          HANDLE hHeap,
          DWORD  dwFlags,
          SIZE_T dwBytes
        );
        '''

        hHeap, dwFlags, dwBytes = argv

        chunk = self.heap_alloc(dwBytes, heap='HeapAlloc')
        if chunk:
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return chunk
```

---

## Mounting Host Files with `--volume`

The `-V`/`--volume` flag mounts host files or directories into the emulated Windows filesystem, similar to Docker's `-v` flag. The format is `host_path:guest_path`. Multiple volumes can be specified.

### Mount a single file

```python
from speakeasy.volumes import parse_volume_spec

# Unix host path -> Windows guest path
host, guest = parse_volume_spec("/data/payload.dll:c:\\windows\\system32\\payload.dll")
print(f"Host:  {host}")
print(f"Guest: {guest}")

# Windows drive letters on both sides
host, guest = parse_volume_spec("C:\\samples\\mal.exe:D:\\staging\\mal.exe")
print(f"Host:  {host}")
print(f"Guest: {guest}")
```

```output
Host:  /data/payload.dll
Guest: c:\windows\system32\payload.dll
Host:  C:\samples\mal.exe
Guest: D:\staging\mal.exe
```

### Mount a directory of files

```python
from speakeasy.volumes import expand_volume_to_entries
from pathlib import Path, PureWindowsPath

entries = expand_volume_to_entries(Path("/tmp/vol_demo"), PureWindowsPath("c:\\appdata"))
for e in entries:
    print(f"{e['emu_path']}  <-  {e['path']}")
```

```output
c:\appdata\configs\settings.ini  <-  /tmp/vol_demo/configs/settings.ini
c:\appdata\sample.bin  <-  /tmp/vol_demo/sample.bin
```

### CLI usage

Mount a single file into the emulated filesystem:

```console
speakeasy -t malware.exe -V /data/config.dat:c:\appdata\config.dat
```

Mount an entire directory (files are added recursively):

```console
speakeasy -t malware.exe -V /data/samples:c:\windows\temp
```

Multiple volumes can be combined:

```console
speakeasy -t malware.exe \\
  -V /data/configs:c:\programdata \\
  -V /data/payload.dll:c:\windows\system32\payload.dll
```

### Programmatic usage

Volumes can also be passed directly to the `Speakeasy` constructor:
```python
import speakeasy

se = speakeasy.Speakeasy(volumes=[
    "/data/config.dat:c:\\appdata\\config.dat",
    "/data/samples:c:\\windows\\temp",
])
module = se.load_module("malware.exe")
se.run_module(module)
```

---

## Further information

- [doc/cli-reference](doc/cli-reference.md)
- [doc/cli-analysis-recipes](doc/cli-analysis-recipes.md)
- [doc/cli-environment-overrides](doc/cli-environment-overrides.md)
- [doc/cli-execution-controls](doc/cli-execution-controls.md)
- [doc/cli-help-showboat](doc/cli-help-showboat.md)
- [doc/configuration](doc/configuration.md)
- [doc/memory](doc/memory.md)
- [doc/reporting](doc/reporting.md)
- [doc/limitations](doc/limitations.md)
- [doc/gdb](doc/gdb.md)
