# GDB Debugging

Speakeasy has a GDB server for the GDB Remote Serial Protocol (RSP). With the server on, the emulator stops before the first instruction and waits for a GDB client. In the client, you can set breakpoints, read and write registers and memory, step and continue.

`GetProcAddress`, the IAT and the export table give the address of a Windows API as the address of code in the DLL image. You can set a breakpoint on this address. When you step into the API, the guest runs this code before the emulator calls the Python handler. See [Unified Windows API addresses](unified-api-addresses.md) for the layout of this code.

## Quick Start

### 1. Start speakeasy with GDB enabled

```console
speakeasy -t sample.exe --gdb
```

The GDB server listens on port 1234. Speakeasy logs this message and waits until a GDB client connects:

```
Native GDB server listening on 127.0.0.1:1234, waiting for connection...
```

To use a different port:

```console
speakeasy -t sample.exe --gdb --gdb-port 9999
```

The server listens on loopback. To let a debugger on a different machine connect, give a bind address:

```console
speakeasy -t sample.exe --gdb --gdb-host 0.0.0.0 --gdb-port 9999
```

RSP has no authentication, and a client can change the memory and registers of the target. Use a `--gdb-host` other than loopback only on a trusted network, or behind a firewall or a tunnel. Speakeasy logs a warning for such a host. With `--gdb`, the CLI also sets `--no-mp`.

### 2. Connect with GDB

In a different terminal, connect with `gdb-multiarch` or the GDB of your platform.

For a 32-bit x86 binary:

```console
$ gdb-multiarch
(gdb) set architecture i386
(gdb) target remote localhost:1234
```

For a 64-bit x86-64 binary:

```console
$ gdb-multiarch
(gdb) set architecture i386:x86-64
(gdb) target remote localhost:1234
```

GDB then shows the address where the emulator stopped.

### 3. Debug

Use the usual GDB commands:

```
(gdb) info registers
(gdb) x/10i $pc
(gdb) break *0x10001000
(gdb) continue
(gdb) stepi
(gdb) x/32xb $esp
```

## Examples

### Debugging a DLL

```console
speakeasy -t malware.dll --gdb --gdb-port 1234
```

```console
$ gdb-multiarch
(gdb) set architecture i386
(gdb) target remote localhost:1234
(gdb) break *0x10001000
(gdb) continue
Breakpoint 1, 0x10001000 in ?? ()
(gdb) info registers
(gdb) x/10i $pc
```

### Debugging shellcode

```console
speakeasy --target shellcode.bin --raw --arch x86 --gdb
```

```console
$ gdb-multiarch
(gdb) set architecture i386
(gdb) target remote localhost:1234
(gdb) stepi
(gdb) info registers
```

### Debugging a kernel driver

```console
speakeasy -t rootkit.sys --gdb --gdb-port 4444
```

```console
$ gdb-multiarch
(gdb) set architecture i386:x86-64
(gdb) target remote localhost:4444
(gdb) continue
```

## Using with IDA Pro

The Remote GDB debugger of IDA Pro can connect to the Speakeasy GDB server:

1. Start speakeasy with `--gdb`
2. In IDA, go to **Debugger > Select debugger > Remote GDB debugger**
3. Set **Hostname** to `localhost` and **Port** to `1234` (or your port)
4. Click **Debugger > Attach to process** or **Start process**

## Programmatic Usage

To start the GDB server from the library, give `gdb_port` to `Speakeasy`:

```python
import speakeasy

se = speakeasy.Speakeasy(gdb_port=1234, gdb_host="127.0.0.1")
module = se.load_module("sample.dll")
# This will block waiting for GDB to connect before emulating
se.run_module(module)
```

## How It Works

Speakeasy implements the all-stop mode of RSP itself. A reader thread reads the RSP packets from the socket. When it gets Ctrl-C, it stops Unicorn. Breakpoint and watchpoint hooks record the stop reason and stop Unicorn. The emulator thread handles the packets only after Unicorn stops.

The server gives the Windows process data that IDA uses:

- `qXfer:libraries:read` gives all mapped PE modules. When a module maps or unmaps while the target runs, for example in `LoadLibrary`, the server stops the target with the `library` stop reason. The client then reads the list again.
- `qXfer:exec-file:read` gives the path of the module of the current run.
- `qXfer:threads:read` and `qfThreadInfo` give the active thread, and `qGetTIBAddr` gives the address of its TEB.
- `qXfer:features:read` gives the registers of the emulated architecture.
- `qXfer:memory-map:read` gives the mapped memory regions of Unicorn.

When the last run ends without a fault, the server stops the target with a `T05` stop reply, and then sends `W00`. This is also true when an earlier run faulted. So the client can read the final memory, for example to dump an unpacked image after `ExitProcess`. When the last run faults, the server sends `X0b` after the fault stop.

## Supported protocol subset

The server implements the all-stop RSP subset that GDB and IDA use:

| Area | Packets |
|---|---|
| Transport | checksums, ACK/NACK retransmission, `QStartNoAckMode`, binary escaping, raw Ctrl-C |
| Target discovery | `qSupported`, `qXfer:features:read`, `qXfer:memory-map:read` |
| Windows metadata | `qXfer:libraries:read`, `qXfer:exec-file:read`, `qXfer:threads:read`, `qGetTIBAddr` |
| Thread selection | `qC`, `qfThreadInfo`, `qsThreadInfo`, `H`, `T` for the one active thread |
| Registers | `g`, `G`, `p`, `P` |
| Memory | `m`, `M`, `X` |
| Breakpoints | `Z0`/`z0`, `Z1`/`z1` and the read, write and access watchpoints (`Z2` to `Z4`) |
| Execution | `c`, `s`, `C`, `S` (the server ignores the signal), `vCont`, asynchronous Ctrl-C, `?`, `swbreak`/`hwbreak`/watchpoint/`library` stop replies |
| Lifecycle | `D`, `k`, `vKill`, a final `T05` stop before exit and `Wxx` exit replies |

The server sends an empty reply to an optional packet that it does not support, as RSP requires. The server does not implement non-stop mode, multiprocess mode, reverse execution or remote file I/O.

## Limitations

- One debugger client can connect to a Speakeasy instance.
- Speakeasy has Windows thread objects, but Unicorn runs one CPU context at a time. The server shows the active context as one GDB thread.
- The server keeps breakpoints across runs. A run is one call into guest code, such as a TLS callback, the entry point or an export.
- `FreeLibrary` does not unmap a module, so the library list does not change after it.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [CLI execution controls](cli-execution-controls.md)
- [Help and troubleshooting](help.md)
