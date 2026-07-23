# GDB Debugging

Speakeasy supports interactive debugging of emulated binaries via the GDB Remote Serial Protocol. When enabled, the emulator pauses before the first instruction and waits for a GDB client to connect. You can then set breakpoints, inspect registers and memory, single-step, and continue execution — all through a standard GDB interface.

---

## Quick Start

### 1. Start speakeasy with GDB enabled

```console
speakeasy -t sample.exe --gdb
```

This starts the GDB server on the default port (1234). Speakeasy will print a message and block until a GDB client connects:

```
Native GDB server listening on 127.0.0.1:1234, waiting for connection...
```

To use a different port:

```console
speakeasy -t sample.exe --gdb --gdb-port 9999
```

The server binds to loopback by default. To allow a debugger on another machine to connect, explicitly choose a bind address:

```console
speakeasy -t sample.exe --gdb --gdb-host 0.0.0.0 --gdb-port 9999
```

> **Warning:** GDB RSP has no authentication and permits target memory and register modification. Only use a non-loopback `--gdb-host` on a trusted network or behind an appropriate firewall/tunnel.
>
> `--gdb` automatically enables `--no-mp` because the server must remain attached to the same Unicorn instance.

### 2. Connect with GDB

In another terminal, connect using `gdb-multiarch` (or your platform's GDB):

**For a 32-bit x86 binary:**

```console
$ gdb-multiarch
(gdb) set architecture i386
(gdb) target remote localhost:1234
```

**For a 64-bit x86-64 binary:**

```console
$ gdb-multiarch
(gdb) set architecture i386:x86-64
(gdb) target remote localhost:1234
```

Once connected, GDB will show the current stop position. From here you can debug normally.

### 3. Debug

Standard GDB commands work:

```
(gdb) info registers
(gdb) x/10i $pc
(gdb) break *0x10001000
(gdb) continue
(gdb) stepi
(gdb) x/32xb $esp
```

---

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

---

## Using with IDA Pro

IDA Pro's built-in GDB debugger can connect to the speakeasy GDB stub:

1. Start speakeasy with `--gdb`
2. In IDA, go to **Debugger > Select debugger > Remote GDB debugger**
3. Set **Hostname** to `localhost` and **Port** to `1234` (or your chosen port)
4. Click **Debugger > Attach to process** or **Start process**

---

## Programmatic Usage

The GDB server can also be enabled when using speakeasy as a library:

```python
import speakeasy

se = speakeasy.Speakeasy(gdb_port=1234, gdb_host="127.0.0.1")
module = se.load_module("sample.dll")
# This will block waiting for GDB to connect before emulating
se.run_module(module)
```

---

## How It Works

Speakeasy implements the all-stop GDB Remote Serial Protocol directly. The server provides register and memory access, software and hardware breakpoints, watchpoints, single-step, asynchronous Ctrl-C pause, and the Windows process metadata used by IDA:

- `qXfer:libraries:read` returns all mapped Speakeasy PE modules
- `qXfer:exec-file:read` returns the emulated executable path
- `qXfer:threads:read`, `qfThreadInfo`, and `qGetTIBAddr` describe the active emulated thread
- `qXfer:features:read` reports a register layout matching the emulated architecture
- `qXfer:memory-map:read` reports Unicorn's mapped memory regions
- `vCont`, legacy resume packets, register/memory writes, detach, and process exit are supported

A socket reader handles RSP framing and can stop Unicorn asynchronously when it receives Ctrl-C. Breakpoint and watchpoint hooks only record a stop reason and stop Unicorn; protocol processing happens after `emu_start()` returns, rather than from inside a Unicorn callback.

---

## Supported protocol subset

The server implements the all-stop RSP subset exercised by GDB and IDA:

| Area | Packets |
|---|---|
| Transport | checksums, ACK/NACK retransmission, `QStartNoAckMode`, binary escaping, raw Ctrl-C |
| Target discovery | `qSupported`, `qXfer:features:read`, `qXfer:memory-map:read` |
| Windows metadata | `qXfer:libraries:read`, `qXfer:exec-file:read`, `qXfer:threads:read`, `qGetTIBAddr` |
| Thread selection | `qC`, `qfThreadInfo`, `qsThreadInfo`, `H`, `T` for the synthetic active thread |
| Registers | `g`, `G`, `p`, `P` |
| Memory | `m`, `M`, `X` |
| Breakpoints | `Z0`/`z0`, `Z1`/`z1`, and read/write/access watchpoints |
| Execution | `c`, `s`, `vCont`, asynchronous Ctrl-C, `?` |
| Lifecycle | `D`, `k`, and `Wxx` exit replies |

Unsupported optional packets receive an empty response as required by RSP. Non-stop mode, multiprocess mode, reverse execution, and remote file I/O are not advertised.

## Limitations

- one debugger client can connect to a Speakeasy instance
- Speakeasy models Windows thread objects but executes one Unicorn CPU context at a time; the server therefore presents the currently active execution context as one synthetic GDB thread
- breakpoints persist across runs: Speakeasy executes multiple runs (for example TLS callbacks, the module entry point, and exports)
- reverse execution, non-stop mode, and multiprocess RSP are not implemented

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [GDB sessions (showboat)](gdb-examples.md)
- [CLI execution controls](cli-execution-controls.md)
- [Help and troubleshooting](help.md)
