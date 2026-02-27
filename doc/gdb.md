# GDB Debugging

Speakeasy supports interactive debugging of emulated binaries via the GDB Remote Serial Protocol. When enabled, the emulator pauses before the first instruction and waits for a GDB client to connect. You can then set breakpoints, inspect registers and memory, single-step, and continue execution — all through a standard GDB interface.

This uses the [udbserver](https://github.com/bet4it/udbserver) library, which hooks directly into the Unicorn emulation engine.

---

## Installation

The GDB server support is an optional dependency. Install it with:

```console
pip install speakeasy-emulator[gdb]
```

Or if installing from source:

```console
pip install -e ".[gdb]"
```

---

## Quick Start

### 1. Start speakeasy with GDB enabled

```console
speakeasy -t sample.exe --gdb
```

This starts the GDB server on the default port (1234). Speakeasy will print a message and block until a GDB client connects:

```
GDB server listening on port 1234, waiting for connection...
```

To use a different port:

```console
speakeasy -t sample.exe --gdb --gdb-port 9999
```

> **Note:** `--gdb` automatically enables `--no-mp` (in-process emulation). This is required because the GDB server hooks are bound to a specific Unicorn engine instance and cannot cross process boundaries.

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

se = speakeasy.Speakeasy(gdb_port=1234)
module = se.load_module("sample.dll")
# This will block waiting for GDB to connect before emulating
se.run_module(module)
```

---

## How It Works

The GDB integration uses `udbserver`, which installs Unicorn hooks for breakpoints, watchpoints, and single-stepping. When `gdb_port` is set:

1. Speakeasy loads the binary and sets up all its emulation hooks normally
2. Speakeasy initializes the first run context (stack/arguments/registers), including setting PC to the run entry point
3. Before the first `emu_start()` call, `udbserver()` is called with `start_addr=0`
4. This blocks on a TCP accept, waiting for a GDB client
5. The GDB client connects, sets breakpoints, and issues `continue`
6. `udbserver()` returns and emulation proceeds under GDB control
7. The udbserver hooks persist across all emulation runs (DllMain, exports, etc.)

---

## Limitations

- **One session per process**: udbserver uses global state internally, so only one GDB server can be active per process.
- **Breakpoints persist across runs**: Speakeasy executes multiple "runs" (e.g., DllMain followed by each exported function). Breakpoints set in GDB remain active across all runs, but execution may appear to "restart" at new entry points.
- **Platform support**: udbserver ships prebuilt binaries for Linux, macOS, and Windows. If your platform is not supported, `--gdb` will fail with an import error.
