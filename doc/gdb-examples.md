# Debugging with GDB

*2026-02-23T11:40:03Z by Showboat 0.6.0*
<!-- showboat-id: ac2ac381-ee5b-43cb-889c-b7dc7e65544f -->

Speakeasy supports interactive debugging via the GDB Remote Serial Protocol. When you pass `--gdb`, the emulator pauses before the first instruction and waits for a GDB client to connect. You can then set breakpoints, inspect registers and memory, single-step, and continue execution — all through a standard GDB interface.

Install the optional GDB dependency:

```
pip install speakeasy-emulator[gdb]
```

### Debugging a 32-bit DLL

Start speakeasy with `--gdb` on a sample DLL. It will pause before the first instruction and wait for GDB to connect. In a second terminal, connect with `gdb` (or `gdb-multiarch`) and set the architecture to `i386`:

```
# Terminal 1
speakeasy -t sample.dll --gdb --gdb-port 1234

# Terminal 2
gdb-multiarch
(gdb) set architecture i386
(gdb) target remote localhost:1234
```

Here is a complete session showing registers, disassembly, single-stepping, and continuing to completion:

```bash

# Start speakeasy in background on a test DLL
/Users/user/code/hex-rays/ida-sandbox-plugin/.venv/bin/python -m speakeasy -t /tmp/dll_test_x86.dll --gdb --gdb-port 11239 >/dev/null 2>&1 &
PID=$\!
sleep 3

# Connect with GDB in batch mode
/nix/store/qaply7216r7vvpyviwjkglani26ms5zi-devshell-dir/bin/gdb -batch \
  -ex 'set architecture i386' \
  -ex 'target remote localhost:11239' \
  -ex 'info registers' \
  -ex 'x/5i $pc' \
  -ex 'stepi' \
  -ex 'stepi' \
  -ex 'info registers eip esp ebp' \
  -ex 'x/10i $pc' \
  -ex 'continue' \
  2>&1 | grep -v '^warning:' | grep -v 'determining executable' | grep -v '^Remote connection'

wait $PID 2>/dev/null
exit 0

```

```output
The target architecture is set to "i386".
0x10001383 in ?? ()
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
=> 0x10001383:	push   %ebp
   0x10001384:	mov    %esp,%ebp
   0x10001386:	cmpl   $0x1,0xc(%ebp)
   0x1000138a:	jne    0x10001391
   0x1000138c:	call   0x100017f9
0x10001384 in ?? ()
0x10001386 in ?? ()
eip            0x10001386          0x10001386
esp            0x12fffe8           0x12fffe8
ebp            0x12fffe8           0x12fffe8
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
```

### Debugging a 64-bit DLL

For 64-bit binaries, set the GDB architecture to `i386:x86-64`:

```
# Terminal 1
speakeasy -t sample_x64.dll --gdb

# Terminal 2
gdb-multiarch
(gdb) set architecture i386:x86-64
(gdb) target remote localhost:1234
```

Here is a session that connects, inspects the entry point, reads the stack, and resumes:

```bash

/Users/user/code/hex-rays/ida-sandbox-plugin/.venv/bin/python -m speakeasy -t /tmp/dll_test_x64.dll --gdb --gdb-port 11240 >/dev/null 2>&1 &
PID=$\!
sleep 3

/nix/store/qaply7216r7vvpyviwjkglani26ms5zi-devshell-dir/bin/gdb -batch \
  -ex 'set architecture i386:x86-64' \
  -ex 'target remote localhost:11240' \
  -ex 'info registers rip rsp rbp rdi rsi rcx rdx' \
  -ex 'x/5i $pc' \
  -ex 'stepi' \
  -ex 'stepi' \
  -ex 'info registers rip' \
  -ex 'x/4xg $rsp' \
  -ex 'continue' \
  2>&1 | grep -v '^warning:' | grep -v 'determining executable' | grep -v '^Remote connection'

wait $PID 2>/dev/null
exit 0

```

```output
The target architecture is set to "i386:x86-64".
0x0000000180001410 in ?? ()
rip            0x180001410         0x180001410
rsp            0x12fffb0           0x12fffb0
rbp            0x12fffd8           0x12fffd8
rdi            0x0                 0
rsi            0x0                 0
rcx            0x180000000         6442450944
rdx            0x1                 1
=> 0x180001410:	mov    %rbx,0x8(%rsp)
   0x180001415:	mov    %rsi,0x10(%rsp)
   0x18000141a:	push   %rdi
   0x18000141b:	sub    $0x20,%rsp
   0x18000141f:	mov    %r8,%rdi
0x0000000180001415 in ?? ()
0x000000018000141a in ?? ()
rip            0x18000141a         0x18000141a
0x12fffb0:	0x00000000feedf000	0x0000000000000000
0x12fffc0:	0x0000000000000000	0x0000000000000000
```

### Setting breakpoints and inspecting memory

You can set breakpoints at specific addresses, continue to them, and inspect memory or registers when they hit. This example sets a breakpoint on the `DllMain` wrapper function, continues to it, then examines memory at the stack pointer:

```bash

/Users/user/code/hex-rays/ida-sandbox-plugin/.venv/bin/python -m speakeasy -t /tmp/dll_test_x86.dll --gdb --gdb-port 11241 >/dev/null 2>&1 &
PID=$\!
sleep 3

/nix/store/qaply7216r7vvpyviwjkglani26ms5zi-devshell-dir/bin/gdb -batch \
  -ex 'set architecture i386' \
  -ex 'target remote localhost:11241' \
  -ex 'break *0x1000139a' \
  -ex 'continue' \
  -ex 'x/5i $pc' \
  -ex 'x/8xw $esp' \
  -ex 'info registers eip esp eax' \
  -ex 'continue' \
  2>&1 | grep -v '^warning:' | grep -v 'determining executable' | grep -v '^Remote connection'

wait $PID 2>/dev/null
exit 0

```

```output
The target architecture is set to "i386".
0x10001383 in ?? ()
Breakpoint 1 at 0x1000139a

Breakpoint 1, 0x1000139a in ?? ()
=> 0x1000139a:	call   0x1000125d
   0x1000139f:	add    $0xc,%esp
   0x100013a2:	pop    %ebp
   0x100013a3:	ret    $0xc
   0x100013a6:	push   %ebp
0x12fffdc:	0x10000000	0x00000001	0x00000000	0x01300000
0x12fffec:	0xfeedf000	0x10000000	0x00000001	0x00000000
eip            0x1000139a          0x1000139a
esp            0x12fffdc           0x12fffdc
eax            0x12fffdc           19922908
```

### Programmatic usage

The GDB server can also be enabled when using speakeasy as a Python library. Pass `gdb_port` to the `Speakeasy` constructor — emulation will block until a GDB client connects:

```python
import speakeasy

se = speakeasy.Speakeasy(gdb_port=1234)
module = se.load_module("sample.dll")
# Blocks here waiting for GDB to connect, then emulates under GDB control
se.run_module(module)
```

See [doc/gdb.md](gdb.md) for the full reference, including IDA Pro integration and limitations.
