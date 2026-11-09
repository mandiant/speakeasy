# Python exceptions

The `Speakeasy` class raises the exceptions that `speakeasy` exports, for example `speakeasy.InputError`. All of them derive from `SpeakeasyError`, so one `except SpeakeasyError` catches every error that Speakeasy raises. These are Python exceptions for the caller. For the CPU exceptions that the guest program gets, see [Guest exception dispatch](exceptions.md).

```
SpeakeasyError
├── ConfigError              the configuration or a volume is not valid
├── InputError               the input is missing, is not a PE, has an unsupported architecture, or is a second input
├── EmulationError           base class of the errors at run time
│   ├── ApiEmuError          an API handler failed
│   ├── NotSupportedError    Speakeasy does not emulate this kind of sample, for example .NET
│   ├── OutOfMemoryError     no free range of the address space can hold an allocation
│   ├── CpuError             a register name is not known, or no instruction decodes
│   ├── WindowsEmuError      the Windows emulation failed
│   │   ├── FileSystemEmuError   in the emulated file system
│   │   ├── NetworkEmuError      in the emulated network
│   │   └── RegistryEmuError     in the emulated registry
│   ├── Win32EmuError        the user mode emulation failed
│   └── KernelEmuError       the kernel mode emulation failed
└── EngineError              the CPU engine rejected a request, for example an unknown hook type
```

`EmuException` and `EmuEngineError` are the 1.x names of `CpuError` and `EngineError`. They stay in `speakeasy.errors` as aliases for one release, but `speakeasy` does not export them.

Each method that uses the emulator raises `SpeakeasyError` if no input is loaded yet. The table gives the other exceptions of the public methods:

| Method | Raises |
|---|---|
| `Speakeasy(...)` | `ConfigError` if the configuration is not valid, a volume is malformed or its host path does not exist, or `volumes` is set together with a `SpeakeasyConfig` |
| `load_module` | `InputError` if the object already has an input, neither `path` nor `data` is given, the file is missing, the input is not a valid PE or its architecture is not x86 or x64; `NotSupportedError` for a .NET assembly |
| `load_shellcode` | `InputError` if the object already has an input, neither `fpath` nor `data` is given, the file is missing or `arch` is not x86, x64 or amd64 |
| `run_shellcode` | `SpeakeasyError` if the kernel mode emulator is loaded |
| `disasm`, `mem_read`, `mem_write` | `SpeakeasyError` if the operation fails |
| `mem_alloc` | `OutOfMemoryError` if no free range below the address limit can hold the block |
| `reg_read`, `reg_write` | `CpuError` if the name is not a register |

`run_module`, `run_shellcode`, `call` and `resume` do not raise for errors in the guest program. The run stops and the report records the error.
