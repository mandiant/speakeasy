# Architecture of the Windows emulator

This page tells you where the main parts of the Windows emulator are, and how a call to a Windows API reaches a Python handler.

## Classes

`BinaryEmulator` (`speakeasy/binemu.py`) wraps Unicorn and capstone. It has the memory manager and the hook lists, and no Windows-specific code.

`WindowsEmulator` (`speakeasy/windows/winemu.py`) adds processes, threads, modules, runs, API calls and SEH. It also gives access to the object, file, registry and network managers. The file, registry and network managers record the report events, so a handler does not add these events itself.

`Win32Emulator` (`speakeasy/windows/win32.py`) runs user mode executables, DLLs and shellcode. `WinKernelEmulator` (`speakeasy/windows/kernel.py`) runs drivers. The `Speakeasy` class (`speakeasy/speakeasy.py`) is the public interface. It creates the emulator for the input.

Each emulated DLL has one handler class in `speakeasy/winenv/api/`. Each handler has an `@apihook` decorator with the export name, the number of arguments and the calling convention. See [Adding API handlers](api-handlers.md).

## Runs

A `Run` is one call into guest code: the entry point, a DLL export, a thread, a TLS callback or a DllMain. The emulator keeps a queue of runs. `start()` adds the DllMain and TLS callbacks of the imported DLLs to the front of the queue, and `_execute_runs` runs the queue in order. `_start_next_run` sets up the stack and registers for the next run.

The return address of a run is the return hook, an address in a reserved range that is not mapped while the guest runs. When the guest returns to it, the fetch fails and the emulator records `RunReturn`. In user mode, the entry point of an EXE and the start routine of a thread return to a `jmp` in the `.dyn` section of the synthetic kernel32. The `jmp` goes to the return hook. On Windows, `BaseThreadInitThunk` in kernel32 calls these routines, and some code searches down from its return address for the `MZ` header of kernel32. The `jmp` is not an export, so it has no symbol and no API event. It adds one instruction to the run. If kernel32 is a real PE from the module directory, these runs also use the return hook. The other runs, for example DllMain, TLS callbacks, exports, shellcode and drivers, always use it.

`_execute_current_run` runs one run. Unicorn runs guest code until a hook stops it. A hook does not run API handlers or guest exception handlers. It records a native exit with `_record_exit` and stops Unicorn. If Unicorn stops and no hook recorded an exit, `_get_exit_at_pc` gets the exit from the address where Unicorn stopped. Then `_handle_exit` handles the exit, for example it calls the API handler, and the loop starts Unicorn again. A native exit tells why Unicorn stopped. It is one of these types:

- `SuspendedApiCall`: the guest called an API. The loop calls the handler of the API next.
- `RunReturn`: the guest returned from the run. The run is complete.
- `CallbackReturn`: a guest callback returned. The API handler that called it continues.
- `RunEnd`: a fault, an API handler, a hook or `stop()` ended the run. See [The end of a run](#the-end-of-a-run).
- `ExecRecovery`: the guest ran code in a guest PE page without execute permission. The loop adds the permission.
- `RaisedCpuException`: a CPU exception or a memory fault that the loop sends to the guest SEH handlers.

If two hooks record an exit before Unicorn stops, the emulator keeps the first.

`RunLimits` has the time and instruction limits of a run. The loop checks all limits before each start of Unicorn and before each API handler. Before `RunReturn`, `CallbackReturn`, `RunEnd` and `ExecRecovery`, it checks only the total time.

### The end of a run

Only the run loop completes a run and starts the next run. An API handler or a hook that must end the run calls `end_run(error)`. `end_run` records the `RunEnd` native exit and stops Unicorn. If the run already ended, `end_run` keeps the first error. A fault calls `end_run_on_fault`, which also stops the debugger, if one is attached.

When the loop handles `RunReturn` or `RunEnd`, or when the run reaches a limit, `_complete_run` records the result of the run with `on_run_complete`. The user mode emulator records the return value, the exit code of the thread and the memory layout. The kernel emulator records the return value. After DriverEntry, it adds the runs of the other routines of the driver. See [Driver runs](#driver-runs). Then `_start_next_run` prepares the next run in the queue. If the queue is empty, it completes the emulation.

`is_run_complete` is true from the call of `end_run` until the next run starts. `stop()` ends the current run, removes the runs in the queue, and ends the emulation.

### Driver runs

`WinKernelEmulator.run_module` adds a run for DriverEntry. If `all_entrypoints` is true, `_queue_driver_routines` adds the other runs when DriverEntry ends, in this order:

1. The exports of the driver.
2. The IRP handlers that DriverEntry registered: `IRP_MJ_CREATE`, `IRP_MJ_DEVICE_CONTROL`, `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_CLOSE` and `IRP_MJ_CLEANUP`. Each handler gets one IRP for the first device of the driver. The `IRP_MJ_DEVICE_CONTROL` IRP has the IOCTL code `0x5D5D5D5D`.
3. The unload routine.

If DriverEntry returns an error status, Windows does not call the other routines, and the emulator adds no runs. If DriverEntry ends with an emulator error, for example an unsupported API, the emulator adds the runs, because they show more of the driver. A driver with no entry point gets these runs at once. Each kernel run starts at `PASSIVE_LEVEL`.

## API calls

Each export of an emulated DLL has 32 bytes of code in the DLL image. The code jumps to a token in a reserved range that the emulator never maps. When the guest calls the API, Unicorn fails to fetch the token, and `_intercept_api_trap` finds the API for the token. The export table, the IAT and `GetProcAddress` give the address of the export code. The guest can read, patch and hook this code. See [Unified Windows API addresses](unified-api-addresses.md).

`dispatch_api_call(dll, name)` calls `resolve_api_implementation` to find the code to run. `speakeasy/windows/api_resolution.py` has one class for each result, in this order:

1. `HandlerImplementation`: the handler for the name, or for a related name. User hooks for the API run first, and they can call the handler.
2. `UserHookImplementation`: a user hook without a handler. The emulator runs the hook that the caller added last.
3. `SignatureImplementation`: a function from the signature database. It logs the arguments and returns a success value.
4. `StubImplementation`: with `functions_always_exist`, a stub that returns 1.
5. `UnsupportedImplementation`: the run ends with an `unsupported_api` error.

`get_handler_candidates(dll, name)` gives the related names, in order: for example, the name without the `A` or `W` suffix, the `Zw` name for an `Nt` name, or the modules that implement an API set (`get_dll_hosts`). `get_api_handler` uses the first related name that has a handler. `get_proc` asks `get_import_host` for the module of an import. When more than one module implements an API set, `get_import_host` returns the first module that has a handler for the name.

A handler can call guest code, for example a window procedure, with `setup_callback` or by yielding `GuestCall`. `speakeasy/windows/guest_callbacks.py` keeps track of these calls.

## Machine setup

`init_machine(arch)` creates the machine before an image loads. The `Speakeasy` class calls it with the architecture of the input. It creates the Unicorn engine, the disassembler and the API layer. Then `init_machine_structures` creates the object manager, the GDT and the segments, `KUSER_SHARED_DATA`, the system modules and the user modules of the config. In user mode, it also adds the processes of the config to the process list, except the `is_main_exe` entry. The process enumeration APIs read this list. Later, `load_container` adds the container process, or `run_module` adds the process of an EXE input, at the end of the list.

If the caller adds a hook before the load, the `Speakeasy` class keeps it in a list, because the engine does not exist yet. The `Speakeasy` class adds these hooks to the engine right after `init_machine`, before the load maps the input. So a memory map hook added before the load sees the maps of the load, but not the maps that `init_machine` makes.

In user mode, when the input is a DLL or shellcode, the `Speakeasy` class then calls `load_container`, before the input loads. `load_container` loads the container image and makes its process the current process. The container image is a placeholder for the EXE that loaded the DLL or that runs the shellcode, and it is the main image of the process. The entry in `processes` of the config that has `is_main_exe` set defines it (see [Configuration walkthrough](configuration.md)). The container image is a synthetic module, unless the module directory has a file with its name, such as `main.exe`. The `ImageBaseAddress` of the PEB and `GetModuleHandle(NULL)` give its base. The container process uses the session of the entry, but not its `pid`.

When the input is an EXE, there is no container image, and the input is the main image of the process. When the config has no `is_main_exe` entry, `load_container` does nothing. Then a DLL runs in a process whose main image is the DLL, and shellcode runs in an empty process.

`init_machine` puts the machine at fixed high addresses, so that the input image can load at its preferred base. It creates the machine in an `allocations_from(MACHINE_BASE)` block. In this block, when an allocation gives no address, the memory manager searches for free memory from `MACHINE_BASE` (0x7D000000). `load_container` loads the container image in the same way, at the first free base above `MACHINE_BASE`. On x86, the container image must fit below the TEB, or `load_container` raises `OutOfMemoryError`. The emulator loads the user modules of the config at their configured bases. In user mode, the TEB of the first thread is at 0x7FFDE000 and the PEB of the main process is at 0x7FFDF000, as in 32-bit Windows. On x64, the emulator also puts the TEB below 4 GB, because the GS base comes from a 32-bit GDT descriptor. `KUSER_SHARED_DATA` is at 0x7FFE0000. The emulated system has the same architecture as the input, so the process is never a WOW64 process, and the WOW64 query APIs report this. In kernel mode, the TEB and the PEB do not have fixed addresses.

## Loader

`load_image` loads a PE file, such as an .exe or a .dll. If a dependency fails to load, it removes everything that it added. `ModuleLoader` (`speakeasy/windows/module_loader.py`, the `module_loader` attribute of the emulator) keeps the loader data that `load_image` restores after a failure: the import bindings, the DLLs whose DllMain and TLS callbacks must run, and the DLLs that each new process gets in its PEB.

For each image, `_load_image` maps it, binds its imports and adds it to the PEB. The caller marks the input image with `is_input`. The input image is the first module in `modules`, and the emulator allocates the stack only for the input image. If a machine module or the container image uses the preferred base of the input image, `_load_image` loads the input image at the next free base.

A loader (`PeLoader`, `ShellcodeLoader` or `ApiModuleLoader`) returns a `LoadedImage` with RVAs: the regions, the import slots, the exports, the entry points, the TLS callbacks and the TLS and resource directories. Its `image_base` is the preferred base. `PeLoader` also returns the base relocations of the PE, or None if the PE has no relocation data. Synthetic API modules and shellcode have no absolute addresses, so they can load at any base. `relocate_image(image, base)` returns a copy of the image rebased to `base`.

`_load_image` selects the base as the Windows loader does. It uses the base that the caller gives, for example the `base_addr` of a module in the config, else the preferred base. If that range is not free, it uses the next free range after it. An image with preferred base 0, such as shellcode, loads at any free address.

`ensure_pe_import_hooks` binds the imports of a PE that the guest maps itself, for example by process hollowing. `speakeasy/windows/mapped_imports.py` reads the import table from guest memory.

The emulator runs DllMain and TLS callbacks in two ways. For the DLLs that the input imports, `_queue_startup_initializers` adds a run for each callback before the first run in the queue. For `LoadLibrary`, `load_library` calls them as guest callbacks.

Usually there are few runs before the entry point. Only a DLL with a real PE image has a DllMain or TLS callbacks: a DLL from the module directory (`module_directory_x86` or `module_directory_x64`, not set by default), or a DLL that the guest loads with `LoadLibrary` from the emulated file system. The other DLLs, such as kernel32, are synthetic API modules without initializers. The loader never loads imports from the emulated file system. All processes share one set of modules.

Both ways use the same data. `Process.peb_modules` has the modules in the loader lists of a process. `RuntimeModule.load_states` has the state of the module in each process, with names from the Windows `LDR_DDAG_STATE` values: `INITIALIZING` while its DllMain and TLS callbacks run, then `READY_TO_RUN` or `INIT_ERROR`. `ModuleLoader.collect_initializers` returns an `InitRoutine` for each DllMain and TLS callback to run. `InitRoutine.args` has the arguments of the call for `DLL_PROCESS_ATTACH`.

After each callback, `ModuleLoader.finish_initializer` decides if it succeeded. A DllMain fails if it faults, or if the low byte of its result is zero. A TLS callback fails only if it faults. After the last callback of a module succeeds, its state is `READY_TO_RUN`.

The two ways handle a failed callback differently. At start, `_finish_run_initializers` sets the module state to `INIT_ERROR`, removes the other runs of the module from the queue and keeps the module mapped. The process continues. In `LoadLibrary`, `_fail_library_initializer` makes the call return NULL with error 1114 (`ERROR_DLL_INIT_FAILED`) and unloads the DLL. If a callback faults in `LoadLibrary`, the run ends. Before the next run, `_finish_run_initializers` undoes the loads that the run did not complete.

If the emulator cancels the runs in the queue, for example when emulation reaches the total time limit, `ModuleLoader.cancel_initializers` clears the `INITIALIZING` state of the callbacks that did not run.

## Hooks and faults

`WindowsEmulator` adds these Unicorn hooks:

- `_hook_mem_unmapped` for unmapped and protected memory. This hook also finds API calls and returns to the reserved range.
- Hooks for interrupts, invalid instructions, `in` and `out`.
- `_hook_code_tracing`, `_hook_mem_read` and `_hook_mem_write` when `analysis.memory_tracing` is set. They count reads, writes and executes for each symbol, section and memory map.
- `_hook_code_coverage` when `analysis.coverage` is set.
- `_hook_code_deferred_work`, which runs at the next instruction after an API call, a fault or a request to end the run, and then disables itself.

If a hook raises a Python exception, the hook catches it and calls `_end_run_on_hook_error`, which saves the error on the run and calls `stop()`.

A hook that detects a fault calls `raise_cpu_exception`, which records the exception as a native exit and stops Unicorn. Unmapped reads, writes and fetches use this path, and so do invalid instructions, interrupts and most protection faults. An access to the reserved range of the API tokens that is not an API call also uses it.

After Unicorn stops, `_handle_exit` calls `_dispatch_cpu_exception`, which sends the exception to the guest handlers with `dispatch_seh`. If no handler takes the exception, `guest_callbacks.fail` ends the run with the fault error. `guest_callbacks.fail` keeps the guest callback frames of the run. So if a DllMain faults in `LoadLibrary`, `_finish_run_initializers` can undo the load before the next run. See [Exception dispatch](exceptions.md).

`speakeasy/windows/thread_context.py` has the tables that `get_thread_context` and `load_thread_context` use to copy registers to and from a `CONTEXT`. Unicorn does not have debug registers, so the emulator keeps them on the thread.
