# Architecture of the Windows emulator

This page tells you where the main parts of the Windows emulator are, and how a call to a Windows API gets to a Python handler.

## Classes

`BinaryEmulator` (`speakeasy/binemu.py`) wraps Unicorn and capstone. It has the memory manager and the hook lists. It does not know about Windows.

`WindowsEmulator` (`speakeasy/windows/winemu.py`) adds processes, threads, modules, runs, API calls and SEH. It also gives access to the object, file, registry and network managers.

`Win32Emulator` (`speakeasy/windows/win32.py`) runs user mode executables, DLLs and shellcode. `WinKernelEmulator` (`speakeasy/windows/kernel.py`) runs drivers. The `Speakeasy` class (`speakeasy/speakeasy.py`) is the public interface. It creates the emulator for the input.

API handlers are in `speakeasy/winenv/api/`, one class for each DLL. Each handler has an `@apihook` decorator with the export name, the number of arguments and the calling convention. See [Adding API handlers](api-handlers.md).

## Runs

A `Run` is one call into guest code: the entry point, a DLL export, a thread, a TLS callback or a DllMain. The emulator keeps a queue of runs. `start()` adds the DllMain and TLS callbacks of the imported DLLs to the front of the queue, and `_execute_runs` runs the queue in order. `_prepare_next_run` sets up the stack and registers for the next run.

`_execute_current_run` runs one run. Unicorn runs guest code until a hook stops it. A hook does not call API handlers while Unicorn is running. It records a native exit with `_record_exit` and stops Unicorn. If Unicorn stops and no hook recorded an exit, `_get_exit_at_pc` gets the exit from the address where Unicorn stopped. Then `_handle_exit` does the work for the exit, and the loop starts Unicorn again. A native exit tells why Unicorn stopped. It is one of these types:

- `SuspendedApiCall`: the guest called an API. The handler of the API runs next.
- `RunReturn`: the guest returned from the run. The run is complete.
- `CallbackReturn`: a guest callback returned. The API handler that called it continues.
- `FaultReturn`: a fault ended the run.
- `ExecRecovery`: the guest ran code in a guest PE page without execute permission. The loop adds the permission.
- `RaisedCpuException`: a CPU exception or a memory fault for guest SEH.

The emulator keeps one native exit. If a second hook records an exit before Unicorn stops, the first exit stays.

`RunLimits` has the time and instruction limits of a run. The loop checks all limits before each start of Unicorn and before each API handler. Before `RunReturn`, `CallbackReturn`, `FaultReturn` and `ExecRecovery`, it checks only the total time.

## API calls

Each export of an emulated DLL has 32 bytes of code in the DLL image. The code jumps to a token in a reserved range that is never mapped. When the guest calls the API, Unicorn fails to fetch the token, and `_intercept_api_trap` finds the API for the token. The export table, the IAT and `GetProcAddress` give the address of the export code. The guest can read, patch and hook this code. See [Unified Windows API addresses](unified-api-addresses.md).

`dispatch_api_call(dll, name)` calls `resolve_api_implementation` to find the code to run. `speakeasy/windows/api_resolution.py` has one class for each result, in this order:

1. `HandlerImplementation`: the handler for the name, or for a related name. User hooks for the API run first, and they can call the handler.
2. `UserHookImplementation`: a user hook without a handler. The last hook that was added runs.
3. `SignatureImplementation`: a function from the signature database. It logs the arguments and returns a success value.
4. `StubImplementation`: with `functions_always_exist`, a stub that returns 1.
5. `UnsupportedImplementation`: the run ends with an `unsupported_api` error.

Each result has its own method: `_handle_api_with_handler`, `_handle_api_hook`, `_handle_api_from_signature`, `_handle_api_stub` and `_handle_unsupported_api`.

`get_handler_candidates(dll, name)` gives the related names, in order. For example, the name without the `A` or `W` suffix, the `Zw` name for an `Nt` name, or the modules that implement an API set (`get_dll_hosts`). `get_api_handler` uses the first related name that has a handler. `get_proc` gets the module for an import from `get_import_host`. For an API set with functions in more than one module, this is the first module that has a handler for the name.

A handler can call guest code, for example a window procedure, with `setup_callback` or by yielding `GuestCall`. `speakeasy/windows/guest_callbacks.py` keeps track of these calls.

## Machine setup

`init_machine(arch)` creates the machine before an image loads. The `Speakeasy` class calls it with the architecture of the input. It creates the Unicorn engine, the disassembler and the API layer. Then `init_machine_structures` creates the object manager, the GDT and the segments, `KUSER_SHARED_DATA`, the system modules and the user modules of the config.

In user mode, when the input is a DLL or shellcode, the `Speakeasy` class then calls `load_container`, before the input loads. This step loads the container image and makes its process the current process. The container image is a placeholder module for the EXE that loaded the DLL or that runs the shellcode. It is the main image of the process in which the input runs. It comes from the entry in `processes` of the config that has `is_main_exe` set. By default, its name is `main` and its path is `C:\Windows\system32\svchost.exe`. It is a synthetic module, unless the module directory has a file with its name, such as `main.exe`. The `ImageBaseAddress` of the PEB and `GetModuleHandle(NULL)` give its base. When the input is an EXE, there is no container image, and the input is the main image of the process. When the config has no `is_main_exe` entry, `load_container` does nothing. Then a DLL runs in a process whose main image is the DLL, and shellcode runs in an empty process.

The machine uses fixed addresses, so that the input image can use its preferred base. `init_machine` creates the machine in an `allocations_from(MACHINE_BASE)` block. In this block, each allocation that does not give an address starts its search for free memory at `MACHINE_BASE` (0x7D000000). `load_container` loads the container image in the same way, at the first free base above `MACHINE_BASE`. On x86, the container image must fit below the TEB, or `load_container` raises `OutOfMemoryError`. The user modules of the config load at their configured bases. In user mode, the TEB of the first thread is at 0x7FFDE000 and the first PEB is at 0x7FFDF000, as in 32-bit Windows. On x64, the TEB also stays below 4 GB, because the GS base comes from a 32-bit GDT descriptor. `KUSER_SHARED_DATA` is at 0x7FFE0000. In kernel mode, the TEB and the PEB do not have fixed addresses.

## Loader

`load_image` loads a PE file, such as an .exe or a .dll. If a dependency fails to load, it removes everything that it added. `ModuleLoader` (`speakeasy/windows/module_loader.py`, the `module_loader` attribute of the emulator) keeps the data that it must restore: the import bindings, the DLLs whose DllMain and TLS callbacks must run, and the DLLs that each new process gets in its PEB. Do not confuse it with `RuntimeModule.loader`, which reads the image file of one module.

For each image, `_load_image` maps it, binds its imports and adds it to the PEB. The caller marks the input image with `is_input`. The input image is the first module in `modules`, and only the input image allocates the stack. If a machine module or the container image uses the preferred base of the input image, the input image loads at the next free base.

A loader (`PeLoader`, `ShellcodeLoader` or `ApiModuleLoader`) returns a `LoadedImage` with RVAs: the regions, the import slots, the exports, the entry points, the TLS callbacks and the TLS and resource directories. Its `image_base` is the preferred base. `PeLoader` also returns the base relocations of the PE, or None if the PE has no relocation data. Synthetic API modules and shellcode have no absolute addresses, so they can load at any base. `relocate_image(image, base)` returns a copy of the image at a base. It applies the relocations, writes the base in the ImageBase field of the header and adds the base to each RVA. It applies the HIGHLOW and DIR64 relocation types, skips ABSOLUTE and raises `ValueError` for the other types. It also raises `ValueError` if the base is not the preferred base and the image has no relocation data.

`_load_image` selects the base as the Windows loader does. It uses the base that the caller gives, for example the `base_addr` of a module in the config, else the preferred base. If that range is not free, it uses the next free range after it. An image with preferred base 0, such as shellcode, loads at any free address.

`ensure_pe_import_hooks` binds the imports of a PE that the guest maps itself, for example by process hollowing. `speakeasy/windows/mapped_imports.py` reads the import table from guest memory.

DllMain and TLS callbacks run in two ways. For the DLLs that the input imports, `_queue_startup_initializers` adds a run for each callback before the first run in the queue. For `LoadLibrary`, `load_library` calls them as guest callbacks.

Usually there are few runs before the entry point. Only a DLL with a real PE image has a DllMain or TLS callbacks: a DLL from the module directory (`module_directory_x86` or `module_directory_x64`, not set by default), or a DLL that the guest loads with `LoadLibrary` from the emulated file system. The other DLLs, such as kernel32, are synthetic API modules without initializers. Imports never load from the emulated file system, so a DLL that the guest drops and a child process imports is also a synthetic module. All processes share one set of modules, and a child process gets in its PEB all the DLLs that are mapped. If the parent loaded a dropped DLL with `LoadLibrary`, its initializers run again before the entry point of the child.

Both ways use the same data. `Process.peb_modules` has the modules in the loader lists of a process. `RuntimeModule.load_states` has the state of the module in each process, with names from the Windows `LDR_DDAG_STATE` values: `INITIALIZING` while its DllMain and TLS callbacks run, then `READY_TO_RUN` or `INIT_ERROR`. `ModuleLoader.collect_initializers` returns an `InitRoutine` for each DllMain and TLS callback to run. `InitRoutine.args` has the arguments of the call for `DLL_PROCESS_ATTACH`.

After each callback, `ModuleLoader.finish_initializer` decides if it succeeded. A DllMain fails if it faults, or if the low byte of its result is zero. A TLS callback fails only if it faults. After the last callback of a module succeeds, its state is `READY_TO_RUN`.

The two ways do different things when a callback fails. At start, `_finish_run_initializers` sets the module state to `INIT_ERROR` and removes the other runs of the module from the queue. The module stays mapped, and the process continues. In `LoadLibrary`, `_fail_library_initializer` makes the call return NULL with error 1114 (`ERROR_DLL_INIT_FAILED`) and unloads the DLL. If a callback faults in `LoadLibrary`, the run ends. Before the next run, `_finish_run_initializers` undoes the loads that the run did not complete.

If the emulator cancels the runs in the queue, for example when the total time limit is reached, `ModuleLoader.cancel_initializers` clears the `INITIALIZING` state of the callbacks that did not run.

## Hooks and faults

`WindowsEmulator` adds these Unicorn hooks:

- `_hook_mem_unmapped` for unmapped and protected memory. This hook also finds API calls and returns to the reserved range.
- Hooks for interrupts, invalid instructions, `in` and `out`.
- `_hook_code_tracing`, `_hook_mem_read` and `_hook_mem_write` when `analysis.memory_tracing` is set. They count reads, writes and executes for each symbol, section and memory map.
- `_hook_code_coverage` when `analysis.coverage` is set.
- `_hook_code_deferred_work`, which runs at the next instruction after an API call, a fault or a request to end the run, and then disables itself.

If a hook gets an exception, it calls `_end_run_on_hook_error`. This saves the error on the run and stops emulation.

A hook does not send a fault to the guest while Unicorn runs. It calls `raise_cpu_exception`, which records the exception as a native exit and stops Unicorn. Unmapped reads, writes and fetches use this path, and so do invalid instructions, interrupts and most protection faults. An access to the reserved range of the API tokens that is not an API call also uses it. The emulator does not map a page at the fault address.

After Unicorn stops, `_handle_exit` calls `_dispatch_cpu_exception`, which sends the exception to the guest handlers with `dispatch_seh`. If no handler takes the exception, `guest_callbacks.fail` ends the run with the fault error. This function keeps the guest callback frames of the run. Thus, if a DllMain faults in `LoadLibrary`, `_finish_run_initializers` can undo the load before the next run. See [Exception dispatch](exceptions.md).

`speakeasy/windows/thread_context.py` has the tables that `get_thread_context` and `load_thread_context` use to copy registers to and from a `CONTEXT`. Unicorn does not have debug registers, so the emulator keeps them on the thread.
