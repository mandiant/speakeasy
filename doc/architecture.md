# Architecture of the Windows emulator

This page tells you where the main parts of the Windows emulator are, and how a call to a Windows API gets to a Python handler.

## Classes

`BinaryEmulator` (`speakeasy/binemu.py`) wraps Unicorn and capstone. It has the memory manager and the hook lists. It does not know about Windows.

`WindowsEmulator` (`speakeasy/windows/winemu.py`) adds processes, threads, modules, runs, API calls and SEH. It also gives access to the object, file, registry and network managers.

`Win32Emulator` (`speakeasy/windows/win32.py`) runs user mode executables, DLLs and shellcode. `WinKernelEmulator` (`speakeasy/windows/kernel.py`) runs drivers. The `Speakeasy` class (`speakeasy/speakeasy.py`) is the public interface. It creates the emulator for the input.

API handlers are in `speakeasy/winenv/api/`, one class for each DLL. Each handler has an `@apihook` decorator with the export name, the number of arguments and the calling convention. See [Adding API handlers](api-handlers.md).

## Runs

A `Run` is one call into guest code: the entry point, a DLL export, a thread, a TLS callback or a DllMain. The emulator keeps a queue of runs. `start()` adds the DllMain and TLS callbacks of the imported DLLs to the front of the queue, and `_execute_runs` runs the queue in order. `_prepare_next_run` sets up the stack and registers for the next run.

`_execute_current_run` runs one run. Unicorn runs guest code until a hook stops it. A hook does not call API handlers while Unicorn is running. It saves what it found in `PendingState` and stops Unicorn. Then `_execute_current_run` reads `PendingState`, does the work, and starts Unicorn again. `PendingState` can hold:

- `api_entry`: the guest called an API.
- `control`: the run returned, a guest callback returned, or a fault ended the run.
- `cpu_exception`: a CPU exception for guest SEH.
- `trap_fault`: a read, write or fetch in the reserved range that is not an API call.

`RunLimits` has the time and instruction limits of a run.

## API calls

Each export of an emulated DLL has 32 bytes of code in the DLL image. The code jumps to a token in a reserved range that is never mapped. When the guest calls the API, Unicorn fails to fetch the token, and `_intercept_api_trap` finds the API for the token. The export table, the IAT and `GetProcAddress` give the address of the export code. The guest can read, patch and hook this code. See [Unified Windows API addresses](unified-api-addresses.md).

`dispatch_api_call(dll, name)` calls `resolve_api_implementation` to find the code to run. `speakeasy/windows/api_resolution.py` has one class for each result, in this order:

1. `HandlerImplementation`: the handler for the name, or for a related name. User hooks for the API run first, and they can call the handler.
2. `UserHookImplementation`: a user hook without a handler. The last hook that was added runs.
3. `SignatureImplementation`: a function from the signature database. It logs the arguments and returns a success value.
4. `StubImplementation`: with `functions_always_exist`, a stub that returns 1.
5. `UnsupportedImplementation`: the run ends with an `unsupported_api` error.

Each result has its own method: `_handle_api_with_handler`, `_handle_api_hook`, `_handle_api_from_signature`, `_handle_api_stub` and `_handle_unsupported_api`.

`get_handler_candidates(dll, name)` gives the related names, in order. For example, the name without the `A` or `W` suffix, the `Zw` name for an `Nt` name, or the DLL that implements an API set. `get_api_handler` uses the first related name that has a handler.

A handler can call guest code, for example a window procedure, with `setup_callback` or by yielding `GuestCall`. `speakeasy/windows/guest_callbacks.py` keeps track of these calls.

## Loader

`load_image` loads a PE file, such as an .exe or a .dll. If a dependency fails to load, it removes everything that it added. `ModuleLoader` (`speakeasy/windows/module_loader.py`, the `module_loader` attribute of the emulator) keeps the data that it must restore: the import bindings, the DLLs whose DllMain and TLS callbacks must run, and the DLLs that each new process gets in its PEB. Do not confuse it with `RuntimeModule.loader`, which reads the image file of one module.

The first call of `_load_image` also creates the Unicorn engine, and `setup()` loads the system modules. For each image, `_load_image` maps it, binds its imports and adds it to the PEB.

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

For an unmapped read, write or fetch, the hook calls `dispatch_seh` at once and maps a temporary page, so that Unicorn can complete the access. The deferred work hook unmaps the page. Other faults use `raise_cpu_exception`, and `_execute_current_run` sends them to the guest after Unicorn stops. See [Exception dispatch](exceptions.md).

`speakeasy/windows/thread_context.py` has the tables that `get_thread_context` and `load_thread_context` use to copy registers to and from a `CONTEXT`. Unicorn does not have debug registers, so the emulator keeps them on the thread.
