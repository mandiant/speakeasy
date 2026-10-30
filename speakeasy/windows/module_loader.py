"""Load images and their dependencies, and track the DLLs whose initializers still have to run."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from speakeasy.windows.loaders import InitRoutine, LoadState, RuntimeModule

if TYPE_CHECKING:
    from speakeasy.profiler import GuestCallbackFrame

logger = logging.getLogger(__name__)

PebModuleSnapshot = list[tuple[Any, dict[int, RuntimeModule]]]


class ModuleLoader:
    """
    Load images and their dependencies, and keep the data of the loader: the IAT
    entries that the loader bound, the DLLs that each process has in its PEB by
    default, and the DLLs whose DllMain and TLS callbacks must run. Record the
    result of each callback.

    WindowsEmulator._load_image maps one image, and the emulator keeps the module
    list. If a load fails, or a DllMain returns FALSE, this class removes what the
    load added.
    """

    def __init__(self, emu: Any) -> None:
        self.emu = emu
        self.guest_dependencies: list[RuntimeModule] = []
        self.shared_peb_modules: set[int] = set()
        self.import_bindings: dict[int, int] = {}
        self._load_depth = 0

    def _get_processes(self) -> list[Any]:
        # Do not call emu.get_processes(), because it can create the configured processes
        emu = self.emu
        processes = list(emu.processes)
        if emu.curr_process is not None and emu.curr_process not in processes:
            processes.append(emu.curr_process)
        return processes

    def _remove_from_active_pebs(self, module: RuntimeModule) -> None:
        for process in self._get_processes():
            if process.is_peb_active and self.emu.get_address_map(process.peb_ldr_data.address):
                process.remove_module_from_peb(module)

    def load_image(self, image: Any) -> RuntimeModule:
        """Load an image and its dependencies. If the load fails, remove what it added."""
        emu = self.emu
        outer = not self._load_depth
        if outer:
            original_modules = list(emu.modules)
            original_maps = {id(mapping) for mapping in emu.maps}
            original_bindings = dict(self.import_bindings)
            original_shared = set(self.shared_peb_modules)
            original_peb_modules = self.snapshot_peb_modules()
        self._load_depth += 1
        try:
            module: RuntimeModule = emu._load_image(image)
        except Exception:
            if outer:
                removed = [module for module in emu.modules if module not in original_modules]
                for module in reversed(removed):
                    self._remove_from_active_pebs(module)
                    emu.api_registry.unregister_module(module)
                self.rollback_peb_modules(original_peb_modules)
                emu.modules[:] = original_modules
                self.import_bindings = original_bindings
                self.shared_peb_modules = original_shared
                self.guest_dependencies[:] = [
                    module for module in self.guest_dependencies if module in original_modules
                ]
                for mapping in tuple(emu.maps):
                    if id(mapping) not in original_maps and (mapping.tag or "").startswith("emu.module."):
                        emu.mem_unmap(mapping.base, mapping.size)
                        emu.maps.remove(mapping)
            raise
        finally:
            self._load_depth -= 1
        if outer:
            self.notify_module_change()
        return module

    def notify_module_change(self) -> None:
        """Call the module change listeners. A listener that fails does not stop the others."""
        for listener in tuple(self.emu.module_change_listeners):
            try:
                listener()
            except Exception:
                logger.exception("module change listener failed: %r", listener)

    def discard_module(self, module: RuntimeModule) -> None:
        emu = self.emu
        self._remove_from_active_pebs(module)
        emu.api_registry.unregister_module(module)
        self.shared_peb_modules.discard(module.base)
        if module in emu.modules:
            emu.modules.remove(module)
        if module in self.guest_dependencies:
            self.guest_dependencies.remove(module)
        mapping = emu.get_address_map(module.base)
        if mapping is not None:
            emu.mem_unmap(mapping.base, mapping.size)
            emu.maps.remove(mapping)
        self.import_bindings = {
            address: target
            for address, target in self.import_bindings.items()
            if not module.base <= address < module.base + module.image_size
        }
        self.notify_module_change()

    def snapshot_peb_modules(self) -> PebModuleSnapshot:
        return [(process, dict(process.peb_modules)) for process in self._get_processes()]

    def rollback_peb_modules(self, snapshot: PebModuleSnapshot) -> None:
        for process, original in snapshot:
            for base, module in tuple(process.peb_modules.items()):
                if base not in original:
                    process.remove_module_from_peb(module)

    def remove_failed_module_from_peb(self, module: RuntimeModule, pid: int) -> None:
        """Remove the module from one process after its initialization failed. Other processes keep it."""
        module.load_states.pop(pid, None)
        for process in self._get_processes():
            if process.id == pid:
                process.remove_module_from_peb(module)

    def rollback_guest_load(self, frame: GuestCallbackFrame) -> None:
        # Remove the modules that the load added to processes. Unmap a new image
        # only if no process has it. Do not unmap older images.
        self.rollback_peb_modules(frame.peb_module_snapshot)
        original = {process.id: modules for process, modules in frame.peb_module_snapshot}
        for routine in frame.initializers.values():
            module, pid = routine.module, routine.pid
            if module.load_states.get(pid) is LoadState.INITIALIZING or module.base not in original.get(pid, {}):
                module.load_states.pop(pid, None)
        for module in reversed(frame.created_modules):
            if not any(module.base in process.peb_modules for process in self._get_processes()):
                self.discard_module(module)
        frame.pending[:] = [(function, args) for function, args in frame.pending if function not in frame.initializers]
        frame.initializers.clear()
        frame.created_modules.clear()
        frame.peb_module_snapshot = []

    def finish_initializer(self, routine: InitRoutine, return_value: int, faulted: bool = False) -> bool:
        """
        Record the end of an initializer, and return True if it succeeded.

        A DllMain fails if it faults, or if the low byte of its result is zero.
        The Windows loader reads the BOOL result as a BOOLEAN. A TLS callback fails
        only if it faults. When the last initializer of a module succeeds, set the
        state of the module to READY_TO_RUN.
        """
        if faulted or (routine.is_entry_point and not return_value & 0xFF):
            return False
        if routine.is_last:
            routine.module.load_states[routine.pid] = LoadState.READY_TO_RUN
        return True

    def cancel_initializers(self, routines: Iterable[InitRoutine]) -> None:
        """
        Clear the INITIALIZING state of initializers that will not run.
        A later load of the module runs them again.
        """
        for routine in routines:
            if routine.module.load_states.get(routine.pid) is LoadState.INITIALIZING:
                routine.module.load_states.pop(routine.pid)

    def collect_initializers(self) -> list[InitRoutine]:
        """
        Get the DllMain and TLS callbacks of the DLLs that the current process has
        not initialized. Set the state of these DLLs to INITIALIZING.
        """
        process = self.emu.get_current_process()
        if process is None:
            return []
        result = []
        for module in self.guest_dependencies:
            if (
                module not in self.emu.modules
                or module.base not in process.peb_modules
                or process.id in module.load_states
            ):
                continue
            module.load_states[process.id] = LoadState.INITIALIZING
            functions = [(function, False) for function in module.get_tls_callbacks()]
            if module.ep:
                functions.append((module.base + module.ep, True))
            if not functions:
                module.load_states[process.id] = LoadState.READY_TO_RUN
            for index, (function, is_entry_point) in enumerate(functions):
                result.append(InitRoutine(module, function, is_entry_point, index == len(functions) - 1, process.id))
        return result
