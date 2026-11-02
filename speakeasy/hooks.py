"""
Callback types of the ``add_*_hook`` methods.

Every callback gets the emulator as its first argument. The parameters are
positional-only, so that a type checker accepts a callback with other parameter names.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from speakeasy.memmgr import MemMap
    from speakeasy.windows.winemu import WindowsEmulator


class ApiHookCallback(Protocol):
    def __call__(
        self, emu: WindowsEmulator, api_name: str, func: Callable | None, argv: list[int], /
    ) -> int | None: ...


class CodeHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, address: int, size: int, /) -> None: ...


class MemAccessHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, access: int, address: int, size: int, value: int, /) -> bool | None: ...


class MemMapHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, base: int, size: int, tag: str, perms: int, flags: int, /) -> None: ...


class InterruptHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, number: int, /) -> bool | None: ...


class InHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, port: int, size: int, /) -> int: ...


class OutHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, port: int, size: int, value: int, /) -> None: ...


class SyscallHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, /) -> None: ...


class InvalidInstructionHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, /) -> bool: ...


class DynCodeHookCallback(Protocol):
    def __call__(self, emu: WindowsEmulator, region: MemMap, /) -> None: ...
