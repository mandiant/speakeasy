"""The handle table of a process: the objects that its handle values refer to."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar, overload

from speakeasy.winenv.defs.windows.windows import ERROR_INVALID_HANDLE

if TYPE_CHECKING:
    from speakeasy.windows.objman import HandleAllocator

T = TypeVar("T")

# A 64-bit guest can pass a handle sign-extended, so a table looks up only the low 32 bits.
HANDLE_MASK = 0xFFFFFFFF

# (HANDLE)-1 and (HANDLE)-2, as GetCurrentProcess and GetCurrentThread return them
CURRENT_PROCESS_HANDLE = 0xFFFFFFFF
CURRENT_THREAD_HANDLE = 0xFFFFFFFE


class InvalidHandle(Exception):
    """
    A handler got a handle value that is not open, or that refers to an object of another type.

    API dispatch catches it and fails the call with the Win32 error code in ``error``.
    """

    def __init__(self, handle: int, error: int = ERROR_INVALID_HANDLE):
        super().__init__(f"invalid handle 0x{handle:x}")
        self.handle: int = handle
        self.error: int = error


class HandleTable:
    """
    Map the handle values of a process to their objects.

    Each handle holds a reference: ``new_handle`` adds 1 to ``ref_cnt`` of the object, and ``close``
    calls ``release`` with the object. ``pseudo`` gives the object of a pseudo handle, such as the
    current process for -1, or None for a usual handle value.
    """

    def __init__(
        self,
        allocator: HandleAllocator,
        release: Callable[[Any], object],
        pseudo: Callable[[int], Any] | None = None,
    ):
        self._allocator: HandleAllocator = allocator
        self._release: Callable[[Any], object] = release
        self._pseudo: Callable[[int], Any] | None = pseudo
        self._objects: dict[int, Any] = {}

    def new_handle(self, obj: Any) -> int:
        handle = self._allocator.allocate_handle()
        self._objects[handle] = obj
        if hasattr(obj, "ref_cnt"):
            obj.ref_cnt += 1
        return handle

    @overload
    def get(self, handle: int) -> Any: ...

    @overload
    def get(self, handle: int, *types: type[T]) -> T: ...

    def get(self, handle: int, *types: type) -> Any:
        """
        Get the object of an open handle or a pseudo handle.

        Raises:
            InvalidHandle: if the handle is not open, or its object is not an instance of one of ``types``.
                The error comes from the ``invalid_handle_error`` attribute of the first type, if it has one.
        """
        obj = self._pseudo(handle) if self._pseudo else None
        if obj is None:
            obj = self._objects.get(handle & HANDLE_MASK)
        if obj is None or (types and not isinstance(obj, types)):
            error = getattr(types[0], "invalid_handle_error", ERROR_INVALID_HANDLE) if types else ERROR_INVALID_HANDLE
            raise InvalidHandle(handle, error)
        return obj

    def close(self, handle: int) -> None:
        """
        Close a handle and release its reference. Closing a pseudo handle does nothing.

        Raises:
            InvalidHandle: if the handle is not open.
        """
        if self._pseudo and self._pseudo(handle) is not None:
            return
        obj = self._objects.pop(handle & HANDLE_MASK, None)
        if obj is None:
            raise InvalidHandle(handle)
        self._allocator.free_handle(handle & HANDLE_MASK)
        self._release(obj)

    def __contains__(self, handle: int) -> bool:
        return (handle & HANDLE_MASK) in self._objects
