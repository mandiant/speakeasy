"""The handle table of a process: the objects that its handle values refer to."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar, overload

if TYPE_CHECKING:
    from speakeasy.windows.objman import HandleAllocator

T = TypeVar("T")

# A 64-bit guest can pass a handle sign-extended, so a table looks up only the low 32 bits.
HANDLE_MASK = 0xFFFFFFFF

# (HANDLE)-1 and (HANDLE)-2, as GetCurrentProcess and GetCurrentThread return them
CURRENT_PROCESS_HANDLE = 0xFFFFFFFF
CURRENT_THREAD_HANDLE = 0xFFFFFFFE


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
    def get(self, handle: int) -> Any | None: ...

    @overload
    def get(self, handle: int, *types: type[T]) -> T | None: ...

    def get(self, handle: int, *types: type) -> Any | None:
        """
        Get the object of an open handle or a pseudo handle.

        Return None if the handle is not open, or its object is not an instance of one of ``types``.
        """
        obj = self._pseudo(handle) if self._pseudo else None
        if obj is None:
            obj = self._objects.get(handle & HANDLE_MASK)
        if obj is None or (types and not isinstance(obj, types)):
            return None
        return obj

    def close(self, handle: int) -> bool:
        """
        Close a handle and release its reference. Closing a pseudo handle does nothing.

        Return False if the handle is not open.
        """
        if self._pseudo and self._pseudo(handle) is not None:
            return True
        obj = self._objects.pop(handle & HANDLE_MASK, None)
        if obj is None:
            return False
        self._allocator.free_handle(handle & HANDLE_MASK)
        self._release(obj)
        return True

    def __contains__(self, handle: int) -> bool:
        return (handle & HANDLE_MASK) in self._objects
