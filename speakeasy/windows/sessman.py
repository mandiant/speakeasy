# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from speakeasy.windows.handles import HandleTable, InvalidHandle
from speakeasy.winenv.defs.windows.windows import ERROR_INVALID_WINDOW_HANDLE

if TYPE_CHECKING:
    from speakeasy.windows.objman import HandleAllocator


class GuiObject:
    """Base class for all GUI objects."""

    def __init__(self, handles: HandleTable):
        self.handles: HandleTable = handles
        self.handle: int = handles.new_handle(self)

    def get_handle(self):
        return self.handle


class Session(GuiObject):
    """Represents a windows Session."""

    def __init__(self, handles: HandleTable, sess_id):
        super().__init__(handles)
        self.id: int = sess_id
        self.stations: dict[int, Station] = {}

    def new_station(self, name="WinSta0"):
        stat = Station(self.handles, name=name)
        self.stations.update({stat.get_handle(): stat})
        return stat


class Station(GuiObject):
    """Represents a window station."""

    def __init__(self, handles: HandleTable, name=""):
        super().__init__(handles)
        self.name: str = name
        self.desktops: dict[int, Desktop] = {}

    def new_desktop(self, name=""):
        desk = Desktop(self.handles, name=name)
        self.desktops.update({desk.get_handle(): desk})
        return desk


class Desktop(GuiObject):
    """Represents a Desktop object."""

    def __init__(self, handles: HandleTable, name=""):
        super().__init__(handles)
        self.windows: dict[int, Window] = {}
        self.desktop_window: Window = self.new_window()
        self.name: str = name

    def new_window(self):
        window = Window(self.handles)
        self.windows.update({window.get_handle(): window})
        return window


@dataclass
class ListViewColumn:
    fmt: int
    cx: int
    text: str
    sub_item: int


class Window(GuiObject):
    """Represents a GUI window."""

    invalid_handle_error = ERROR_INVALID_WINDOW_HANDLE

    def __init__(self, handles: HandleTable, name=None, class_name=None, style=0, parent=0, thread_id=0, process_id=0):
        super().__init__(handles)
        self.name: str | None = name
        self.class_name: str | None = class_name
        self.style: int = style
        self.parent: int = parent
        self.thread_id: int = thread_id
        self.process_id: int = process_id
        self.props: dict[int | str, int] = {}
        self.lv_columns: list[ListViewColumn] = []


class WindowClass(GuiObject):
    """Represents a GUI window class."""

    def __init__(self, handles: HandleTable, wclass, name):
        super().__init__(handles)
        self.wclass: Any = wclass
        self.name: str = name


class SessionManager:
    """
    The session manager for the emulator.

    It manages things like desktops, windows, and session isolation. USER objects, such as
    windows, desktops and window classes, belong to the session on Windows, not to a process,
    so their handles are in a table of the manager.
    """

    def __init__(self, config, allocator: HandleAllocator):
        super().__init__()
        self.handles: HandleTable = HandleTable(allocator, release=lambda obj: None)
        self.sessions: dict[int, Session] = {}
        self.window_classes: dict[int | str, WindowClass] = {}
        self.windows: dict[int | str, Window] = {}
        self.curr_session: Session | None = None
        self.curr_station: Station | None = None
        self.curr_desktop: Desktop | None = None
        self.config: Any = config
        self.dev_ctx: int = allocator.allocate_handle()

        # create a session 0
        self.curr_session = Session(self.handles, sess_id=0)

        # create WinSta0
        self.curr_station = self.curr_session.new_station(name="WinSta0")

        # Create a desktop
        self.curr_station.new_desktop("Winlogon")
        default = self.curr_station.new_desktop("Default")
        self.curr_station.new_desktop("Disconnect")

        # For now lets default to the Default desktop
        self.curr_desktop = default

    def create_window_class(self, class_obj, class_name=None):
        wc = WindowClass(self.handles, class_obj, class_name)
        atom = wc.get_handle()
        self.window_classes.update({atom: wc})
        if class_name:
            self.window_classes.update({class_name: wc})
        return atom

    def create_window(self, window_name=None, class_name=None, style=0, parent=0, thread_id=0, process_id=0):
        wc = Window(self.handles, window_name, class_name, style, parent, thread_id, process_id)
        hnd = wc.get_handle()
        self.windows.update({hnd: wc})
        if window_name:
            self.windows.update({window_name: wc})
        return hnd

    def get_window_class(self, atom):
        return self.window_classes.get(atom)

    def get_window(self, handle):
        return self.windows.get(handle)

    def get_handle_object(self, handle, *types):
        """Get the object of an open USER object handle if it is one of ``types``, else None."""
        try:
            return self.handles.get(handle, *types)
        except InvalidHandle:
            return None

    def get_device_context(self):
        return self.dev_ctx

    def get_current_desktop(self):
        return self.curr_desktop

    def get_current_station(self):
        return self.curr_station
