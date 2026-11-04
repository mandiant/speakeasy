# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from speakeasy.windows.handles import HandleTable

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
    """Represents a Windows session."""

    def __init__(self, handles: HandleTable, windows: dict[int | str, Window], sess_id):
        super().__init__(handles)
        self.windows: dict[int | str, Window] = windows
        self.id: int = sess_id
        self.stations: dict[int, Station] = {}

    def new_station(self, name="WinSta0"):
        stat = Station(self.handles, self.windows, name=name)
        self.stations.update({stat.get_handle(): stat})
        return stat


class Station(GuiObject):
    """Represents a window station."""

    def __init__(self, handles: HandleTable, windows: dict[int | str, Window], name=""):
        super().__init__(handles)
        self.windows: dict[int | str, Window] = windows
        self.name: str = name
        self.desktops: dict[int, Desktop] = {}

    def new_desktop(self, name=""):
        desk = Desktop(self.handles, self.windows, name=name)
        self.desktops.update({desk.get_handle(): desk})
        return desk


class Desktop(GuiObject):
    """
    Represents a desktop.

    The windows of all desktops are in the one window store of the session manager. The desktop
    window is not in the store, because EnumWindows does not give it.
    """

    def __init__(self, handles: HandleTable, windows: dict[int | str, Window], name=""):
        super().__init__(handles)
        self.windows: dict[int | str, Window] = windows
        self.desktop_window: Window = Window(handles)
        self.name: str = name

    def new_window(self, window_name=None, class_name=None, style=0, parent=0, thread_id=0, process_id=0) -> Window:
        window = Window(self.handles, window_name, class_name, style, parent, thread_id, process_id)
        self.windows.update({window.get_handle(): window})
        if window_name:
            self.windows.update({window_name: window})
        return window


@dataclass
class ListViewColumn:
    fmt: int
    cx: int
    text: str
    sub_item: int


class Window(GuiObject):
    """Represents a GUI window."""

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
    Keep the sessions, window stations, desktops, windows and window classes of the emulator.

    USER objects, such as windows, desktops and window classes, belong to the session on Windows, not
    to a process, so their handles are in a table of the manager.
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

        self.curr_session = Session(self.handles, self.windows, sess_id=0)
        self.curr_station = self.curr_session.new_station(name="WinSta0")
        self.curr_station.new_desktop("Winlogon")
        default = self.curr_station.new_desktop("Default")
        self.curr_station.new_desktop("Disconnect")
        self.curr_desktop = default

    def create_window_class(self, class_obj, class_name=None):
        wc = WindowClass(self.handles, class_obj, class_name)
        atom = wc.get_handle()
        self.window_classes.update({atom: wc})
        if class_name:
            self.window_classes.update({class_name: wc})
        return atom

    def create_window(self, window_name=None, class_name=None, style=0, parent=0, thread_id=0, process_id=0):
        desk = self.get_current_desktop()
        return desk.new_window(window_name, class_name, style, parent, thread_id, process_id).get_handle()

    def get_window_class(self, atom):
        return self.window_classes.get(atom)

    def get_window(self, handle) -> Window | None:
        """Get the window of a window handle, else None."""
        return self.handles.get(handle, Window)

    def get_device_context(self):
        return self.dev_ctx

    def get_current_desktop(self):
        return self.curr_desktop

    def get_current_station(self):
        return self.curr_station
