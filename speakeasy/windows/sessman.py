# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

class GuiObject(object):
    """
    Base class for all GUI objects
    """
    curr_handle = 0x120

    def __init__(self):
        self.handle = self.get_handle()

    def get_handle(self):
        tmp = GuiObject.curr_handle
        GuiObject.curr_handle += 4
        return tmp


class Session(GuiObject):
    """
    Represents a windows Session
    """
    def __init__(self, sess_id):
        super(Session, self).__init__()
        self.id = sess_id
        self.stations = {}

    def new_station(self, name='WinSta0'):
        stat = Station(name=name)
        self.stations.update({stat.get_handle(): stat})
        return stat


class Station(GuiObject):
    """
    Represents a window station
    """
    def __init__(self, name=''):
        super(Station, self).__init__()
        self.name = name
        self.desktops = {}

    def new_desktop(self, name=''):
        desk = Desktop(name=name)
        self.desktops.update({desk.get_handle(): desk})
        return desk

    def get_name(self):
        return self.name


class Desktop(GuiObject):
    """
    Represents a Desktop object
    """
    def __init__(self, name=''):
        super(Desktop, self).__init__()
        self.windows = {}
        self.desktop_window = self.new_window()
        self.name = name

    def new_window(self):
        # create the desktop window
        window = Window()
        self.windows.update({window.get_handle(): window})
        return window

    def get_desktop_window(self):
        return self.desktop_window

    def get_name(self):
        return self.name


class Window(GuiObject):
    """
    Represents a GUI window
    """
    def __init__(self):
        super(Window, self).__init__()


class SessionManager(object):
    """
    The session manager for the emulator. This will manage things like desktops,
    windows, and session isolation
    """
    def __init__(self, config):
        super(SessionManager, self).__init__()
        self.sessions = {}
        self.curr_session = None
        self.curr_station = None
        self.curr_desktop = None
        self.config = config
        self.dev_ctx = GuiObject.curr_handle

        # create a session 0
        self.curr_session = Session(sess_id=0)

        # create WinSta0
        self.curr_station = self.curr_session.new_station(name='WinSta0')

        # Create a desktop
        self.curr_station.new_desktop('Winlogon')
        default = self.curr_station.new_desktop('Default')
        self.curr_station.new_desktop('Disconnect')

        # For now lets default to the Default desktop
        self.curr_desktop = default

    def get_device_context(self):
        return self.dev_ctx

    def get_current_desktop(self):
        return self.curr_desktop

    def get_current_station(self):
        return self.curr_station

    def get_gui_object(self, handle):
        for hsess, sess in self.sessions.items():
            if hsess == handle:
                return sess
            for hstat, stat in sess.stations.items():
                if hstat == handle:
                    return stat
                for hdesk, desk in stat.desktops.items():
                    if hdesk == handle:
                        return desk
