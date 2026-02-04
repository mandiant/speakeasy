# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.kernel32 as k32defs


class DriveManager:
    """
    Manages the emulation of Windows drives. Currently assumes one volume per drive.
    """

    def __init__(self, config: list | None = None):
        super().__init__()
        self.drives: list = config or []
        self.drive_letters: list[str] = []

        for drive in self.drives:
            if drive.root_path:
                self.drive_letters.append(drive.root_path[0])

    def walk_drives(self):
        yield from self.drives

    def get_drive(self, root_path="", volume_guid_path=""):
        for drive in self.drives:
            if root_path:
                if drive.root_path and root_path == drive.root_path:
                    return drive
            elif volume_guid_path:
                if drive.volume_guid_path and drive.volume_guid_path == volume_guid_path:
                    return drive

    def get_drive_type(self, root_path):
        drive = self.get_drive(root_path=root_path)
        if drive:
            if drive.root_path == root_path:
                return k32defs.get_define_value(drive.drive_type)

        return k32defs.DRIVE_NO_ROOT_DIR
