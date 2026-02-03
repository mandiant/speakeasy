# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

class KernelModule:

    def __init__(self):
        self.name = ''

    def get_mod_name(self):
        return self.name.lower()

    def ioctl(self, arch, code, inbuf):
        raise NotImplementedError
