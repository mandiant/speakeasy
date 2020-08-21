# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

WH_CALLWNDPROC = 4
WH_CALLWNDPROCRET = 12
WH_CBT = 5
WH_DEBUG = 9
WH_FOREGROUNDIDLE = 11
WH_GETMESSAGE = 3
WH_JOURNALPLAYBACK = 1
WH_JOURNALRECORD = 0
WH_KEYBOARD = 2
WH_KEYBOARD_LL = 13
WH_MOUSE = 7
WH_MOUSE_LL = 14
WH_MSGFILTER = -1
WH_SHELL = 10
WH_SYSMSGFILTER = 6


def get_flag_defines(flags, prefix=''):
    defs = []
    for k, v in globals().items():
        if not isinstance(v, int):
            continue
        if v == flags:
            if prefix and k.startswith(prefix):
                defs.append(k)
    return defs


def get_windowhook_flags(flags):
    return get_flag_defines(flags, prefix='WH_')
