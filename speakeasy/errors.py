# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

class SpeakeasyError(Exception):
    """
    Base class for Speakeasy errors
    """
    pass


class NotSupportedError(SpeakeasyError):
    """
    Sample is not currently supported
    """
    pass


class ApiEmuError(SpeakeasyError):
    """
    Base class for API errors
    """
    pass


class EmuException(SpeakeasyError):
    """
    Base class for emulation errors
    """
    pass


class EmuEngineError(SpeakeasyError):
    pass


class WindowsEmuError(SpeakeasyError):
    """
    Base class for Windows emulation errors
    """
    pass


class KernelEmuError(SpeakeasyError):
    """
    Base class for Windows kernel mode emulation errors
    """
    pass


class Win32EmuError(SpeakeasyError):
    """
    Base class for Windows user mode emulation errors
    """
    pass


class FileSystemEmuError(SpeakeasyError):
    """
    Base class for Windows user mode emulation errors
    """
    pass


class NetworkEmuError(SpeakeasyError):
    """
    Raised during network emulation errors
    """
    pass


class RegistryEmuError(SpeakeasyError):
    """
    Raised during registry emulation errors
    """
    pass


class ConfigError(SpeakeasyError):
    """
    Raised during validating configuration
    """
    pass
