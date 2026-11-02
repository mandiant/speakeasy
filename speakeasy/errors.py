# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


class SpeakeasyError(Exception):
    """Base class for Speakeasy errors."""


class NotSupportedError(SpeakeasyError):
    """Sample is not currently supported."""


class ApiEmuError(SpeakeasyError):
    """Base class for API errors."""


class EmuException(SpeakeasyError):
    """Base class for emulation errors."""


class OutOfMemoryError(SpeakeasyError):
    """No free range of the address space can hold an allocation."""


class EmuEngineError(SpeakeasyError):
    pass


class WindowsEmuError(SpeakeasyError):
    """Base class for Windows emulation errors."""


class KernelEmuError(SpeakeasyError):
    """Base class for Windows kernel mode emulation errors."""


class Win32EmuError(SpeakeasyError):
    """Base class for Windows user mode emulation errors."""


class FileSystemEmuError(SpeakeasyError):
    """Base class for Windows file system emulation errors."""


class NetworkEmuError(SpeakeasyError):
    """Raised for network emulation errors."""


class RegistryEmuError(SpeakeasyError):
    """Raised for registry emulation errors."""


class ConfigError(SpeakeasyError):
    """Raised when the configuration is not valid."""
