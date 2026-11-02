# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


class SpeakeasyError(Exception):
    """Base class for Speakeasy errors."""


class ConfigError(SpeakeasyError):
    """Raised when the configuration is not valid."""


class InputError(SpeakeasyError):
    """Raised when the input file or its architecture is not supported."""


class EmulationError(SpeakeasyError):
    """Base class for errors at run time."""


class NotSupportedError(EmulationError):
    """Sample is not currently supported."""


class ApiEmuError(EmulationError):
    """Base class for API errors."""


class CpuError(EmulationError):
    """Raised for CPU state errors, for example an unknown register or an instruction that does not decode."""


class OutOfMemoryError(EmulationError):
    """No free range of the address space can hold an allocation."""


class WindowsEmuError(EmulationError):
    """Base class for Windows emulation errors."""


class KernelEmuError(EmulationError):
    """Base class for Windows kernel mode emulation errors."""


class Win32EmuError(EmulationError):
    """Base class for Windows user mode emulation errors."""


class FileSystemEmuError(WindowsEmuError):
    """Base class for Windows file system emulation errors."""


class NetworkEmuError(WindowsEmuError):
    """Raised for network emulation errors."""


class RegistryEmuError(WindowsEmuError):
    """Raised for registry emulation errors."""


class EngineError(SpeakeasyError):
    """Raised when the CPU engine rejects a request, for example an unknown register or hook type."""


# Old names, kept for one release.
EmuException = CpuError
EmuEngineError = EngineError
