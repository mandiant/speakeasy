"""
The DLL names in the system directory of a clean Windows install.

Each ``resources/win32/system_dlls/<arch>.txt`` file holds the lower-case file names of the DLLs
in ``System32`` (x64) or ``SysWOW64`` (x86), one name on each line.
"""

from __future__ import annotations

import ntpath
from functools import cache
from pathlib import Path

SYSTEM_DLLS_ROOT = Path(__file__).resolve().parent.parent / "resources" / "win32" / "system_dlls"


@cache
def get_system_dlls(arch: str) -> frozenset[str]:
    """Get the DLL file names in the system directory that an ``x86`` or ``x64`` process sees."""
    return frozenset((SYSTEM_DLLS_ROOT / f"{arch}.txt").read_text().split())


def is_system_dll(path: str, arch: str) -> bool:
    """
    Tell if LoadLibrary finds the file of path in the system directory of a clean install.

    LoadLibrary adds ``.dll`` to a file name without an extension.
    """
    file_name = ntpath.basename(path).lower()
    if "." not in file_name:
        file_name += ".dll"
    return file_name in get_system_dlls(arch)
