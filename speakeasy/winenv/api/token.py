"""
The access token information that GetTokenInformation and NtQueryInformationToken return.

On Windows, GetTokenInformation calls NtQueryInformationToken, so the advapi32 and the ntoskrnl
handlers use the same function. Each token has the user of the configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.winenv.defs.enums import TOKEN_INFORMATION_CLASS
from speakeasy.winenv.defs.nt import ddk

if TYPE_CHECKING:
    from speakeasy.windows.winemu import WindowsEmulator
    from speakeasy.winenv.api.api import ApiHandler


def query_token_information(
    handler: ApiHandler, emu: WindowsEmulator, info_class: int, buf: int, length: int
) -> tuple[int, int]:
    """
    Write the token information of info_class to buf, as NtQueryInformationToken does.

    Return the NTSTATUS and the ReturnLength. TokenUser and TokenIntegrityLevel return
    STATUS_BUFFER_TOO_SMALL for a short buffer. TokenElevation needs exactly 4 bytes and returns
    STATUS_INFO_LENGTH_MISMATCH for other lengths. Other classes need 4 bytes and leave the
    buffer unchanged.
    """
    if info_class == TOKEN_INFORMATION_CLASS.TokenElevation:
        if length != 4:
            return ddk.STATUS_INFO_LENGTH_MISMATCH, 4
        if not buf:
            return ddk.STATUS_ACCESS_VIOLATION, 4
        handler.write_dword(buf, int(emu.config.user.admin))
        return ddk.STATUS_SUCCESS, 4

    if info_class in (TOKEN_INFORMATION_CLASS.TokenUser, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel):
        ptr_size = emu.get_ptr_size()
        if info_class == TOKEN_INFORMATION_CLASS.TokenUser:
            str_sid = emu.config.user.sid
            attributes = 0
        else:
            str_sid = "S-1-16-12288" if emu.config.user.admin else "S-1-16-8192"
            attributes = windefs.SE_GROUP_INTEGRITY
        sid = handler.get_bytes(windefs.convert_sid_str_to_struct(ptr_size, str_sid))
        size = 2 * ptr_size + len(sid)
        if not buf or length < size:
            return ddk.STATUS_BUFFER_TOO_SMALL, size
        label = (buf + 2 * ptr_size).to_bytes(ptr_size, "little") + attributes.to_bytes(ptr_size, "little")
        handler.mem_write(buf, label + sid)
        return ddk.STATUS_SUCCESS, size

    return (ddk.STATUS_SUCCESS if length >= 4 else ddk.STATUS_BUFFER_TOO_SMALL), 4
