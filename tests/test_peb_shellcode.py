"""
Test for GitHub issue #45: Shellcode emulation issue.

Shellcode that walks the PEB InInitializationOrderModuleList to find
kernel32.dll and resolve exports (the classic Metasploit technique)
must work correctly. The InInitializationOrderModuleList skips the EXE
and should have ntdll first, kernel32 second.
"""

import copy
import struct

from speakeasy import Speakeasy
from speakeasy.report import Report


def _run_shellcode(cfg: dict, sc_bytes: bytes) -> Report:
    se = Speakeasy(config=cfg)
    try:
        addr = se.load_shellcode(arch="x86", data=sc_bytes)
        se.run_shellcode(addr)
        return se.get_report()
    finally:
        se.shutdown()


def _build_peb_walk_shellcode() -> bytes:
    """Build x86 shellcode that walks PEB InInitializationOrderModuleList.

    This is a simplified version of the classic block_api technique used by
    Metasploit. It walks InInitializationOrderModuleList to reach kernel32
    (expected at position 2 — after ntdll), reads the export directory,
    and resolves WinExec by hash, then calls WinExec("calc", 0).

    The ROR13 hash for WinExec is 0x0E8AFE98.
    """
    sc = bytearray()

    # --- PEB walk to get kernel32 base ---
    # xor ecx, ecx
    sc += b"\x31\xc9"
    # mov eax, fs:[ecx+0x30]   ; PEB
    sc += b"\x64\x8b\x41\x30"
    # mov eax, [eax+0x0c]      ; PEB->Ldr
    sc += b"\x8b\x40\x0c"
    # mov esi, [eax+0x1c]      ; InInitializationOrderModuleList.Flink (1st entry = ntdll)
    sc += b"\x8b\x70\x1c"
    # lodsd (eax = [esi], esi += 4)  ; follow Flink to 2nd entry = kernel32
    sc += b"\xad"
    # mov ebx, [eax+0x08]      ; InInitializationOrderModuleList entry + 0x08 = DllBase
    sc += b"\x8b\x58\x08"

    # ebx = kernel32 base address
    # Now resolve WinExec from kernel32's export table

    # --- Parse PE export directory ---
    # mov edx, [ebx+0x3c]      ; e_lfanew
    sc += b"\x8b\x53\x3c"
    # mov edx, [edx+ebx+0x78]  ; export directory RVA
    sc += b"\x8b\x54\x13\x78"
    # add edx, ebx             ; export directory VA
    sc += b"\x01\xda"
    # mov ecx, [edx+0x18]      ; NumberOfNames
    sc += b"\x8b\x4a\x18"
    # mov edi, [edx+0x20]      ; AddressOfNames RVA
    sc += b"\x8b\x7a\x20"
    # add edi, ebx             ; AddressOfNames VA
    sc += b"\x01\xdf"

    # --- Search for WinExec by ROR13 hash ---
    # search_loop:
    # jecxz not_found          ; if ecx==0, bail (placeholder — won't happen)
    sc += b"\xe3\x28"  # jump forward past the search (will adjust)
    # dec ecx
    sc += b"\x49"
    # mov esi, [edi+ecx*4]     ; name RVA
    sc += b"\x8b\x34\x8f"
    # add esi, ebx             ; name VA
    sc += b"\x01\xde"

    # --- ROR13 hash the name ---
    # xor eax, eax
    sc += b"\x31\xc0"
    # xor edx, edx              ; save edx? no, we reload it. use ebp for export dir
    # Actually let's keep it simpler: push/pop edx around the hash loop
    # We need edx for the export dir pointer. Let's save it.
    # push the export directory address
    # Actually, let's restructure. We saved ebx = kernel32 base.
    # We can re-derive edx after finding the name index.
    # For simplicity, let's just compute the hash in eax.

    # hash_loop:
    # lodsb                     ; al = [esi++]
    sc += b"\xac"
    # test al, al
    sc += b"\x84\xc0"
    # jz hash_done
    sc += b"\x74\x07"
    # ror eax, 0x0d  (but we need to preserve upper bits... use edx as accumulator)
    # Let's redo: use edx as hash accumulator

    # Start over with a cleaner approach using the standard block_api pattern
    sc = bytearray()

    # --- Classic Metasploit-style PEB walk + export resolution ---
    # This shellcode finds kernel32 via InInitializationOrderModuleList,
    # then resolves and calls WinExec("calc", 0).

    # cld
    sc += b"\xfc"
    # xor ecx, ecx
    sc += b"\x31\xc9"
    # mov eax, fs:[ecx+0x30]   ; PEB
    sc += b"\x64\x8b\x41\x30"
    # mov eax, [eax+0x0c]      ; PEB->Ldr
    sc += b"\x8b\x40\x0c"
    # mov esi, [eax+0x1c]      ; InInitializationOrderModuleList.Flink
    sc += b"\x8b\x70\x1c"

    # First entry is ntdll, follow Flink to get kernel32
    # lodsd                     ; eax = [esi]; esi += 4
    sc += b"\xad"
    # mov ebp, [eax+0x08]      ; DllBase of kernel32
    sc += b"\x8b\x68\x08"

    # ebp = kernel32 base

    # push 0                    ; uCmdShow = SW_HIDE
    sc += b"\x6a\x00"
    # push 0x636c6163           ; "calc" (little-endian, will be on stack)
    # Actually let's push "calc\0" properly
    # push 0x00636c61           ; "alc\0"
    sc += b"\x68\x61\x6c\x63\x00"
    # We need "calc" = 63 61 6c 63 but as a null-terminated string on stack
    # push "calc\0":
    # 'c' 'a' 'l' 'c' '\0'  → we need 5 bytes
    # push 0x00 first, then push "calc"
    # Actually that won't work because push is 4 bytes. Let's use:
    # push 0x00636c6163 won't work (5 bytes)
    # Simpler: push the string with a null terminator
    # xor eax, eax
    # push eax                  ; null terminator
    # push 0x636c6163           ; "calc"

    # Let me restart with clean shellcode
    sc = bytearray()

    # cld
    sc += b"\xfc"

    # --- Get kernel32 base via PEB InInitializationOrderModuleList ---
    # xor ecx, ecx
    sc += b"\x31\xc9"
    # mov eax, fs:[ecx+0x30]   ; PEB
    sc += b"\x64\x8b\x41\x30"
    # mov eax, [eax+0x0c]      ; PEB->Ldr
    sc += b"\x8b\x40\x0c"
    # mov esi, [eax+0x1c]      ; InInitializationOrderModuleList.Flink (ntdll entry)
    sc += b"\x8b\x70\x1c"
    # lodsd                     ; eax = Flink of ntdll entry -> kernel32 entry; esi advances
    sc += b"\xad"
    # mov ebp, [eax+0x08]      ; DllBase of 2nd entry (kernel32)
    sc += b"\x8b\x68\x08"

    # ebp now holds kernel32 base address.
    # If the PEB ordering is wrong (kernel32 not at position 2),
    # this will get the wrong DllBase and the PE parsing below will crash.

    # --- Parse kernel32 PE exports to find WinExec ---
    # mov edx, [ebp+0x3c]      ; e_lfanew
    sc += b"\x8b\x55\x3c"
    # mov edx, [edx+ebp+0x78]  ; export directory RVA
    sc += b"\x8b\x54\x15\x78"
    # add edx, ebp             ; export directory VA
    sc += b"\x01\xea"
    # mov ecx, [edx+0x18]      ; NumberOfNames
    sc += b"\x8b\x4a\x18"
    # mov ebx, [edx+0x20]      ; AddressOfNames RVA
    sc += b"\x8b\x5a\x20"
    # add ebx, ebp             ; AddressOfNames VA
    sc += b"\x01\xeb"

    # --- Search for "WinExec" by ROR13 hash ---
    # The ROR13 hash of "WinExec" is 0x0e8afe98
    # search_loop:
    search_off = len(sc)
    # jecxz done               ; if no more names, give up
    sc += b"\xe3"
    sc += b"\x00"  # placeholder for relative offset (will patch)
    jecxz_patch = len(sc) - 1
    # dec ecx
    sc += b"\x49"
    # mov esi, [ebx+ecx*4]     ; name RVA
    sc += b"\x8b\x34\x8b"
    # add esi, ebp             ; name VA
    sc += b"\x01\xee"

    # Compute ROR13 hash of the export name
    # xor edi, edi
    sc += b"\x31\xff"
    # hash_loop:
    hash_off = len(sc)
    # xor eax, eax
    sc += b"\x31\xc0"
    # lodsb
    sc += b"\xac"
    # test al, al
    sc += b"\x84\xc0"
    # jz hash_done
    sc += b"\x74\x07"
    # ror edi, 0x0d
    sc += b"\xc1\xcf\x0d"
    # add edi, eax
    sc += b"\x01\xc7"
    # jmp hash_loop
    jmp_back = len(sc)
    sc += b"\xeb"
    sc += struct.pack("b", hash_off - (jmp_back + 2))

    # hash_done:
    # cmp edi, 0x0e8afe98       ; ROR13("WinExec")
    sc += b"\x81\xff\x98\xfe\x8a\x0e"
    # jnz search_loop
    jnz_off = len(sc)
    sc += b"\x75"
    sc += struct.pack("b", search_off - (jnz_off + 2))

    # Found WinExec at index ecx in the names table.
    # Resolve the function address:
    # mov ebx, [edx+0x24]      ; AddressOfNameOrdinals RVA
    sc += b"\x8b\x5a\x24"
    # add ebx, ebp             ; VA
    sc += b"\x01\xeb"
    # movzx ecx, word [ebx+ecx*2] ; ordinal
    sc += b"\x0f\xb7\x0c\x4b"
    # mov ebx, [edx+0x1c]      ; AddressOfFunctions RVA
    sc += b"\x8b\x5a\x1c"
    # add ebx, ebp
    sc += b"\x01\xeb"
    # mov eax, [ebx+ecx*4]     ; function RVA
    sc += b"\x8b\x04\x8b"
    # add eax, ebp             ; function VA
    sc += b"\x01\xe8"

    # eax = address of WinExec

    # --- Call WinExec("calc", 0) ---
    # push 0                    ; uCmdShow
    sc += b"\x6a\x00"
    # push "calc\0" onto stack
    # xor ecx, ecx
    sc += b"\x31\xc9"
    # push ecx                  ; null terminator
    sc += b"\x51"
    # push 0x636c6163           ; "clac" -> but "calc" in LE is 0x636c6163...
    # "calc" = 63 61 6c 63 hex. In memory (LE): 63 61 6c 63 → push 0x636c6163
    # wait: 'c'=0x63, 'a'=0x61, 'l'=0x6c, 'c'=0x63
    # on stack as string: esp -> 0x63 0x61 0x6c 0x63 0x00 0x00 0x00 0x00
    # push dword: bytes at esp = val[0], esp+1 = val[1], etc (little endian)
    # push 0x636c6163 -> esp: 63 61 6c 63  -> "calc" ✓
    sc += b"\x68\x63\x61\x6c\x63"
    # mov ecx, esp              ; lpCmdLine -> "calc"
    sc += b"\x89\xe1"
    # push ecx                  ; lpCmdLine
    sc += b"\x51"
    # call eax                  ; WinExec("calc", 0)
    sc += b"\xff\xd0"

    # Patch jecxz target (jump to after the call = end of shellcode)
    done_off = len(sc)
    sc[jecxz_patch] = (done_off - (jecxz_patch + 1)) & 0xFF

    # ret
    sc += b"\xc3"

    return bytes(sc)


def test_peb_walk_finds_kernel32_and_calls_winexec(config):
    """Issue #45: shellcode walking InInitializationOrderModuleList must find kernel32.

    The shellcode walks PEB->Ldr->InInitializationOrderModuleList,
    expects ntdll as entry 1 and kernel32 as entry 2, then resolves
    WinExec and calls it. If the PEB module order is wrong, emulation
    crashes with an invalid memory read before reaching any API call.
    """
    sc = _build_peb_walk_shellcode()
    report = _run_shellcode(config, sc)

    ep = report.entry_points[0]
    api_names = [e.api_name for e in (ep.events or []) if e.event == "api"]
    assert "kernel32.WinExec" in api_names, (
        f"WinExec not found in API calls (got {api_names}). "
        "PEB InInitializationOrderModuleList ordering may be wrong (issue #45)."
    )


def test_peb_walk_works_even_with_reversed_config_order(base_config):
    """Verify _ordered_peb_modules() corrects bad config ordering.

    Even if the config lists kernel32 before ntdll (wrong init order),
    the emulator must reorder them so InInitializationOrderModuleList
    has ntdll first and kernel32 second.
    """
    cfg = copy.deepcopy(base_config)
    umods = cfg["modules"]["user_modules"]
    ntdll_idx = next(i for i, m in enumerate(umods) if m["name"] == "ntdll")
    k32_idx = next(i for i, m in enumerate(umods) if m["name"] == "kernel32")
    if ntdll_idx < k32_idx:
        umods[ntdll_idx], umods[k32_idx] = umods[k32_idx], umods[ntdll_idx]

    sc = _build_peb_walk_shellcode()
    report = _run_shellcode(cfg, sc)

    ep = report.entry_points[0]
    api_names = [e.api_name for e in (ep.events or []) if e.event == "api"]
    assert "kernel32.WinExec" in api_names, (
        f"WinExec not found in API calls (got {api_names}). "
        "_ordered_peb_modules() failed to correct config ordering (issue #45)."
    )
