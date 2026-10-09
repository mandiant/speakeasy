"""Public shellcode reports retain input literals and runtime stack strings."""

from speakeasy import Speakeasy


def test_public_shellcode_reports_ansi_and_utf16_input_strings(config):
    config["analysis"]["strings"] = True
    ansi = "INPUT_ANSI_LITERAL"
    wide = "INPUT_WIDE_LITERAL"
    data = b"\xc3\0" + ansi.encode() + b"\0\0" + wide.encode("utf-16le") + b"\0\0"
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=data, arch="x86")

        se.run_shellcode(base)

        report = se.get_report()
        assert ansi in report.strings.static.ansi
        assert wide in report.strings.static.unicode
        # Synthetic API export names must not replace the input inventory.
        assert "GetTickCount" not in report.strings.static.ansi


def test_public_shellcode_extracts_new_stack_string_after_guest_stores(config):
    config["analysis"]["strings"] = True
    marker = "DECODED_STACK_MARKER"
    # Byte-by-byte stores keep the complete text out of the input image. RET
    # leaves the bytes below SP for the completion-time string scanner.
    code = b"\x83\xec\x20"
    for offset, value in enumerate(marker.encode() + b"\0"):
        code += b"\xc6\x44\x24" + bytes([offset, value])
    code += b"\x83\xc4\x20\xc3"
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=code, arch="x86")

        se.run_shellcode(base)

        report = se.get_report()
        assert marker not in report.strings.static.ansi
        assert marker in report.strings.in_memory.ansi
