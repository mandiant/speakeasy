"""Public shellcode reports retain input literals and the strings that the shellcode writes at run time."""

from speakeasy import Speakeasy


def test_public_shellcode_reports_ansi_and_utf16_input_strings(config):
    config["memory"]["strings"] = True
    ansi = "INPUT_ANSI_LITERAL"
    wide = "INPUT_WIDE_LITERAL"
    data = b"\xc3\0" + ansi.encode() + b"\0\0" + wide.encode("utf-16le") + b"\0\0"
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=data, arch="x86")

        se.run_shellcode(base)

        report = se.get_report()
        assert report.entry_points[0].error is None
        assert ansi in report.strings.static.ansi
        assert wide in report.strings.static.unicode
        # Synthetic API export names must not replace the input inventory.
        assert "GetTickCount" not in report.strings.static.ansi


def test_public_shellcode_reports_each_new_string_once_and_skips_input_strings(config):
    config["memory"]["strings"] = True
    literal = "INPUT_ANSI_LITERAL"
    marker = "DECODED_STACK_MARKER"
    # The stack gets a copy of the input literal and two copies of the marker.
    # Byte-by-byte stores keep the marker out of the input image. RET leaves
    # the bytes below SP for the completion-time string scanner.
    stores = (literal + "\0" + marker + "\0" + marker + "\0").encode()
    code = b"\x83\xec\x40"
    for offset, value in enumerate(stores):
        code += b"\xc6\x44\x24" + bytes([offset, value])
    code += b"\x83\xc4\x40\xc3"
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=code + literal.encode() + b"\0", arch="x86")

        se.run_shellcode(base)

        report = se.get_report()
        assert report.entry_points[0].error is None
        assert literal in report.strings.static.ansi
        assert literal not in report.strings.in_memory.ansi
        assert report.strings.in_memory.ansi.count(marker) == 1


def test_public_shellcode_reports_strings_that_it_decodes_in_place(config):
    config["memory"]["strings"] = True
    marker = "SHELLCODE_DECODED_MARKER"
    # call $+5; pop eax; then one "mov byte [eax+disp32], imm8" for each character.
    code = b"\xe8\x00\x00\x00\x00\x58"
    data_offset = 6 + 7 * len(marker) + 1
    for offset, value in enumerate(marker.encode()):
        code += b"\xc6\x80" + (data_offset - 5 + offset).to_bytes(4, "little") + bytes([value])
    code += b"\xc3"
    assert len(code) == data_offset
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=code + bytes(len(marker) + 1), arch="x86")

        se.run_shellcode(base)

        report = se.get_report()
        assert report.entry_points[0].error is None
        assert marker not in report.strings.static.ansi
        assert report.strings.in_memory.ansi.count(marker) == 1
