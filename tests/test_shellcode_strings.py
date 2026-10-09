"""Public shellcode reports retain input literals and runtime stack strings."""

import pytest

from speakeasy import Speakeasy


@pytest.fixture(params=["x86", "amd64"])
def architecture(request):
    return request.param


@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "enabled"])
def test_public_shellcode_reports_ansi_and_utf16_input_strings(architecture, enabled, config):
    config["analysis"]["strings"] = enabled
    ansi = "INPUT_ANSI_LITERAL"
    wide = "INPUT_WIDE_LITERAL"
    data = b"\xc3\0" + ansi.encode() + b"\0\0" + wide.encode("utf-16le") + b"\0\0"
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=data, arch=architecture)
        report = se.get_report()
        if enabled:
            assert ansi in report.strings.static.ansi
            assert wide in report.strings.static.unicode
        else:
            assert report.strings is None

        se.run_shellcode(base)

        report = se.get_report()
        assert report.entry_points[0].error is None
        if enabled:
            assert ansi in report.strings.static.ansi
            assert wide in report.strings.static.unicode
            # Synthetic API export names must not replace the input inventory.
            assert "GetTickCount" not in report.strings.static.ansi
        else:
            assert report.strings is None


@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "enabled"])
def test_public_shellcode_extracts_new_stack_string_after_guest_stores(architecture, enabled, config):
    config["analysis"]["strings"] = enabled
    marker = "DECODED_STACK_MARKER"
    adjust = b"\x83" if architecture == "x86" else b"\x48\x83"
    code = adjust + b"\xec\x20"
    # Isolated byte immediates keep the complete text out of the input image.
    # Actual guest writes materialize it below SP; RET leaves those bytes in
    # stack memory for the normal completion-time string scanner.
    for offset, value in enumerate(marker.encode() + b"\0"):
        code += b"\xc6\x44\x24" + bytes([offset, value])
    code += adjust + b"\xc4\x20\xc3"
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=code, arch=architecture)
        initial = se.get_report().strings
        assert initial is None or marker not in initial.static.ansi

        se.run_shellcode(base)

        report = se.get_report()
        assert report.entry_points[0].error is None
        if enabled:
            assert marker not in report.strings.static.ansi
            assert marker in report.strings.in_memory.ansi
        else:
            assert report.strings is None
