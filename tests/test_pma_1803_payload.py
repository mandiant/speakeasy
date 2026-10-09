"""The unpacked PMA18-03 payload must pass its real filename gate without hooks."""

import pytest

from tests.pma_cases import PMA_CASES
from tests.pma_harness import assert_case, collect_behavior, get_sample_path, run_case


def test_ocl_payload_connects_and_starts_socket_backed_shell(base_config, tmp_path):
    case = next(case for case in PMA_CASES if case.name == "pma-18-03-ocl")
    source = get_sample_path(case)
    if not source.exists():
        pytest.skip(f"missing sample: {source}")

    report = run_case(base_config, case, tmp_path)
    assert (tmp_path / "ocl.exe").read_bytes() == source.read_bytes()
    assert_case(case, report, collect_behavior(report))
    events = [event for ep in report.entry_points for event in ep.events or []]
    apis = [event for event in events if event.event == "api"]

    filenames = [event for event in apis if event.api_name.lower() == "kernel32.getmodulefilenamea"]
    assert filenames
    assert all(event.args[1].display.lower().endswith("\\ocl.exe") for event in filenames)
    connect = next(event for event in apis if event.api_name.lower() == "ws2_32.connect")
    assert connect.args[1].display.endswith(":9999")
    assert connect.ret_val == "0x0"
    shell = next(event for event in apis if event.api_name.lower() == "kernel32.createprocessa")
    assert shell.args[1].display == "cmd"
    assert shell.args[4].value == 1
    assert shell.ret_val == "0x1"
    socket = hex(connect.args[0].value)
    startup = shell.args[8].display
    assert "STARTF_USESTDHANDLES" in startup
    assert all(f"{handle}: {socket}" in startup for handle in ("hStdInput", "hStdOutput", "hStdError"))
    assert any(event.event == "net_traffic" and event.port == 9999 for event in events)
    assert any(event.event == "process_create" and event.cmdline == "cmd" for event in events)
    assert {ep.error.type for ep in report.entry_points if ep.error} == {"max_api_count"}
