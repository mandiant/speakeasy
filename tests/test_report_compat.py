import copy
import json
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from speakeasy import Speakeasy
from speakeasy.profiler_events import ApiEvent, UnknownEvent
from speakeasy.report import ErrorType, Report
from tests.strict_report import get_strict_report


@pytest.fixture(scope="module")
def report_dict(base_config, load_test_bin) -> dict[str, Any]:
    se = Speakeasy(config=copy.deepcopy(base_config))
    try:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        se.run_module(module)
        return json.loads(se.get_json_report())
    finally:
        se.shutdown()


def add_top_level_key(r: dict[str, Any]) -> None:
    r["analysis_host"] = "sandbox-1"


def add_api_event_key(r: dict[str, Any]) -> None:
    r["runs"][0]["events"][0]["thread_name"] = "main"


def add_event_type(r: dict[str, Any]) -> None:
    pos = r["runs"][0]["events"][0]["pos"]
    r["runs"][0]["events"].append({"pos": pos, "event": "mutex_create", "name": "Global\\x"})


def add_event_type_with_no_other_keys(r: dict[str, Any]) -> None:
    pos = r["runs"][0]["events"][0]["pos"]
    r["runs"][0]["events"].append({"pos": pos, "event": "heartbeat"})


def add_error_type(r: dict[str, Any]) -> None:
    r["runs"][0]["error"] = {"type": "memory_limit", "pc": "0x401000"}


NEWER_MINOR_CHANGES = [
    add_top_level_key,
    add_api_event_key,
    add_event_type,
    add_event_type_with_no_other_keys,
    add_error_type,
]


def get_changed(report: dict[str, Any], change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    changed = copy.deepcopy(report)
    change(changed)
    return changed


def test_a_newer_minor_report_validates(report_dict):
    changed = report_dict
    for change in NEWER_MINOR_CHANGES:
        changed = get_changed(changed, change)

    report = Report.model_validate(changed)

    events = report.runs[0].events
    assert isinstance(events[0], ApiEvent)
    unknown = [e for e in events if isinstance(e, UnknownEvent)]
    assert [e.event for e in unknown] == ["mutex_create", "heartbeat"]
    assert unknown[0].model_extra == {"name": "Global\\x"}
    assert unknown[0].pos == events[0].pos
    error = report.runs[0].error
    assert error is not None
    assert error.type == "memory_limit"
    assert error.pc == 0x401000


def test_a_known_error_type_is_an_error_type_member(report_dict):
    changed = copy.deepcopy(report_dict)
    changed["runs"][0]["error"] = {"type": "api_call_limit"}

    error = Report.model_validate(changed).runs[0].error

    assert error is not None
    assert error.type is ErrorType.API_CALL_LIMIT


def test_an_unknown_event_keeps_its_keys_in_the_json(report_dict):
    changed = get_changed(report_dict, add_event_type)

    dumped = json.loads(Report.model_validate(changed).model_dump_json(exclude_none=True))

    assert dumped["runs"][0]["events"][-1] == changed["runs"][0]["events"][-1]


def test_a_known_event_type_with_a_missing_field_fails(report_dict):
    changed = copy.deepcopy(report_dict)
    del changed["runs"][0]["events"][0]["api_name"]

    with pytest.raises(ValidationError, match="api_name"):
        Report.model_validate(changed)


def test_the_report_of_a_run_validates_in_strict_mode(report_dict):
    get_strict_report(json.dumps(report_dict))


@pytest.mark.parametrize("change", NEWER_MINOR_CHANGES)
def test_strict_mode_rejects_what_the_models_do_not_know(report_dict, change):
    changed = get_changed(report_dict, change)

    with pytest.raises(ValueError):
        get_strict_report(json.dumps(changed))


def test_a_report_of_a_newer_minor_version_validates(report_dict):
    changed = copy.deepcopy(report_dict)
    changed["report_version"] = "7.1.0"

    assert Report.model_validate(changed).report_version == "7.1.0"


@pytest.mark.parametrize("version", ["6.2.0", "8.0.0", "1.1.0"])
def test_a_report_of_another_major_version_fails(report_dict, version):
    changed = copy.deepcopy(report_dict)
    changed["report_version"] = version

    with pytest.raises(ValidationError, match="report_version"):
        Report.model_validate(changed)
