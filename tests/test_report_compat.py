import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from speakeasy import Speakeasy
from speakeasy.profiler_events import ApiEvent, UnknownEvent
from speakeasy.report import ErrorType, Report


@pytest.fixture(scope="module")
def report_dict(base_config, load_test_bin) -> dict[str, Any]:
    se = Speakeasy(config=copy.deepcopy(base_config))
    try:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        se.run_module(module)
        return json.loads(se.get_json_report())
    finally:
        se.shutdown()


def test_a_report_of_a_newer_minor_version_validates(report_dict):
    r = copy.deepcopy(report_dict)
    r["report_version"] = "7.1.0"
    r["analysis_host"] = "sandbox-1"
    events = r["runs"][0]["events"]
    events[0]["thread_name"] = "main"
    events.append({"pos": events[0]["pos"], "event": "mutex_create", "name": "Global\\x"})
    r["runs"][0]["error"] = {"type": "memory_limit", "pc": "0x401000"}

    report = Report.model_validate(r)

    events = report.runs[0].events
    assert isinstance(events[0], ApiEvent)
    assert isinstance(events[-1], UnknownEvent)
    assert events[-1].event == "mutex_create"
    assert events[-1].model_extra == {"name": "Global\\x"}
    error = report.runs[0].error
    assert error is not None
    assert error.type == "memory_limit"
    assert error.pc == 0x401000


def test_a_known_error_type_is_an_error_type_member(report_dict):
    r = copy.deepcopy(report_dict)
    r["runs"][0]["error"] = {"type": "api_call_limit"}

    error = Report.model_validate(r).runs[0].error

    assert error is not None
    assert error.type is ErrorType.API_CALL_LIMIT


def test_a_known_event_type_with_a_missing_field_fails(report_dict):
    r = copy.deepcopy(report_dict)
    del r["runs"][0]["events"][0]["api_name"]

    with pytest.raises(ValidationError, match="api_name"):
        Report.model_validate(r)


def test_an_event_type_that_is_not_a_string_fails(report_dict):
    r = copy.deepcopy(report_dict)
    r["runs"][0]["events"][0]["event"] = ["api"]

    with pytest.raises(ValidationError, match="event"):
        Report.model_validate(r)


@pytest.mark.parametrize("version", ["1.1.0", "8.0.0"])
def test_a_report_of_another_major_version_fails(report_dict, version):
    r = copy.deepcopy(report_dict)
    r["report_version"] = version

    with pytest.raises(ValidationError, match="report_version"):
        Report.model_validate(r)
