from speakeasy.profiler_events import UnknownEvent
from speakeasy.report import ErrorType, Report


def get_strict_report(data: str | bytes) -> Report:
    """
    Validate a report JSON, and reject each key, event type and error type that the models do not know.

    The shipped models accept these, so that a consumer can read a report of a newer minor version.
    The tests use this function, so that Speakeasy cannot write a report that its own models do not describe.

    Raises:
        ValueError: if the report has data that the models do not know. ``pydantic.ValidationError`` is a
            ``ValueError``.
    """
    report = Report.model_validate_json(data, extra="forbid")
    errors = list(report.errors)
    for i, run in enumerate(report.runs):
        for event in run.events:
            if isinstance(event, UnknownEvent):
                raise ValueError(f"run {i}: unknown event type {event.event!r}")
        if run.error is not None:
            errors.append(run.error)
    for error in errors:
        if not isinstance(error.type, ErrorType):
            raise ValueError(f"unknown error type {error.type!r}")
    return report
