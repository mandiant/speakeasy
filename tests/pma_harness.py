import copy
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from speakeasy import Speakeasy

TESTS_DIR = Path(__file__).resolve().parent
PMA_DIR = TESTS_DIR / "capa-testfiles"
URL_PATTERN = re.compile(r"https?://[^\s\"']+")


@dataclass(frozen=True)
class IndicatorExpectations:
    files: tuple[str, ...] = ()
    registry_keys: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()


@dataclass(frozen=True)
class CaseRuntime:
    sample_path: Path | None = None
    argv: tuple[str, ...] = ()
    volumes: tuple[str, ...] = ()


CaseProfile = Callable[[dict[str, Any], Path], CaseRuntime]


@dataclass(frozen=True)
class PmaCase:
    name: str
    sample: str
    expected_apis: tuple[str, ...]
    indicators: IndicatorExpectations = field(default_factory=IndicatorExpectations)
    config_patch: dict[str, Any] = field(default_factory=dict)
    allowed_entrypoint_errors: tuple[str, ...] = ()
    argv: tuple[str, ...] = ()
    profile: CaseProfile | None = None


@dataclass(frozen=True)
class ObservedBehavior:
    api_names: set[str]
    files: set[str]
    registry_keys: set[str]
    domains: set[str]
    urls: set[str]
    entrypoint_errors: set[str]
    unsupported_api_count: int


def normalize_value(value: str) -> str:
    return value.lower()


def build_case_config(base_config: dict[str, Any], case: PmaCase) -> dict[str, Any]:
    cfg = copy.deepcopy(base_config)
    cfg["timeout"] = 4
    cfg["max_api_count"] = 600
    merge_config_patch(cfg, case.config_patch)
    return cfg


def merge_config_patch(target: dict[str, Any], patch: dict[str, Any]) -> None:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            merge_config_patch(target[key], value)
            continue
        target[key] = copy.deepcopy(value)


def get_sample_path(case: PmaCase) -> Path:
    return PMA_DIR / case.sample


def run_case(base_config: dict[str, Any], case: PmaCase, tmp_path: Path):
    cfg = build_case_config(base_config, case)
    runtime = CaseRuntime()
    if case.profile is not None:
        runtime = case.profile(cfg, tmp_path)

    sample_path = runtime.sample_path or get_sample_path(case)
    argv = runtime.argv if runtime.argv else case.argv

    kwargs: dict[str, Any] = {
        "config": cfg,
        "argv": list(argv),
    }
    if runtime.volumes:
        kwargs["volumes"] = list(runtime.volumes)

    se = Speakeasy(**kwargs)
    try:
        module = se.load_module(str(sample_path))
        se.run_module(module, all_entrypoints=True)
        return se.get_report()
    finally:
        se.shutdown()


def collect_behavior(report) -> ObservedBehavior:
    events = [evt for ep in report.entry_points for evt in (ep.events or [])]
    api_events = [evt for evt in events if evt.event == "api"]

    api_names = {normalize_value(evt.api_name) for evt in api_events if evt.api_name}
    files = {
        normalize_value(evt.path)
        for evt in events
        if evt.event in {"file_create", "file_open", "file_read", "file_write"} and getattr(evt, "path", None)
    }
    files.update(
        normalize_value(dropped.path)
        for ep in report.entry_points
        for dropped in (ep.dropped_files or [])
        if getattr(dropped, "path", None)
    )

    registry_keys = {
        normalize_value(evt.path)
        for evt in events
        if evt.event in {"reg_open_key", "reg_create_key", "reg_read_value", "reg_list_subkeys"}
        and getattr(evt, "path", None)
    }

    domains = {normalize_value(evt.query) for evt in events if evt.event == "net_dns" and getattr(evt, "query", None)}
    domains.update(
        normalize_value(evt.server) for evt in events if evt.event == "net_http" and getattr(evt, "server", None)
    )

    urls = set()
    for evt in api_events:
        for arg in evt.args or []:
            if isinstance(arg, str):
                urls.update(normalize_value(match) for match in URL_PATTERN.findall(arg))

    unsupported_api_count = sum(1 for evt in events if evt.event == "unsupported_api")
    unsupported_api_count += sum(1 for evt in api_events if (evt.api_name or "").lower().startswith("unsupported"))

    entrypoint_errors = {ep.error.type for ep in report.entry_points if ep.error and getattr(ep.error, "type", None)}

    return ObservedBehavior(
        api_names=api_names,
        files=files,
        registry_keys=registry_keys,
        domains=domains,
        urls=urls,
        entrypoint_errors=entrypoint_errors,
        unsupported_api_count=unsupported_api_count,
    )


def assert_case(case: PmaCase, report, observed: ObservedBehavior) -> None:
    assert report.errors is None
    assert report.entry_points
    assert observed.unsupported_api_count == 0

    for api_name in case.expected_apis:
        assert normalize_value(api_name) in observed.api_names

    for path in case.indicators.files:
        assert normalize_value(path) in observed.files

    for path in case.indicators.registry_keys:
        assert normalize_value(path) in observed.registry_keys

    for domain in case.indicators.domains:
        assert normalize_value(domain) in observed.domains

    for url in case.indicators.urls:
        assert normalize_value(url) in observed.urls

    assert observed.entrypoint_errors.issubset(set(case.allowed_entrypoint_errors))
