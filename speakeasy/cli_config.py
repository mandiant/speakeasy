from __future__ import annotations

import argparse
import copy
import json
import types
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Union, get_args, get_origin

from pydantic import BaseModel
from pydantic.fields import PydanticUndefined

from speakeasy.config import SpeakeasyConfig
from speakeasy.config import get_default_config_dict as get_model_default_config_dict

EXCLUDED_CLI_PATHS = {
    "config_version",
    "description",
    "emu_engine",
    "system",
    "os_ver.name",
}

EXCLUDED_CLI_PREFIXES = (
    "symlinks",
    "drives",
    "filesystem.files",
    "registry.keys",
    "network.dns.txt",
    "network.http.responses",
    "network.winsock.responses",
    "network.adapters",
    "processes",
    "modules.user_modules",
    "modules.system_modules",
)


@dataclass(frozen=True)
class ConfigCliFieldSpec:
    path: str
    option: str
    dest: str
    kind: Literal["bool", "int", "float", "str", "list_str", "dict_str_str"]
    description: str
    default: Any


@dataclass(frozen=True)
class _LeafField:
    path: str
    annotation: Any
    description: str | None
    model_default: Any


def get_default_config_dict() -> dict[str, Any]:
    return get_model_default_config_dict()


def merge_config_dicts(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = merge_config_dicts(current, value)
            continue
        merged[key] = copy.deepcopy(value)
    return merged


def add_config_cli_arguments(parser: argparse.ArgumentParser, specs: list[ConfigCliFieldSpec]) -> None:
    for spec in specs:
        help_text = f"{spec.description} (default: {render_cli_default(spec.default)})"
        if spec.kind == "bool":
            parser.add_argument(
                spec.option,
                dest=spec.dest,
                action=argparse.BooleanOptionalAction,
                default=argparse.SUPPRESS,
                help=help_text,
            )
            continue
        if spec.kind == "int":
            parser.add_argument(
                spec.option,
                dest=spec.dest,
                type=int,
                metavar=get_cli_metavar(spec),
                default=argparse.SUPPRESS,
                help=help_text,
            )
            continue
        if spec.kind == "float":
            parser.add_argument(
                spec.option,
                dest=spec.dest,
                type=float,
                metavar=get_cli_metavar(spec),
                default=argparse.SUPPRESS,
                help=help_text,
            )
            continue
        if spec.kind == "str":
            parser.add_argument(
                spec.option,
                dest=spec.dest,
                type=str,
                metavar=get_cli_metavar(spec),
                default=argparse.SUPPRESS,
                help=help_text,
            )
            continue
        if spec.kind == "list_str":
            parser.add_argument(
                spec.option,
                dest=spec.dest,
                metavar=get_cli_metavar(spec),
                action="append",
                default=argparse.SUPPRESS,
                help=help_text,
            )
            continue
        parser.add_argument(
            spec.option,
            dest=spec.dest,
            metavar=get_cli_metavar(spec),
            action="append",
            type=parse_cli_mapping_entry,
            default=argparse.SUPPRESS,
            help=help_text,
        )


def apply_config_cli_overrides(
    config: dict[str, Any],
    args: argparse.Namespace,
    specs: list[ConfigCliFieldSpec],
) -> dict[str, Any]:
    updated = copy.deepcopy(config)
    for spec in specs:
        if not hasattr(args, spec.dest):
            continue
        value = getattr(args, spec.dest)
        path = tuple(spec.path.split("."))
        if spec.kind == "dict_str_str":
            update_config_mapping_keys(updated, path, value)
            continue
        set_config_path_value(updated, path, value)
    return updated


def get_config_cli_field_specs(default_config: dict[str, Any] | None = None) -> list[ConfigCliFieldSpec]:
    defaults = default_config or get_default_config_dict()
    specs: list[ConfigCliFieldSpec] = []
    for leaf in iterate_model_leaf_fields(SpeakeasyConfig):
        if leaf.path in EXCLUDED_CLI_PATHS:
            continue
        if leaf.path.startswith(EXCLUDED_CLI_PREFIXES):
            continue
        kind = get_cli_kind(leaf.annotation)
        if kind is None:
            continue
        default_value, has_default = get_path_value(defaults, tuple(leaf.path.split(".")))
        if not has_default:
            default_value = leaf.model_default
        if not leaf.description:
            raise ValueError(f"Missing description for CLI config field: {leaf.path}")
        specs.append(
            ConfigCliFieldSpec(
                path=leaf.path,
                option=get_option_name_for_path(leaf.path),
                dest=get_dest_name_for_path(leaf.path),
                kind=kind,
                description=leaf.description,
                default=default_value,
            )
        )
    return specs


def get_config_value_items(model: BaseModel, prefix: tuple[str, ...] = ()) -> Iterator[tuple[str, Any]]:
    for name, field in model.__class__.model_fields.items():
        value = getattr(model, name)
        path = prefix + (name,)
        annotation = unwrap_optional(field.annotation)
        if is_model_type(annotation):
            if isinstance(value, BaseModel):
                yield from get_config_value_items(value, path)
            else:
                yield ".".join(path), value
            continue
        yield ".".join(path), value


def output_active_config(model: SpeakeasyConfig, logger) -> None:
    logger.info("* Active Speakeasy configuration")
    for path, value in get_config_value_items(model):
        logger.info("  %s = %s", path, render_config_value(value))


def get_option_name_for_path(path: str) -> str:
    return "--" + path.replace(".", "-").replace("_", "-")


def get_dest_name_for_path(path: str) -> str:
    return "cfg_" + path.replace(".", "__")


def get_cli_metavar(spec: ConfigCliFieldSpec) -> str:
    if spec.kind == "dict_str_str":
        return "KEY=VALUE"
    if spec.kind == "list_str":
        return "VALUE"
    return spec.path.split(".")[-1].upper()


def get_path_value(data: dict[str, Any], path: tuple[str, ...]) -> tuple[Any, bool]:
    cursor: Any = data
    for part in path:
        if not isinstance(cursor, dict):
            return None, False
        if part not in cursor:
            return None, False
        cursor = cursor[part]
    return cursor, True


def set_config_path_value(data: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor = data
    for part in path[:-1]:
        if not isinstance(cursor.get(part), dict):
            cursor[part] = {}
        cursor = cursor[part]
    cursor[path[-1]] = value


def update_config_mapping_keys(data: dict[str, Any], path: tuple[str, ...], updates: list[tuple[str, str]]) -> None:
    cursor = data
    for part in path[:-1]:
        if not isinstance(cursor.get(part), dict):
            cursor[part] = {}
        cursor = cursor[part]
    target = cursor.get(path[-1])
    if not isinstance(target, dict):
        target = {}
        cursor[path[-1]] = target
    for key, value in updates:
        target[key] = value


def parse_cli_mapping_entry(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise argparse.ArgumentTypeError(f"Invalid mapping {raw!r}; expected KEY=VALUE")
    key, value = raw.split("=", 1)
    if not key:
        raise argparse.ArgumentTypeError(f"Invalid mapping {raw!r}; key is empty")
    return key, value


def render_cli_default(value: Any) -> str:
    if isinstance(value, dict):
        return f"{len(value)} entries"
    if isinstance(value, list):
        return f"{len(value)} items"
    return repr(value)


def render_config_value(value: Any) -> str:
    normalized = normalize_config_value(value)
    if isinstance(normalized, str):
        return normalized
    try:
        return json.dumps(normalized, sort_keys=True)
    except TypeError:
        return repr(normalized)


def normalize_config_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="python")
    if isinstance(value, list):
        return [normalize_config_value(item) for item in value]
    if isinstance(value, tuple):
        return [normalize_config_value(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize_config_value(item) for key, item in value.items()}
    return value


def iterate_model_leaf_fields(model_type: type[BaseModel], prefix: tuple[str, ...] = ()) -> Iterator[_LeafField]:
    for name, field in model_type.model_fields.items():
        annotation = unwrap_optional(field.annotation)
        path = prefix + (name,)
        if is_model_type(annotation):
            yield from iterate_model_leaf_fields(annotation, path)
            continue
        yield _LeafField(
            path=".".join(path),
            annotation=annotation,
            description=field.description,
            model_default=get_field_default(field),
        )


def get_field_default(field) -> Any:
    if field.default is not PydanticUndefined:
        return field.default
    if field.default_factory is not None:
        return field.default_factory()
    return None


def unwrap_optional(annotation: Any) -> Any:
    unwrapped = unwrap_annotated(annotation)
    origin = get_origin(unwrapped)
    if origin in (Union, types.UnionType):
        args = [unwrap_annotated(arg) for arg in get_args(unwrapped) if arg is not type(None)]
        if len(args) == 1:
            return args[0]
    return unwrapped


def unwrap_annotated(annotation: Any) -> Any:
    current = annotation
    while get_origin(current) is Annotated:
        current = get_args(current)[0]
    return current


def is_model_type(annotation: Any) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, BaseModel)


def get_cli_kind(annotation: Any) -> Literal["bool", "int", "float", "str", "list_str", "dict_str_str"] | None:
    target = unwrap_annotated(annotation)
    origin = get_origin(target)
    if target is bool:
        return "bool"
    if target is int:
        return "int"
    if target is float:
        return "float"
    if target is str:
        return "str"
    if origin is list and get_args(target) == (str,):
        return "list_str"
    if origin is dict and get_args(target) == (str, str):
        return "dict_str_str"
    return None
