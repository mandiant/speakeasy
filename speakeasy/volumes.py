"""Docker-style --volume support for mounting host files into the emulated filesystem."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath


def parse_volume_spec(spec: str) -> tuple[Path, PureWindowsPath]:
    """Parse a ``host_path:guest_path`` volume specification.

    Handles Windows drive-letter colons on both sides (e.g.
    ``C:\\samples:C:\\guest``).  The real separator is the first ``:``
    that is NOT the second character of a drive-letter prefix.
    """
    if not spec:
        raise ValueError("Empty volume specification")

    # Find the separator colon.  Skip a leading drive letter (X:) on the
    # host side, then look for the next colon.
    start = 0
    if len(spec) >= 2 and spec[1] == ":":
        # Host path starts with a drive letter — skip past it.
        start = 2

    idx = spec.find(":", start)
    if idx == -1:
        raise ValueError(f"Invalid volume spec (missing ':' separator): {spec!r}")

    host_str = spec[:idx]
    guest_str = spec[idx + 1 :]

    if not host_str:
        raise ValueError(f"Empty host path in volume spec: {spec!r}")
    if not guest_str:
        raise ValueError(f"Empty guest path in volume spec: {spec!r}")

    return Path(host_str), PureWindowsPath(guest_str)


def expand_volume_to_entries(host_path: Path, guest_path: PureWindowsPath) -> list[dict]:
    """Expand a volume mapping into ``FileEntryFullPath``-compatible dicts.

    If *host_path* is a file, one entry is returned.  If it is a
    directory, every file underneath it (recursively) becomes an entry
    with the relative path appended to *guest_path*.
    """
    host_path = host_path.resolve()

    if not host_path.exists():
        raise FileNotFoundError(f"Volume host path does not exist: {host_path}")

    entries: list[dict] = []

    if host_path.is_file():
        entries.append(
            {
                "mode": "full_path",
                "emu_path": str(guest_path),
                "path": str(host_path),
            }
        )
    elif host_path.is_dir():
        for child in sorted(host_path.rglob("*")):
            if not child.is_file():
                continue
            rel = child.relative_to(host_path)
            emu_path = guest_path / PureWindowsPath(*rel.parts)
            entries.append(
                {
                    "mode": "full_path",
                    "emu_path": str(emu_path),
                    "path": str(child),
                }
            )

    return entries


def apply_volumes(config: dict, volume_specs: list[str]) -> dict:
    """Parse *volume_specs* and prepend the resulting file entries to *config*.

    Entries are prepended so they win first-match resolution in
    ``get_emu_file()``.
    """
    if not volume_specs:
        return config

    new_entries: list[dict] = []
    for spec in volume_specs:
        host_path, guest_path = parse_volume_spec(spec)
        new_entries.extend(expand_volume_to_entries(host_path, guest_path))

    fs = config.setdefault("filesystem", {})
    existing = fs.get("files", [])
    fs["files"] = new_entries + existing

    return config
