# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing as mp
import os
import shlex
import sys
import time
from typing import TextIO

from rich.console import Console
from rich.logging import RichHandler

from speakeasy import Speakeasy
from speakeasy.cli_config import add_config_cli_arguments, get_active_config, get_config_cli_field_specs
from speakeasy.config import SpeakeasyConfig
from speakeasy.version import __version__

logger = logging.getLogger(__name__)

CHILD_EXIT_GRACE = 5

ChildResult = tuple[str | None, str | None]


def setup_logging(verbose: bool, stream: TextIO | None = None) -> None:
    if stream is None:
        stream = sys.stderr
    root = logging.getLogger("speakeasy")
    root.handlers.clear()
    handler: logging.Handler
    if stream.isatty():
        handler = RichHandler(console=Console(file=stream), show_path=False, show_time=False, show_level=False)
    else:
        # Rich wraps and pads at 80 columns when it cannot get the terminal width, so a pipe or a file gets
        # one record split over many lines.
        handler = logging.StreamHandler(stream)
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


def emulate_binary(
    q,
    exit_event,
    fpath,
    cfg,
    argv,
    do_raw,
    arch="",
    dropped_files_path="",
    raw_offset=0x0,
    entry_point=None,
    verbose=False,
    gdb_port=None,
    gdb_host="127.0.0.1",
):
    setup_logging(verbose)

    report = None
    error = None
    se = None
    try:
        se = Speakeasy(
            config=cfg,
            argv=argv,
            exit_event=exit_event,
            gdb_port=gdb_port,
            gdb_host=gdb_host,
        )
        if do_raw:
            sc_addr = se.load_shellcode(fpath, arch)
            se.run_shellcode(sc_addr, offset=raw_offset or 0)
        else:
            module = se.load_module(fpath)
            se.run_module(module, entry_point=entry_point)
    except Exception as err:
        logger.debug("emulation failed", exc_info=True)
        error = str(err) or type(err).__name__
    finally:
        if se is not None and se.has_emulator:
            try:
                report = se.get_json_report()
            except Exception as err:
                logger.debug("report generation failed", exc_info=True)
                error = error or f"failed to build the report: {err or type(err).__name__}"
        q.put((report, error))

        if dropped_files_path and se is not None and se.has_emulator:
            data = se.create_file_archive()
            if data:
                logger.info("* Saving dropped files archive to %s", dropped_files_path)
                with open(dropped_files_path, "wb") as f:
                    f.write(data)
            else:
                logger.info("* No dropped files found")


def get_child_result(q: mp.Queue[ChildResult], p: mp.Process, wait: float) -> ChildResult | None:
    deadline = time.monotonic() + wait
    while True:
        try:
            return q.get(timeout=max(min(deadline - time.monotonic(), 1), 0.01))
        except mp.queues.Empty:  # type: ignore[attr-defined]
            if not p.is_alive():
                try:
                    return q.get(timeout=1)
                except mp.queues.Empty:  # type: ignore[attr-defined]
                    return None
            if time.monotonic() >= deadline:
                return None


def wait_for_child(q: mp.Queue[ChildResult], p: mp.Process, evt, wall_limit) -> ChildResult:
    """
    Wait for the result of the emulation process and stop it after ``wall_limit`` seconds.

    A child that exits or stops without a result gives an error.
    """
    result = None
    start_time = time.time()
    while True:
        if wall_limit and wall_limit < (time.time() - start_time):
            evt.set()
            logger.error("* Child process timeout reached after %d seconds", wall_limit)
            result = get_child_result(q, p, CHILD_EXIT_GRACE)
            break
        try:
            result = get_child_result(q, p, 1)
            if result is not None or not p.is_alive():
                break
        except KeyboardInterrupt:
            evt.set()
            logger.error("\n* User exited")
            result = get_child_result(q, p, CHILD_EXIT_GRACE)
            break

    if result is None:
        p.join(CHILD_EXIT_GRACE)
        if p.is_alive():
            p.terminate()
    p.join()

    if result is None:
        return None, f"emulation process exited with code {p.exitcode} and sent no report"
    return result


def run_main(parser: argparse.ArgumentParser, args: argparse.Namespace, config_specs) -> str | None:
    target = args.target
    output = args.output
    dropped_files_path = args.dropped_files_path
    config_path = args.config
    do_raw = args.do_raw
    raw_offset = args.raw_offset
    entry_point = args.entry_point
    arch = args.arch
    argv = shlex.split(args.argv) if args.argv else []
    verbose = args.verbose
    gdb_port = args.gdb_port if args.gdb else None
    gdb_host = args.gdb_host

    setup_logging(verbose)

    if args.gdb and not args.no_mp:
        args.no_mp = True
        logger.info("--gdb requires --no-mp mode; enabling automatically")
    user_cfg = {}
    if config_path:
        if not os.path.isfile(config_path):
            parser.error(f"Config file not found: {config_path}")
        with open(config_path) as f:
            user_cfg = json.load(f)

    if do_raw and not arch:
        parser.error("--raw needs --arch")

    try:
        validated = get_active_config(user_cfg, args.volumes, args, config_specs)
    except Exception as err:
        parser.error(f"Invalid active configuration: {err}")

    active_cfg = validated.model_dump(mode="python")
    # The CLI limit stops a child process that hangs in Python code, so it must not stop the child before the
    # emulator limits do. limits.per_run_time applies to each run and the queue can hold any number of runs, so only
    # limits.total_time bounds all runs. When it is 0, the CLI does not stop the child.
    wall_limit = validated.limits.total_time

    if target and not os.path.isfile(target):
        parser.error(f"Target file not found: {target}")

    if not target:
        parser.error("No target file supplied")

    q: mp.Queue[ChildResult] = mp.Queue()
    evt = mp.Event()

    if args.no_mp:
        emulate_binary(
            q,
            evt,
            target,
            active_cfg,
            argv,
            do_raw,
            arch,
            dropped_files_path,
            raw_offset=raw_offset,
            entry_point=entry_point,
            verbose=verbose,
            gdb_port=gdb_port,
            gdb_host=gdb_host,
        )
        result = q.get()
    else:
        p = mp.Process(
            target=emulate_binary,
            args=(
                q,
                evt,
                target,
                active_cfg,
                argv,
                do_raw,
                arch,
                dropped_files_path,
            ),
            kwargs={
                "raw_offset": raw_offset,
                "entry_point": entry_point,
                "verbose": verbose,
                "gdb_port": gdb_port,
                "gdb_host": gdb_host,
            },
        )
        p.start()
        result = wait_for_child(q, p, evt, wall_limit)

    logger.info("* Finished emulating")
    report, error = result

    if report and output:
        logger.info("* Saving emulation report to %s", output)
        with open(output, "w") as f:
            f.write(report)
    elif report:
        print(report)  # noqa: T201
        # A short write stays in the buffer, so flush here to raise inside the try block of main.
        sys.stdout.flush()

    return error


def main():
    parser = argparse.ArgumentParser(description="Emulate a Windows binary with speakeasy", allow_abbrev=False)
    parser.add_argument("-t", "--target", action="store", dest="target", required=False, help="Path of the input file")
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        dest="output",
        required=False,
        help="Path of the report file (default: write the report to stdout)",
    )
    parser.add_argument(
        "--argv",
        action="store",
        default="",
        dest="argv",
        required=False,
        help="Command line arguments of the emulated process, as one quoted string "
        "(e.g. --argv=\"-log -path 'C:\\\\path with spaces\\\\'\")",
    )
    parser.add_argument(
        "-c", "--config", action="store", dest="config", required=False, help="Path of a JSON config file"
    )
    parser.add_argument(
        "--dump-default-config",
        action="store_true",
        dest="dump_default_config",
        required=False,
        help="Print the default config as JSON and exit",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        dest="do_raw",
        required=False,
        help="Emulate the input as shellcode, without PE parsing",
    )
    parser.add_argument(
        "--raw-offset",
        type=lambda s: int(s, 0),
        default=0,
        required=False,
        dest="raw_offset",
        help="Offset in the shellcode at which emulation starts: decimal, or hex with 0x",
    )
    parser.add_argument(
        "--entry-point",
        type=lambda s: int(s, 0),
        default=None,
        required=False,
        dest="entry_point",
        help="RVA at which emulation starts, in place of the entry point of the PE: decimal, or hex with 0x. "
        "Applies only to PE input.",
    )
    parser.add_argument(
        "--arch",
        action="store",
        dest="arch",
        type=str.lower,
        choices=["x86", "x64", "amd64"],
        required=False,
        help="Architecture of the shellcode. Required with --raw.",
    )
    parser.add_argument(
        "--dropped-files-path",
        action="store",
        dest="dropped_files_path",
        required=False,
        help="Path of a zip archive for the files that the sample writes, with a speakeasy_manifest.json",
    )
    parser.add_argument(
        "--no-mp",
        action="store_true",
        dest="no_mp",
        required=False,
        help="Run the emulation in the current process, in place of a child process",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose",
        required=False,
        help="Enable verbose (DEBUG) logging",
    )
    parser.add_argument(
        "--gdb",
        action="store_true",
        dest="gdb",
        required=False,
        help="Start a GDB server and wait for a client before the first instruction. Implies --no-mp.",
    )
    parser.add_argument(
        "--gdb-host",
        action="store",
        dest="gdb_host",
        default="127.0.0.1",
        required=False,
        help="Address on which the GDB server listens (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--gdb-port",
        action="store",
        dest="gdb_port",
        type=int,
        default=1234,
        required=False,
        help="Port on which the GDB server listens (default: 1234)",
    )
    parser.add_argument(
        "-V",
        "--volume",
        action="append",
        dest="volumes",
        default=[],
        help="Map a host path into the emulated file system (host_path:guest_path). Can be given more than once.",
    )
    parser.add_argument("--version", action="version", version=f"speakeasy {__version__}")

    config_specs = get_config_cli_field_specs()
    add_config_cli_arguments(parser, config_specs)

    args = parser.parse_args()
    try:
        if args.dump_default_config:
            print(json.dumps(SpeakeasyConfig().model_dump(mode="json"), indent=4))  # noqa: T201
            # A short write stays in the buffer, so flush here to raise inside the try block.
            sys.stdout.flush()
            return
        error = run_main(parser, args, config_specs)
    except BrokenPipeError:
        # The reader closed stdout. Python flushes stdout again at exit, so point it at devnull to stop a second error.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
    if error:
        logger.error("error: %s", error)
        sys.exit(1)


if __name__ == "__main__":
    main()
