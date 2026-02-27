# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import argparse
import json
import logging
import multiprocessing as mp
import os
import time

from rich.console import Console
from rich.logging import RichHandler

import speakeasy.winenv.arch as e_arch
from speakeasy import Speakeasy
from speakeasy.cli_config import (
    add_config_cli_arguments,
    apply_config_cli_overrides,
    get_config_cli_field_specs,
    get_default_config_dict,
    merge_config_dicts,
)
from speakeasy.config import SpeakeasyConfig
from speakeasy.volumes import apply_volumes

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool) -> None:
    root = logging.getLogger("speakeasy")
    root.handlers.clear()
    root.addHandler(RichHandler(console=Console(stderr=True), show_path=False))
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


def emulate_binary(
    q,
    exit_event,
    fpath,
    cfg,
    argv,
    do_raw,
    arch="",
    drop_path="",
    dump_path="",
    raw_offset=0x0,
    emulate_children=False,
    verbose=False,
    gdb_port=None,
):
    setup_logging(verbose)

    report = None
    se = None
    try:
        se = Speakeasy(config=cfg, argv=argv, exit_event=exit_event, gdb_port=gdb_port)
        if do_raw:
            arch = arch.lower()
            if arch == "x86":
                arch = e_arch.ARCH_X86
            elif arch in ("x64", "amd64"):
                arch = e_arch.ARCH_AMD64
            else:
                raise Exception(f"Unsupported architecture: {arch}")

            sc_addr = se.load_shellcode(fpath, arch)
            se.run_shellcode(sc_addr, offset=raw_offset or 0)
        else:
            module = se.load_module(fpath)
            se.run_module(module, all_entrypoints=True, emulate_children=emulate_children)
    finally:
        if se is not None:
            report = se.get_json_report()
        q.put(report)

        if dump_path and se is not None:
            data = se.create_memdump_archive()
            logger.info("* Saving memory dump archive to %s", dump_path)
            with open(dump_path, "wb") as f:
                f.write(data)

        if drop_path and se is not None:
            data = se.create_file_archive()
            if data:
                logger.info("* Saving dropped files archive to %s", drop_path)
                with open(drop_path, "wb") as f:
                    f.write(data)
            else:
                logger.info("* No dropped files found")


class Main:
    def __init__(self, parser: argparse.ArgumentParser, args: argparse.Namespace, config_specs) -> None:
        self.target = args.target
        self.output = args.output
        self.dump_path = args.dump_path
        self.drop_files_path = args.drop_files_path
        self.config_path = args.config
        self.emulate_children = args.emulate_children
        self.cfg: dict = {}
        self.do_raw = args.do_raw
        self.raw_offset = args.raw_offset
        self.arch = args.arch
        self.timeout = 0.0
        self.argv = args.params
        self.verbose = args.verbose
        self.gdb_port = args.gdb_port if args.gdb else None

        setup_logging(self.verbose)

        if args.gdb and not args.no_mp:
            args.no_mp = True
            logger.info("--gdb requires --no-mp mode; enabling automatically")

        cfg = get_default_config_dict()

        if self.config_path:
            if not os.path.isfile(self.config_path):
                parser.error(f"Config file not found: {self.config_path}")
            with open(self.config_path) as f:
                user_cfg = json.load(f)
            cfg = merge_config_dicts(cfg, user_cfg)

        if args.volumes:
            apply_volumes(cfg, args.volumes)

        cfg = apply_config_cli_overrides(cfg, args, config_specs)

        try:
            validated = SpeakeasyConfig.model_validate(cfg)
        except Exception as err:
            parser.error(f"Invalid active configuration: {err}")

        self.cfg = validated.model_dump(mode="python")
        self.timeout = float(validated.timeout)

        if self.target and not os.path.isfile(self.target):
            parser.error(f"Target file not found: {self.target}")

        if not self.target:
            parser.error("No target file supplied")

        q: mp.Queue = mp.Queue()
        evt = mp.Event()

        if args.no_mp:
            emulate_binary(
                q,
                evt,
                args.target,
                self.cfg,
                self.argv,
                self.do_raw,
                self.arch,
                self.drop_files_path,
                self.dump_path,
                raw_offset=self.raw_offset,
                emulate_children=self.emulate_children,
                verbose=self.verbose,
                gdb_port=self.gdb_port,
            )
            report = q.get()
        else:
            p = mp.Process(
                target=emulate_binary,
                args=(
                    q,
                    evt,
                    args.target,
                    self.cfg,
                    self.argv,
                    self.do_raw,
                    self.arch,
                    self.drop_files_path,
                    self.dump_path,
                ),
                kwargs={
                    "raw_offset": self.raw_offset,
                    "emulate_children": self.emulate_children,
                    "verbose": self.verbose,
                    "gdb_port": self.gdb_port,
                },
            )
            p.start()

            report = None
            start_time = time.time()
            while True:
                if self.timeout and self.timeout < (time.time() - start_time):
                    evt.set()
                    logger.error("* Child process timeout reached after %d seconds", self.timeout)
                    try:
                        report = q.get(timeout=5)
                    except mp.queues.Empty:  # type: ignore[attr-defined]
                        pass
                    break
                try:
                    report = q.get(timeout=1)
                    break
                except mp.queues.Empty:  # type: ignore[attr-defined]
                    if not p.is_alive():
                        break
                except KeyboardInterrupt:
                    evt.set()
                    logger.error("\n* User exited")
                    try:
                        report = q.get(timeout=5)
                    except mp.queues.Empty:  # type: ignore[attr-defined]
                        pass
                    break

        logger.info("* Finished emulating")

        if report and self.output:
            logger.info("* Saving emulation report to %s", self.output)
            with open(self.output, "w") as f:
                f.write(report)


def main():
    parser = argparse.ArgumentParser(description="Emulate a Windows binary with speakeasy")
    parser.add_argument(
        "-t", "--target", action="store", dest="target", required=False, help="Path to input file to emulate"
    )
    parser.add_argument(
        "-o", "--output", action="store", dest="output", required=False, help="Path to output file to save report"
    )
    parser.add_argument(
        "-p",
        "--params",
        action="store",
        default=[],
        nargs="*",
        dest="params",
        required=False,
        help="Commandline parameters to supply to emulated process (e.g. main(argv))",
    )
    parser.add_argument(
        "-c", "--config", action="store", dest="config", required=False, help="Path to emulator config file"
    )
    parser.add_argument(
        "--dump-default-config",
        action="store_true",
        dest="dump_default_config",
        required=False,
        help="Print built-in default config JSON and exit",
    )
    parser.add_argument(
        "-r",
        "--raw",
        action="store_true",
        dest="do_raw",
        required=False,
        help="Attempt to emulate file as-is with no parsing (e.g. shellcode)",
    )
    parser.add_argument(
        "--raw_offset",
        type=lambda s: int(s, 0x10),
        default=0,
        required=False,
        dest="raw_offset",
        help="When in raw mode, offset (hex) to start emulating",
    )
    parser.add_argument(
        "-a",
        "--arch",
        action="store",
        dest="arch",
        required=False,
        help="Force architecture to use during emulation (for multi-architecture files or shellcode). "
        "Supported archs: [ x86 | amd64 ]",
    )
    parser.add_argument(
        "-d",
        "--dump",
        action="store",
        dest="dump_path",
        required=False,
        help="Path to store compressed memory dump package",
    )
    parser.add_argument(
        "-z",
        "--dropped-files",
        action="store",
        dest="drop_files_path",
        required=False,
        help="Path to store files created during emulation",
    )
    parser.add_argument(
        "-k",
        "--emulate-children",
        action="store_true",
        dest="emulate_children",
        required=False,
        help="Emulate any processes created with CreateProcess APIs after the input file finishes emulating",
    )
    parser.add_argument(
        "--no-mp",
        action="store_true",
        dest="no_mp",
        required=False,
        help="Run emulation in the current process instead of a child process",
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
        help="Enable GDB server stub (pauses before first instruction)",
    )
    parser.add_argument(
        "--gdb-port",
        action="store",
        dest="gdb_port",
        type=int,
        default=1234,
        required=False,
        help="GDB server port (default: 1234)",
    )
    parser.add_argument(
        "-V",
        "--volume",
        action="append",
        dest="volumes",
        default=[],
        help="Mount a host path into the emulated filesystem (host_path:guest_path). May be repeated.",
    )

    config_specs = get_config_cli_field_specs()
    add_config_cli_arguments(parser, config_specs)

    args = parser.parse_args()
    if args.dump_default_config:
        print(json.dumps(get_default_config_dict(), indent=4))
        return
    Main(parser, args, config_specs)


if __name__ == "__main__":
    main()
