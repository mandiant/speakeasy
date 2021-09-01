# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os
import json
import time
import logging
import argparse
import multiprocessing as mp

import speakeasy
from speakeasy import Speakeasy

import speakeasy.winenv.arch as e_arch


def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('speakeasy')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.INFO)

    return logger


def emulate_binary(q, exit_event, fpath, cfg, argv, do_raw, arch='',
        drop_path='', dump_path='', raw_offset=0x0, emulate_children=False):
    """
    Setup the binary for emulation
    """

    logger = get_logger()

    try:
        report = None
        se = Speakeasy(config=cfg, logger=logger, argv=argv, exit_event=exit_event)
        if do_raw:
            arch = arch.lower()
            if arch == 'x86':
                arch = e_arch.ARCH_X86
            elif arch in ('x64', 'amd64'):
                arch = e_arch.ARCH_AMD64
            else:
                raise Exception('Unsupported architecture: %s' % arch)

            sc_addr = se.load_shellcode(fpath, arch)
            se.run_shellcode(sc_addr, offset=raw_offset or 0)
        else:
            module = se.load_module(fpath)
            se.run_module(module, all_entrypoints=True,
                    emulate_children=emulate_children)

    finally:

        report = se.get_json_report()
        q.put(report)

        # If a memory dump was requested, do it now
        if dump_path:
            data = se.create_memdump_archive()
            logger.info('* Saving memory dump archive to %s' % (dump_path))
            with open(dump_path, 'wb') as f:
                f.write(data)

        if drop_path:
            data = se.create_file_archive()
            if data:
                logger.info('* Saving dropped files archive to %s' % (drop_path))
                with open(drop_path, 'wb') as f:
                    f.write(data)
            else:
                logger.info('* No dropped files found')


class Main(object):
    """
    Main class for emulation of Windows shellcode, user mode, and kernel mode binaries
    """
    def __init__(self, parser):
        args = parser.parse_args()
        self.target = args.target
        self.output = args.output
        self.dump_path = args.dump_path
        self.drop_files_path = args.drop_files_path
        self.config_path = args.config
        self.emulate_children = args.emulate_children
        self.cfg = None
        self.do_raw = args.do_raw
        self.raw_offset = args.raw_offset
        self.do_memtrace = args.do_memtrace
        self.module_dir = args.module_dir
        self.arch = args.arch
        self.timeout = 0
        self.argv = args.params
        self.logger = get_logger()

        if not self.config_path:
            self.config_path = './speakeasy/configs/default.json'
        if not os.path.isfile(self.config_path):
            self.config_path = os.path.join(os.path.dirname(speakeasy.__file__),
                                            'configs', 'default.json')
            if not os.path.isfile(self.config_path):
                parser.print_help()
                self.logger.error('[-] No emulator config file supplied')
                return

        with open(self.config_path, 'r') as f:
            self.cfg = json.load(f)
            if args.timeout:
                self.timeout = args.timeout
                self.cfg.update({'timeout': self.timeout})
                self.cfg.update({'max_api_count': self.timeout * 500})
            else:
                self.timeout = self.cfg.get('timeout', 0)

            if self.do_memtrace:
                analysis = self.cfg.get('analysis', {})
                # Override and enable memory tracing
                if analysis:
                    analysis['memory_tracing'] = True
                else:
                    self.cfg.update({'analysis': {'memory_tracing': True}})

            if self.module_dir:
                modules = self.cfg.get('modules', {})
                if modules:
                    modules['module_directory_x86'] = self.module_dir
                    modules['module_directory_x64'] = self.module_dir
                else:
                    self.cfg.update({'modules': {'module_directory_x86': self.module_dir,
                                                 'module_directory_x64': self.module_dir}})

        if self.target and not os.path.isfile(self.target):
            parser.print_help()
            self.logger.error('[-] Target file not found: %s' % (self.target))
            return

        if not self.target:
            parser.print_help()
            self.logger.error('[-] No target file supplied')
            return

        q = mp.Queue()
        evt = mp.Event()

        if args.no_mp:
            # Emulate within the current process, losing some control with execution but
            # allows us to debug speakeasy.
            emulate_binary(q, evt, args.target,
                           self.cfg, self.argv, self.do_raw, self.arch,
                           self.drop_files_path, self.dump_path,
                           raw_offset=self.raw_offset,
                           emulate_children=self.emulate_children)
            report = q.get()
        else:
            # We are using a child process here so we can maintain absolute control over its
            # execution
            p = mp.Process(target=emulate_binary,
                           args=(q, evt, args.target, self.cfg,
                                 self.argv, self.do_raw, self.arch,
                                 self.drop_files_path, self.dump_path),
                           kwargs={
                               "raw_offset": self.raw_offset,
                               "emulate_children": self.emulate_children,
                           })
            p.start()

            report = None
            start_time = time.time()
            while True:
                if self.timeout and self.timeout < (time.time() - start_time):
                    evt.set()
                    self.logger.error('* Child process timeout reached after %d seconds' %
                                      (self.timeout))
                    report = q.get(5)
                try:
                    report = q.get(timeout=1)
                    break
                except mp.queues.Empty:
                    if not p.is_alive():
                        break
                except KeyboardInterrupt:
                    evt.set()
                    self.logger.error('\n* User exited')
                    report = q.get(5)
                    break

        self.logger.info('* Finished emulating')

        if report:
            if self.output:
                self.logger.info('* Saving emulation report to %s' % (self.output))
                with open(self.output, 'w') as f:
                    f.write(report)


def main():
    """ speakeasy command line entrypoint """

    parser = argparse.ArgumentParser(description='Emulate a Windows binary with speakeasy')
    parser.add_argument('-t', '--target', action='store', dest='target',
                        required=False, help='Path to input file to emulate')
    parser.add_argument('-o', '--output', action='store', dest='output',
                        required=False, help='Path to output file to save report')
    parser.add_argument('-p', '--params', action='store', default=[],
                        nargs='*', dest='params', required=False,
                        help='Commandline parameters to supply to emulated '
                             'process (e.g. main(argv))')
    parser.add_argument('-c', '--config', action='store', dest='config',
                        required=False, help='Path to emulator config file')
    parser.add_argument('-m', '--mem-tracing', action='store_true', dest='do_memtrace',
                        required=False, help='Enables memory tracing.\n'
                                             'This will log all memory access by the '
                                             'sample but will impact speed')
    parser.add_argument('-r', '--raw', action='store_true', dest='do_raw',
                        required=False, help='Attempt to emulate file as-is '
                                             'with no parsing (e.g. shellcode)')
    parser.add_argument('--raw_offset', type=lambda s: int(s, 0x10), default=0,
                        required=False, help='When in raw mode, offset (hex) to start emulating')
    parser.add_argument('-a', '--arch', action='store', dest='arch',
                        required=False,
                        help='Force architecture to use during emulation (for '
                             'multi-architecture files or shellcode). '
                             'Supported archs: [ x86 | amd64 ]')
    parser.add_argument('-d', '--dump', action='store', dest='dump_path',
                        required=False, help='Path to store compressed memory dump package')
    parser.add_argument('-q', '--timeout', action='store', dest='timeout', type=int,
                        required=False, help='Emulation timeout in seconds (default 60 sec)')
    parser.add_argument('-z', '--dropped-files', action='store', dest='drop_files_path',
                        required=False, help='Path to store files created during emulation')
    parser.add_argument('-l', '--module-dir', action='store', dest='module_dir',
                        required=False, help='Path to directory containing loadable PE modules.\n'
                                             'When modules are parsed or loaded by samples,\n'
                                             'PEs from this directory will be loaded into the\n'
                                             'emulated address space')
    parser.add_argument('-k', '--emulate-children', action='store_true', dest='emulate_children',
                        required=False, help='Emulate any processes created with\n'
                                             'the CreateProcess APIs after the\n'
                                             'input file finishes emulating')
    parser.add_argument('--no-mp', action='store_true', dest='no_mp',
                        required=False, help='Run emulation in the current process to assist\n'
                                             'instead of a child process. Useful when debugging'
                                             'speakeasy itself (using pdb.set_trace()).\n')

    Main(parser)

if __name__ == "__main__":
    main()
