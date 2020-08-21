# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os
import json
import lzma
import multiprocessing as mp

from speakeasy import Speakeasy


def get_test_bin_path(bin_name):
    fp = os.path.join(os.path.dirname(__file__), 'bins', bin_name)
    return fp


def get_test_bin_data(bin_name):
    fp = get_test_bin_path(bin_name)
    with lzma.open(fp) as f:
        file_content = f.read()
    return file_content


def get_config():
    fp = os.path.join(os.path.dirname(__file__), 'test.json')
    with open(fp, 'r') as f:
        return json.load(f)


def _run_module(q, cfg, target, logger, argv):
    se = Speakeasy(config=cfg, logger=logger, argv=argv)
    module = se.load_module(data=target)
    se.run_module(module, all_entrypoints=True)
    report = se.get_report()
    q.put(report)


def run_test(cfg, target, logger=None, argv=[]):

    q = mp.Queue()
    p = mp.Process(target=_run_module, args=(q, cfg, target, logger, argv))
    p.start()
    return q.get()
