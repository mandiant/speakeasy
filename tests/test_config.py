# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os
import json
import os.path

import unittest
import jsonschema

import speakeasy
import speakeasy.speakeasy


def get_default_config():
    fpath = os.path.join(os.path.dirname(speakeasy.__file__), 'configs', 'default.json')
    with open(fpath, 'r') as ff:
        return json.load(ff)


class TestConfig(unittest.TestCase):
    def test_speakeasy_configs(self):
        '''
        Make sure all of the bundled configs shipped with speakeasy conform
        '''
        config_dir = os.path.join(os.path.dirname(speakeasy.__file__), 'configs')
        self.assertTrue(os.path.isdir(config_dir))
        for fname in os.listdir(config_dir):
            if not fname.endswith('.json'):
                continue
            fpath = os.path.join(config_dir, fname)
            self.assertTrue(os.path.isfile(fpath))
            with open(fpath, 'r') as ff:
                config = json.load(ff)
            speakeasy.speakeasy.validate_config(config)

    def test_validation(self):
        '''
        Tweak the default config, validate that errors are caught
        '''
        conf0 = get_default_config()
        self.assertTrue('emu_engine' in conf0)
        speakeasy.speakeasy.validate_config(conf0)

        # validating a non enum
        conf0['emu_engine'] = 'alternate_engine'
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            speakeasy.speakeasy.validate_config(conf0)

        # validate a missing required field
        conf1 = get_default_config()
        conf1.pop('emu_engine', None)
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            speakeasy.speakeasy.validate_config(conf1)

        # validate an incorrect type
        conf2 = get_default_config()
        conf2['emu_engine'] = 1.0
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            speakeasy.speakeasy.validate_config(conf2)


if __name__ == '__main__':
    unittest.main()
