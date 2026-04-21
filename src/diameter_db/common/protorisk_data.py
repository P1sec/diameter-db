#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from os.path import dirname, realpath, join
from json import load

SCRIPT_DIR = dirname(realpath(__file__))
MODULE_DIR = dirname(realpath(SCRIPT_DIR))
SRC_DIR = dirname(realpath(MODULE_DIR))
ROOT_DIR = dirname(realpath(SRC_DIR))
DATA_DIR = realpath(join(ROOT_DIR, 'data'))

JSON_PATH = realpath(join(DATA_DIR, 'specification_list.json'))

with open(JSON_PATH) as json_file:
    json_data = load(json_file)['all_specifications']

# See https://protorisk.p1sec.com/api
# See https://protorisk.p1sec.com/v1/specification_list.json
# that was download to ../../../data

class Spec:
    type: str  # "TS", "TR", "GSM"...
    code: str  # "27.323"
    name: str

# Used to obtain type, code and name:
# e.g TS 27.002 Diameter something

def obtain_spec_from_code(spec_code) -> Spec:

    spec_entry = json_data[spec_code]

    spec = Spec()
    spec.type = spec_entry['spec_type']
    spec.code = spec_code
    spec.name = spec_entry['title']

    return spec
