#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from os.path import dirname, realpath, exists, join
from subprocess import run, DEVNULL
from os import listdir, makedirs
from shlex import quote, split

# mkdir -p html_from_doc; sshfs p1sec@protorisk.p1sec.com:protorisk/fetch/html html_from_doc -C -o allow_other -p47478 -o ro

SCRIPT_DIR = dirname(realpath(__file__))
MODULE_DIR = dirname(realpath(SCRIPT_DIR))
SRC_DIR = dirname(realpath(MODULE_DIR))
ROOT_DIR = dirname(realpath(SRC_DIR))
DATA_DIR = realpath(join(ROOT_DIR, 'data'))

HTML_3GPP_DOCS_PATH = DATA_DIR + '/html_from_doc'
EXTRACTED_CCF_FROM_3GPP_PATH = DATA_DIR + '/ccf_from_html'

if not exists(HTML_3GPP_DOCS_PATH):
    makedirs(HTML_3GPP_DOCS_PATH, exist_ok=True)

if not exists(EXTRACTED_CCF_FROM_3GPP_PATH):
    makedirs(EXTRACTED_CCF_FROM_3GPP_PATH, exist_ok=True)

if not listdir(HTML_3GPP_DOCS_PATH):
    print(
        'Note: going to mount the remote 3GPP .HTML specifications from the Protorisk server, please make sure that you can access the Protorisk server with one of your local public keys'
    )

    run(
        split('fusermount -u ' + quote(HTML_3GPP_DOCS_PATH)),
        check=False,
        stderr=DEVNULL,
        stdout=DEVNULL,
    )
    run(
        split(
            'sshfs p1sec@protorisk:protorisk/data/html '
            + quote(HTML_3GPP_DOCS_PATH)
            + ' -C -o allow_other -o ro'
        ),
        check=True,
    )
