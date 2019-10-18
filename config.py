#!/usr/bin/python3
#-*- encoding: utf-8 -*-
from os.path import dirname, realpath, exists
from os import listdir, makedirs
from subprocess import run
from shlex import quote

# mkdir -p html_from_doc; sshfs p1sec@protorisk.p1sec.com:protorisk/fetch/html html_from_doc -C -o allow_other -p47478 -o ro

DIAMETER_DB_DIR = dirname(realpath(__file__))

HTML_3GPP_DOCS_PATH = DIAMETER_DB_DIR + '/html_from_doc'
EXTRACTED_CCF_FROM_3GPP_PATH = DIAMETER_DB_DIR + '/ccf_from_html'

if not exists(HTML_3GPP_DOCS_PATH):
    makedirs(HTML_3GPP_DOCS_PATH, exist_ok = True)

if not exists(EXTRACTED_CCF_FROM_3GPP_PATH):
    makedirs(EXTRACTED_CCF_FROM_3GPP_PATH, exist_ok = True)

if not listdir(HTML_3GPP_DOCS_PATH):
    print('Note: going to mount the remote 3GPP .HTML specifications from the Protorisk server, please make sure that you can access the Protorisk server with one of your local public keys')
    
    # run(('fusermount -u ' + quote(HTML_3GPP_DOCS_PATH)).split(' '), check = True)
    run(('sshfs p1sec@protorisk.p1sec.com:protorisk/fetch/html ' + quote(HTML_3GPP_DOCS_PATH) + ' -C -o allow_other -p47478 -o ro').split(' '), check = True)


