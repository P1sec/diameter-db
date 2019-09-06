#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from re import findall, IGNORECASE, MULTILINE
from lxml.etree import XMLParser, parse, dump
from os.path import dirname, realpath
from typing import Dict, Set, List
from os import listdir, scandir
from datetime import datetime
from subprocess import run
from csv import DictReader
from requests import get
from io import StringIO
from typing import Set
from time import time

SCRIPT_DIR = dirname(realpath(__file__))

OLD_DIAFUZZER_DATA_DIR = realpath(SCRIPT_DIR + '/compare_data_sources/diafuzzer/specs/')
WIRESHARK_DATA_DIR = realpath(SCRIPT_DIR + '/compare_data_sources/wireshark/diameter/')

EXTRACTED_CCF_FROM_3GPP_PATH = realpath(SCRIPT_DIR + '/ccf_from_html')

"""
    We'll parse the custom Diameter ABNF (CCF)
    from stripped 3GPP speciications (downloaded
    by the "./extract_abnf_from_3gpp.py" script
    which will be called if needed) and/or
    resources from Diafuzzer
    
    CCF is specified here: https://tools.ietf.org/html/rfc6733#section-3.2
"""

CCF_AVP_REGEX = '(?:[\d\s]*\*[\d\s]*)?(?:\s*\[[^\]]+?\s*\]\s*|\s*<[^>]+?\s*>\s*(?!::\s*=)|\s*\{[^\}]*?\s*\}\s*)'

CCF_MESSAGE_REGEX = r'<\s*([^>]+?)\s*>\s*::\s*=\s*<\s*Diameter[-\s_]*Header([^>]*?)\s*>'
CCF_MESSAGE_REGEX += r'((?:' + CCF_AVP_REGEX + ')+)'



# Ensure that we have messages defined in the CCF
# format and extracted from 3GPP specifications
# at our disposal

most_recent_ccf_extraction_date : int = None

for file_entry in scandir(EXTRACTED_CCF_FROM_3GPP_PATH):
    
    most_recent_ccf_extraction_date = file_entry.stat().st_mtime

if not most_recent_ccf_extraction_date or most_recent_ccf_extraction_date < time() - 7 * 24 * 60 * 60:
    
    print('[+] Downloading the most recent ABNF from the 3GPP...')
    
    run([SCRIPT_DIR + '/extract_abnf_from_3gpp.py'], check = True)


from database_diameter import *

sql_session = Session()

try:
    
    for file_name in listdir(EXTRACTED_CCF_FROM_3GPP_PATH): # ['29.272.html']: # DEBUG
        
        with open(EXTRACTED_CCF_FROM_3GPP_PATH + '/' + file_name) as fd:
            
            file_contents = fd.read()
            
            for cmd_code_name, cmd_code_header, cmd_code_elements in findall(CCF_MESSAGE_REGEX, file_contents, flags = IGNORECASE):
                print('Parse and insert this:', repr((cmd_code_name, cmd_code_header, findall(CCF_AVP_REGEX, cmd_code_elements))))
                
                header_informations = list(map(str.strip, cmd_code_header.strip('\r\n\t \xa0-:').upper().split(',')))
                
                if header_informations[0] in ('XXX', 'CODE'):
                    continue
                
                command_code = int(header_informations[0])
                if len(header_informations) > 1 and header_informations[-1].isdigit():
                    application_id = int(header_informations[-1])
                else:
                    application_id = None
                
                req_bit = 'REQ' in header_informations
                pxy_bit = 'PXY' in header_informations
                # err_bit = 'ERR' in header_informations # Not present?
                
                DiameterCommand(
                    object_id = 'cmd_%d_%d' % (command_code, req_bit),
                    req_bit = req_bit,
                    pxy_bit = pxy_bit,
                    application_id = application_id
                )
                
                # TODO parse AVPs?
                
    sql_session.commit()
    

finally:
    
    sql_session.close()
