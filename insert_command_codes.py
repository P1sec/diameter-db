#!/usr/bin/python3.7 -Su
#-*- encoding: Utf-8 -*-

import usercustomize

from re import findall, match, IGNORECASE, MULTILINE
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

from database_protorisk import obtain_spec_from_code

SCRIPT_DIR = dirname(realpath(__file__))

OLD_DIAFUZZER_DATA_DIR = realpath(SCRIPT_DIR + '/compare_data_sources/diafuzzer/specs/')
WIRESHARK_DATA_DIR = realpath(SCRIPT_DIR + '/compare_data_sources/wireshark/diameter/')

EXTRACTED_CCF_FROM_3GPP_PATH = realpath(SCRIPT_DIR + '/ccf_from_html')

"""
    We'll parse the custom Diameter ABNF (CCF)
    from stripped 3GPP specifications (downloaded
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
    
    """
        This function will either create, update or dismiss
        the information into the SQL database, depending
        on whether information is changed and/or the available
        command code name is longer than the existing one
        
        It does not do "sql_session.commit()"
        
        @param command_row_dict: Dict resembling DiameterCommand
        @param command_application_row_dict: Dict resembling
            DiameterCommandApplicationOccurrence
        @param source_row_dict: Dict resembling DiameterObjectUpdate
            (without the "object_id" column, because it will be used both
            as a base to set the objects derivating "command_row_dict"
            and "command_application_row_dict")
    """
    

    
    def create_or_merge_command_code(command_row_dict, command_application_row_dict, source_row_dict : dict):
        
        # Is there an existing row for this command code?
        
        
        diameter_command = sql_session.query(DiameterCommand).filter_by(object_id = command_row_dict['object_id']).first()
        
        object_modified = False
        
        if not diameter_command:
            
            sql_session.add(DiameterCommand(**command_row_dict))
            
            object_modified = True
            
        else:
            
            for key, value in command_row_dict.items():
                    
                if (key == 'command_name' and len(value) > len(diameter_command.command_name)) or (value and not getattr(diameter_command, key)):
                    
                    object_modified = True

                    setattr(diameter_command, key, value)
                    
        
        if object_modified:
        
            sql_session.add(DiameterObjectUpdate(
                **source_row_dict,
                object_id = command_row_dict['object_id']
            ))
            
            
            
        
        
        if command_application_row_dict:
            
            # Is there an existing row for this "Command code - Application ID" association?
            
            diameter_command_to_application = sql_session.query(DiameterCommandApplicationOccurrence).filter_by(object_id = command_application_row_dict['object_id']).first()
            
            if not diameter_command_to_application:
                
                sql_session.add(DiameterCommandApplicationOccurrence(**command_application_row_dict))
                
                sql_session.add(DiameterObjectUpdate(
                    **source_row_dict,
                    object_id = command_row_dict['object_id']
                ))
        
        sql_session.commit()
    
    """
        This function will take a file containing CCF (custom Diameter
        ABNF) command code and AVPs definition, and insert into the
        SQLAlchemy database the command code definitions extracted from
        it
    """
    
    def parse_extracted_ccf(file_contents : str, tgpp_spec_name : str = None):
            
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
                
                cmd_code_name = cmd_code_name.strip()
                
                three_char_prefix_regex = match('^([A-Z]{2})-([RA])(?:equest|nswer)', cmd_code_name, flags = MULTILINE)
                
                command_three_char_abbreviation = None
                if len(cmd_code_name) == 3 and cmd_code_name.isupper():
                    command_three_char_abbreviation = cmd_code_name
                elif three_char_prefix_regex:
                    command_three_char_abbreviation = three_char_prefix_regex.group(1) + three_char_prefix_regex.group(2)
                
                assert tgpp_spec_name.count('.') == 1
                
                if tgpp_spec_name:
                    protorisk_spec_object = obtain_spec_from_code(tgpp_spec_name)

                create_or_merge_command_code(
                    dict( # DiameterCommand row
                        object_id = 'cmd_%d_%d' % (command_code, req_bit),
                        command_code = command_code,
                        req_bit = req_bit,
                        pxy_bit = pxy_bit,
                        command_name = cmd_code_name,
                        command_three_char_abbreviation = command_three_char_abbreviation,
                        
                        spec_url = 'http://www.3gpp.org/DynaReport/%s.htm' % tgpp_spec_name if tgpp_spec_name else None,
                        alternate_spec_url = 'https://protorisk.p1sec.com/3gpp/%s.htm' % tgpp_spec_name if tgpp_spec_name else None,
                        short_spec_name = '%s %s' % (protorisk_spec_object.type, protorisk_spec_object.code) if tgpp_spec_name else None,
                        long_spec_name_prefix = '3GPP %s %s' % (protorisk_spec_object.type, protorisk_spec_object.code) if tgpp_spec_name else None,
                        long_spec_name_suffix = protorisk_spec_object.name if tgpp_spec_name else None
                    ),
                    
                    dict( # DiameterCommandApplicationOccurrence row
                        object_id = 'cmd_app_%d_%d_%d' % (command_code, req_bit, application_id),
                        application_id = application_id,
                        command_code = command_code
                    ) if application_id else None,
                    
                    dict( # DiameterObjectUpdate without "object_id"
                        #   object_id = 'cmd_%d_%d' % (command_code, req_bit),
                        source = DiameterDataSource.tgpp_specifications,
                        source_url = 'http://www.3gpp.org/DynaReport/%s.htm' % tgpp_spec_name,
                        # source_update_date = ,
                        insertion_date = datetime.now()
                    )
                )
                
                # TODO parse AVPs?

    
    
    
    
    """
        1. Add information from 3GPP (the best quality information)
    """
    
    for file_name in listdir(EXTRACTED_CCF_FROM_3GPP_PATH): # ['29.272.html']: # DEBUG
        
        with open(EXTRACTED_CCF_FROM_3GPP_PATH + '/' + file_name) as fd:
            
            file_contents = fd.read()
            
            parse_extracted_ccf(file_contents, file_name.rsplit('.', 1)[0])
                
    sql_session.commit()
    
    """
        2) Add information from Diafuzzer (a subset of 3GPP information
        but also covering IETF specs)
    """
    
    for file_name in listdir(OLD_DIAFUZZER_DATA_DIR): # ['29.272.html']: # DEBUG
        
        with open(OLD_DIAFUZZER_DATA_DIR + '/' + file_name) as fd:
            
            file_contents = fd.read()
            
            parse_extracted_ccf(file_contents)
                
    sql_session.commit()
    
    """
        3) Add information from Wireshark
    """

    xml_parser = XMLParser()  # load_dtd = True, no_network = False

    xml_file = parse(WIRESHARK_DATA_DIR + '/' + 'dictionary.xml', parser = xml_parser)


    for cmd in xml_file.iterfind('.//command'):
        
        cmd_id = int(cmd.get('code'))
        cmd_name = cmd.get('name')
        cmd_vendor_id = cmd.get('vendor-id') if cmd.get('vendor-id') and cmd.get('vendor-id') != 'None' else None
        
        
        parent_base_tag = cmd.xpath('ancestor::base')
        parent_application_tag = cmd.xpath('ancestor::application')
        parent_vendor_tag = cmd.xpath('ancestor::vendor')
        
        print(cmd, '=>', parent_base_tag, parent_application_tag, parent_vendor_tag)

    
    
    """
        4) Add information from IANA
    """
    

finally:
    
    sql_session.close()
