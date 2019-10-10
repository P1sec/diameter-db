#!/usr/bin/python3.7 -Su
#-*- encoding: Utf-8 -*-

import usercustomize

from lxml.etree import XMLParser, parse, dump, tostring, _Comment
from re import findall, search, match, IGNORECASE, MULTILINE
from typing import Set, List, Dict, Union
from os.path import dirname, realpath
from typing import Dict, Set, List
from os import listdir, scandir
from datetime import datetime
from subprocess import run
from csv import DictReader
from requests import get
from io import StringIO
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
        AVP name is longer than the existing one
        
        @param avp_row_dict: Dict resembling DiameterAVPDefinition
        @param list_of_enum_value_row_dicts: List of dicts resembling
            DiameterAVPEnumValue
        @param list_of_grouped_avp_row_dicts: List of dicts resembling
            DiameterNestedAVPOccurrence
        @param source_row_dict: Dict resembling DiameterObjectUpdate
            (without the "object_id" column, because it will be used both
            as a base to set the objects derivating "avp_row_dict"
            and "list_of_enum_value_row_dicts")
        @param vendor_row_dict: Dict resembling DiameterVendor
    """
    

    
    def create_or_merge_avp(avp_row_dict : dict, list_of_enum_value_row_dicts : List[dict], list_of_grouped_avp_row_dicts : List[dict], source_row_dict : dict, vendor_row_dict : dict = None):
        
        # Is there an existing row for this AVP?
        
        
        diameter_avp = sql_session.query(DiameterAVPDefinition).filter_by(object_id = avp_row_dict['object_id']).first()
        
        object_modified = False
        
        if not diameter_avp:
            
            sql_session.add(DiameterAVPDefinition(**avp_row_dict))
            
            object_modified = True
            
        else:
            
            for key, value in avp_row_dict.items():
                    
                if (key == 'avp_name' and len(value) > len(diameter_avp.avp_name)) or (value is not None and getattr(diameter_avp, key) is None):
                    
                    object_modified = True

                    setattr(diameter_avp, key, value)
        
        if object_modified:
        
            sql_session.add(DiameterObjectUpdate(
                **source_row_dict,
                object_id = avp_row_dict['object_id']
            ))
        
        
        # Is there an existing row for this AVP type?
        
        if avp_row_dict['avp_type']:
            
            avp_type_definition_entry = sql_session.query(DiameterAVPTypeDefinition).filter_by(diameter_type_name = avp_row_dict['avp_type']).first()
            
            if not avp_type_definition_entry:
                        
                sql_session.add(DiameterAVPTypeDefinition(
                    object_id = 'avp_type_' + avp_row_dict['avp_type'],
                    diameter_type_name = avp_row_dict['avp_type'],
                ))
                
                sql_session.add(DiameterObjectUpdate(
                    **source_row_dict,
                    object_id = 'avp_type_' + avp_row_dict['avp_type'],
                ))
            
            
                
                
            
        
        
        if list_of_enum_value_row_dicts:
            
            for enum_value_row_dict in list_of_enum_value_row_dicts:
                
                # Is there an existing row for this "AVP Enum ID - AVP Enum Name" association?
                
                diameter_avp_enum_value_row = sql_session.query(DiameterAVPEnumValue).filter_by(object_id = enum_value_row_dict['object_id']).first()
                
                if not diameter_avp_enum_value_row:
                    
                    sql_session.add(DiameterAVPEnumValue(**enum_value_row_dict))
                    
                    sql_session.add(DiameterObjectUpdate(
                        **source_row_dict,
                        object_id = enum_value_row_dict['object_id']
                    ))
                
            
        
            
        
        
        if list_of_grouped_avp_row_dicts:
            
            for grouped_avp_row_dict in list_of_grouped_avp_row_dicts:
                
                # Is there an existing row for this "AVP Enum ID - AVP Enum Name" association?
                
                diameter_grouped_avp_row = sql_session.query(DiameterNestedAVPOccurrence).filter_by(object_id = grouped_avp_row_dict['object_id']).first()
                
                if not diameter_grouped_avp_row:
                    
                    sql_session.add(DiameterNestedAVPOccurrence(**grouped_avp_row_dict))
                    
                    sql_session.add(DiameterObjectUpdate(
                        **source_row_dict,
                        object_id = grouped_avp_row_dict['object_id']
                    ))
                
            
        
        if vendor_row_dict:
            
            # Is there an existing row for this "Vendor ID - Vendor Name" association?
            
            diameter_vendor_row = sql_session.query(DiameterVendor).filter_by(object_id = vendor_row_dict['object_id']).first()
            
            if not diameter_vendor_row:
                
                sql_session.add(DiameterVendor(**vendor_row_dict))
                
                sql_session.add(DiameterObjectUpdate(
                    **source_row_dict,
                    object_id = vendor_row_dict['object_id']
                ))
        
        sql_session.commit()
    
    """
        This function will take a file containing CCF (custom Diameter
        ABNF) command code and AVPs definition, and insert into the
        SQLAlchemy database the command code definitions extracted from
        it
    """
    
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
                    
                    spec_url = 'http://www.3gpp.org/DynaReport/%s.htm' % tgpp_spec_name.replace('.', '') if tgpp_spec_name else None,
                    alternate_spec_url = 'https://protorisk.p1sec.com/3gpp/%s.htm' % tgpp_spec_name if tgpp_spec_name else None,
                    short_spec_name = '%s %s' % (protorisk_spec_object.type, protorisk_spec_object.code) if tgpp_spec_name else None,
                    long_spec_name_prefix = ('3GPP %s %s' % (protorisk_spec_object.type, protorisk_spec_object.code)) if tgpp_spec_name else None,
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
                    source_url = 'http://www.3gpp.org/DynaReport/%s.htm' % tgpp_spec_name.replace('.', ''),
                    # source_update_date = ,
                    insertion_date = datetime.now()
                )
            )
            
            # TODO parse AVPs?
    """

    
    
    """
        1. Add information from 3GPP (the best quality information)
    """
    
    """
    for file_name in listdir(EXTRACTED_CCF_FROM_3GPP_PATH): # ['29.272.html']: # DEBUG
        
        with open(EXTRACTED_CCF_FROM_3GPP_PATH + '/' + file_name) as fd:
            
            file_contents = fd.read()
            
            parse_extracted_ccf(file_contents, file_name.rsplit('.', 1)[0])
                
    sql_session.commit()
    """
    
    """
        2) Add information from Diafuzzer (a subset of 3GPP information
        but also covering IETF specs)
    """
    
    """
    for file_name in listdir(OLD_DIAFUZZER_DATA_DIR): # ['29.272.html']: # DEBUG
        
        with open(OLD_DIAFUZZER_DATA_DIR + '/' + file_name) as fd:
            
            file_contents = fd.read()
            
            parse_extracted_ccf(file_contents)
                
    sql_session.commit()
    """
    
    """
        3) Add information from Wireshark
    """

    xml_parser = XMLParser()  # load_dtd = True, no_network = False

    xml_file = parse(WIRESHARK_DATA_DIR + '/' + 'dictionary.xml', parser = xml_parser)


    for avp_tag in xml_file.iterfind('.//avp'):
            
        grouped_tag = avp_tag.xpath('.//grouped')
        is_grouped : bool = False
        
        if grouped_tag:
            grouped_tag = grouped_tag[0]
            
            is_grouped = True
        
        else:
            type_tag = avp_tag.xpath('.//type')[0]
        
        
        
        
        
                
        
        parent_base_tag = avp_tag.xpath('ancestor::base')
        parent_application_tag = avp_tag.xpath('ancestor::application')
        parent_vendor_tag = avp_tag.xpath('ancestor::vendor')
        

        
        
        # Obtain the Application ID, if available
        
        application_id : int = None
        
        if parent_application_tag:
            
            parent_application_tag  =                 parent_application_tag[0]
            
            application_id = int(parent_application_tag.get('id'))
        
        
        
        # If any source for the application is mentioned, indicate it
        
        spec_information = {}
        
        if parent_application_tag and   parent_application_tag.get('uri'):
            
            spec_information['spec_url'] = parent_application_tag.get('uri')
            spec_information['short_spec_name'] = parent_application_tag.get('name').strip()
            spec_information['long_spec_name_prefix'] = parent_application_tag.get('name').strip()
        
        
        # Evaluate the different information bit flags
        # that may be assigned to a Diameter object
        # (see https://github.com/wireshark/wireshark/blob/master/diameter/dictionary.dtd#L50)
        
        mandatory_flag = None
        if avp_tag.get('mandatory') == 'must':
            mandatory_flag = True
        elif avp_tag.get('mandatory') == 'mustnot':
            mandatory_flag = False
        
        protected_flag = None
        if avp_tag.get('protected') == 'must':
            protected_flag = True
        elif avp_tag.get('protected') == 'mustnot':
            protected_flag = False
        
        vendor_bit = False
        if avp_tag.get('protected') == 'must':
            vendor_bit = True
        
        may_encrypt = True
        if avp_tag.get('may-encrypt') == 'no':
            may_encrypt = False
        
        
        # Build a SQL row for the corresponding vendor,
        # if any is specified
            
        
        vendor_row = None
        command_vendor_id : int = None
        
        if parent_vendor_tag:
            
            
            parent_vendor_tag =         parent_vendor_tag[0]
        
        if not parent_vendor_tag and avp_tag.get('vendor-id') and avp_tag.get('vendor-id') != 'None':
            
            parent_vendor_tag = xml_file.xpath('.//vendor[@vendor-id="%s"]' %    avp_tag.get('vendor-id'))[0]
        
        if parent_vendor_tag:


            command_vendor_id = int(parent_vendor_tag.get('code'))
            vendor_name = parent_vendor_tag.get('name').strip()

            vendor_row =   dict( # DiameterVendor row
                object_id = 'vendor_%d' % command_vendor_id,
                vendor_id = command_vendor_id,
                vendor_name =       vendor_name
            )







        avp_code = int(avp_tag.get('code'))
        
        
        
        
        if grouped_tag:
            
            for avp_index, gavp_tag in enumerate(grouped_tag.xpath('.//gavp')):
                print('=>', gavp_tag,      '      /////////         ',           gavp_tag.get('name').strip(),         ' =====>    DEBUG        ===========>       ', xml_file.xpath('.//avp[@name="%s" or @name="%s "]' % (gavp_tag.get('name').strip(), gavp_tag.get('name').strip())  )        )      #       DEBUG
                
                
                
                
                
                
                
                
                
        
        
        
            
        create_or_merge_avp(
            avp_row_dict = dict( # based on DiameterAvpDefinition
                object_id = 'avp_%d' % int(avp_tag.get('code')),
                
                application_id = application_id,
                vendor_id = command_vendor_id,
                
                mandatory_flag = mandatory_flag,
                protected_flag = protected_flag,
                vendor_specific_flag = vendor_bit,
                
                may_encrypt = may_encrypt,
                
                avp_code = avp_code,
                avp_name = avp_tag.get('name').strip(),
                avp_type = None if is_grouped else type_tag.get('type-name'),
                
                is_grouped = is_grouped,
                
                
                **spec_information
                
            ),
            list_of_enum_value_row_dicts = [dict( #  like DiameterAVPEnumValue
                object_id = 'avp_enum_%d_%d' % (avp_code,  int(enum_tag.get('code'))),
                avp_code = avp_code,
                enum_name_string = enum_tag.get('name').strip(),
                enum_value_integer = int(enum_tag.get('code')),
                
            ) for enum_tag in avp_tag.xpath('.//enum')],
            
            
            
            
            
            list_of_grouped_avp_row_dicts = [dict( #  like DiameterNestedAVPOccurrence
                object_id = 'nested_avp_%d_%d' % (avp_code, int(xml_file.xpath('.//avp[@name="%s" or @name="%s "]' % (gavp_tag.get('name').strip(), gavp_tag.get('name').strip())  )[0].get('code'))),
                parent_avp_code = avp_code,
                avp_index_within_grouped_avp = avp_index,
                
                nested_avp_code = int(xml_file.xpath('.//avp[@name="%s" or @name="%s "]' % (gavp_tag.get('name').strip(), gavp_tag.get('name').strip())  )[0].get('code')),
            ) for avp_index, gavp_tag in enumerate(grouped_tag.xpath('.//gavp'))] if grouped_tag else None,
            
            
            
            
            
            source_row_dict = dict(  # DiameterObjectUpdate without "object_id"
                source = DiameterDataSource.wireshark_database,
                source_url = 'https://github.com/wireshark/wireshark/tree/master/diameter',
                source_information_html_excerpts = None,
                #   source_update_date = ,
                
                insertion_date = datetime.now()
            ),
            
            vendor_row_dict = vendor_row)




        # , [tostring(i).split('>')[0] + '>' for i in parent_vendor_tag]

    
    
    """
        4) Add information from IANA
    """
    

finally:
    
    sql_session.close()
