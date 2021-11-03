#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

import usercustomize

from re import findall, IGNORECASE, MULTILINE, search
from lxml.etree import XMLParser, parse, dump
from os.path import dirname, realpath
from typing import Dict, Set, List
from datetime import datetime
from csv import DictReader
from requests import get
from io import StringIO
from os import listdir
from typing import Set

from database_protorisk import obtain_spec_from_code

SCRIPT_DIR = dirname(realpath(__file__))

OLD_DIAFUZZER_DATA_DIR = realpath(SCRIPT_DIR + '/compare_data_sources/diafuzzer/specs/')
WIRESHARK_DATA_DIR = realpath(SCRIPT_DIR + '/compare_data_sources/wireshark/diameter/')

EXTRACTED_CCF_FROM_3GPP_PATH = realpath(SCRIPT_DIR + '/ccf_from_html')



from database_diameter import *

sql_session = Session()

try:
    
    
    """
        Obtain application IDs from Wireshark
    """

    xml_parser = XMLParser()  # load_dtd = True, no_network = False

    xml_file = parse(WIRESHARK_DATA_DIR + '/' + 'dictionary.xml', parser = xml_parser)

    # dump(xml_file.getroot()) # DEBUG

    # Buffer information through dictionaries so that
    # we can handle when an ID is defined twice (both
    # in the "dictionary.xml" and the vendor files)

    wireshark__application_id_to_name : Dict[int, str] = {}
    wireshark__application_id_to_url : Dict[int, str] = {}

    for app in xml_file.iterfind('.//application'):
        
        if (int(app.get('id')) not in wireshark__application_id_to_name or
            len(app.get('name')) > len(wireshark__application_id_to_name[int(app.get('id'))])):
            
            wireshark__application_id_to_name[int(app.get('id'))] = app.get('name')
            wireshark__application_id_to_url[int(app.get('id'))] = app.get('uri')
    
    for application_id, application_name in wireshark__application_id_to_name.items():
        
        print('DEBUG: adding application ID %s: %s' % (application_id, application_name))
        
        spec_url = wireshark__application_id_to_url[application_id] if '//' in wireshark__application_id_to_url[application_id] else None
        
        alternate_spec_url : str = None
        short_spec_name : str = None
        long_spec_name_prefix : str = None
        long_spec_name_suffix : str = None
        
        if spec_url:
            tgpp_spec_match  = search('3gpp.+?/([\d]{5})\D', spec_url, flags = IGNORECASE)
            rfc_spec_match = search('/rfc(\d+)', spec_url, flags = IGNORECASE)
            if tgpp_spec_match:
                tgpp_spec_code =  tgpp_spec_match.group(1)
                tgpp_spec_code = tgpp_spec_code[:2] + '.' + tgpp_spec_code[2:]
                
                protorisk_spec_object = obtain_spec_from_code(tgpp_spec_code)
                
                alternate_spec_url = 'https://protorisk.p1sec.com/3gpp/%s.html' % tgpp_spec_code
                short_spec_name = '%s %s' % (protorisk_spec_object.type, protorisk_spec_object.code)
                long_spec_name_prefix = ('3GPP %s %s' % (protorisk_spec_object.type, protorisk_spec_object.code))
                long_spec_name_suffix = protorisk_spec_object.name
                
                spec_url = 'http://www.3gpp.org/DynaReport/%s.htm' % tgpp_spec_code.replace('.', '')
            
            elif rfc_spec_match:
                rfc_code =  rfc_spec_match.group(1)
                
                alternate_spec_url = None
                short_spec_name = 'RFC ' + rfc_code
                long_spec_name_prefix = 'IETF RFC ' + rfc_code
                long_spec_name_suffix = search('<title>(.+?)</title>', get('https://tools.ietf.org/html/rfc%s' % rfc_code).text).group(1).split('-', 1)[1].strip()
                
                spec_url = 'https://tools.ietf.org/html/rfc%s' % rfc_code
                
            
        sql_session.add(DiameterApplication(
            object_id = 'app_' + str(application_id),
            application_id = application_id,
            application_name = application_name,
            
            spec_url = spec_url,
            alternate_spec_url = alternate_spec_url,
            short_spec_name = short_spec_name,
            long_spec_name_prefix = long_spec_name_prefix,
            long_spec_name_suffix = long_spec_name_suffix
        ))
        
        sql_session.add(DiameterObjectUpdate(
            object_id = 'app_' + str(application_id),
            source = DiameterDataSource.wireshark_database,
            insertion_date = datetime.now(),
            source_url = 'https://github.com/wireshark/wireshark/tree/master/diameter'
        ))
    
    print('Commiting application IDs from Wireshark...')
    sql_session.commit()
    print('Committed application IDs from Wireshark')
        

    """
        Obtain IANA information in order to fill up missing application IDs
    """
    
    iana_app_ids : Set[int] =  set()

    iana_app_ids_text = get('https://www.iana.org/assignments/aaa-parameters/aaa-parameters-46.csv').text

    for row in DictReader(StringIO(iana_app_ids_text), delimiter = ','):

        if '-' not in row['ID Value']:

            iana_app_ids.add(int(row['ID Value']))
            
            if not sql_session.query(DiameterApplication).filter_by(application_id = int(row['ID Value'])).first():

                sql_session.add(DiameterApplication(
                    object_id = 'app_' + str(row['ID Value']),
                    application_id = int(row['ID Value']),
                    application_name = row['Name']
                ))
                
                sql_session.add(DiameterObjectUpdate(
                    object_id = 'app_' + str(row['ID Value']),
                    source = DiameterDataSource.iana_database,
                    insertion_date = datetime.now(),
                    source_url = 'https://www.iana.org/assignments/aaa-parameters/aaa-parameters.xhtml#aaa-parameters-46'
                ))
    
    sql_session.commit()
    

finally:
    
    sql_session.close()
