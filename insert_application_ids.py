#!/usr/bin/python3.7 -Su
#-*- encoding: Utf-8 -*-

import usercustomize

from re import findall, IGNORECASE, MULTILINE
from lxml.etree import XMLParser, parse, dump
from os.path import dirname, realpath
from typing import Dict, Set, List
from datetime import datetime
from csv import DictReader
from requests import get
from io import StringIO
from os import listdir
from typing import Set

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
        
        print('DEBUG: adding application ID %s: %s' % (str(app.get('id')), str(app.get('name'))))
        
        sql_session.add(DiameterApplication(
            object_id = 'app_' + str(application_id),
            application_id = application_id,
            application_name = application_name,
            spec_url = wireshark__application_id_to_url[application_id]
        ))
        
        sql_session.add(DiameterObjectUpdate(
            object_id = 'app_' + str(app.get('id')),
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
