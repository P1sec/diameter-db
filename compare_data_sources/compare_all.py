#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from re import findall, IGNORECASE, MULTILINE
from lxml.etree import XMLParser, DTD, parse, dump
from os.path import dirname, realpath
from csv import DictReader
from requests import get
from io import StringIO
from os import listdir
from typing import Set

SCRIPT_DIR = dirname(realpath(__file__))

OLD_DIAFUZZER_DATA_DIR = realpath(SCRIPT_DIR + '/diafuzzer/specs/')
WIRESHARK_DATA_DIR = realpath(SCRIPT_DIR + '/wireshark/diameter/')

EXTRACTED_CCF_FROM_3GPP_PATH = realpath(SCRIPT_DIR + '/../data/ccf_from_html')

old_diafuzzer_avp_ids: Set[int] = set()
old_diafuzzer_cmd_ids: Set[int] = set()
old_diafuzzer_app_ids: Set[int] = set()

wireshark_avp_ids: Set[int] = set()
wireshark_cmd_ids: Set[int] = set()
wireshark_app_ids: Set[int] = set()

iana_app_ids: Set[int] = set()
iana_cmd_ids: Set[int] = set()
iana_avp_ids: Set[int] = set()

"""
    First, parse all known Diafuzzer AVPs, command codes and application IDs
"""

for spec_file in listdir(OLD_DIAFUZZER_DATA_DIR):
    with open(OLD_DIAFUZZER_DATA_DIR + '/' + spec_file) as fd:
        spec_contents = fd.read()

        for command_code_id, application_id in findall(
            r'<\s*Diameter[\s-]*Header\s*:\s*(\d+).+?(\d+)\s*>',
            spec_contents,
            flags=IGNORECASE,
        ):
            old_diafuzzer_cmd_ids.add(int(command_code_id))
            old_diafuzzer_app_ids.add(int(application_id))

        for avp_id in findall(
            r'^[\w-]+\s+(\d+)\s+\S+\s+', spec_contents, flags=MULTILINE
        ):
            old_diafuzzer_avp_ids.add(int(avp_id))

"""
    Complete Diafuzzer information with information from
    CCF code contained in recent 3GPP specs as we know
    that we will be able to rely on it
"""

cmd_ids_only_in_live_3gpp = set()

for file_name in listdir(EXTRACTED_CCF_FROM_3GPP_PATH):
    with open(EXTRACTED_CCF_FROM_3GPP_PATH + '/' + file_name) as fd:
        ccf_data = fd.read()

        for cmd_code, app_id in findall(
            r'Diameter[ -]Header\s*:\s*(\d+).+?(\d+)\s*>',
            ccf_data,
            flags=IGNORECASE,
        ):
            old_diafuzzer_cmd_ids.add(int(cmd_code))
            old_diafuzzer_app_ids.add(int(app_id))

            cmd_ids_only_in_live_3gpp.add(int(cmd_code))

        for command_code_id in findall(
            r'<\s*Diameter[\s-]*Header\s*:\s*(\d+)', ccf_data, flags=IGNORECASE
        ):
            old_diafuzzer_cmd_ids.add(int(command_code_id))

            cmd_ids_only_in_live_3gpp.add(int(cmd_code))


"""
    Then, do the same with Wireshark XML files
"""

xml_parser = XMLParser(
    resolve_entities=True
)  # load_dtd = True, no_network = False

xml_file = parse(
    WIRESHARK_DATA_DIR + '/' + 'dictionary.xml', parser=xml_parser
)

# dump(xml_file.getroot()) # DEBUG

for avp in xml_file.iterfind('.//avp'):
    wireshark_avp_ids.add(int(avp.get('code')))

for app in xml_file.iterfind('.//application'):
    wireshark_app_ids.add(int(app.get('id')))

for cmd in xml_file.iterfind('.//command'):
    wireshark_cmd_ids.add(int(cmd.get('code')))

"""
    Obtain IANA information for comparison
"""

iana_app_ids_text = get(
    'https://www.iana.org/assignments/aaa-parameters/aaa-parameters-46.csv'
).text

for row in DictReader(StringIO(iana_app_ids_text), delimiter=','):
    if '-' not in row['ID Value']:
        iana_app_ids.add(int(row['ID Value']))

iana_cmd_ids_text = get(
    'https://www.iana.org/assignments/aaa-parameters/aaa-parameters-47.csv'
).text

for row in DictReader(StringIO(iana_cmd_ids_text), delimiter=','):
    if '-' not in row['Code Value']:
        iana_cmd_ids.add(int(row['Code Value']))

iana_avp_ids_text = get(
    'https://www.iana.org/assignments/aaa-parameters/aaa-parameters-1.csv'
).text

for row in DictReader(StringIO(iana_avp_ids_text), delimiter=','):
    if '-' not in row['AVP Code']:
        iana_avp_ids.add(int(row['AVP Code']))

print(
    'AVPs only in old Diafuzzer:',
    sorted(old_diafuzzer_avp_ids - wireshark_avp_ids),
)
print(
    'AVPs only in Wireshark:',
    sorted(wireshark_avp_ids - old_diafuzzer_avp_ids),
)
print('All AVPs in Diafuzzer:', sorted(old_diafuzzer_avp_ids))
print(
    'AVPs codes in IANA but not in Wireshark:',
    sorted(iana_avp_ids - wireshark_avp_ids),
)
print(
    'AVPs codes in Wireshark but not in IANA:',
    sorted(wireshark_avp_ids - iana_avp_ids),
)

print(
    'Command codes only in Diafuzzer + refreshed 3GPP specs:',
    sorted(old_diafuzzer_cmd_ids - wireshark_cmd_ids),
)
print(
    'Command codes only in refreshed 3GPP specs but not Diafuzzer:',
    sorted(old_diafuzzer_cmd_ids - wireshark_cmd_ids),
)
print(
    'Command codes only in Wireshark:',
    sorted(wireshark_cmd_ids - old_diafuzzer_cmd_ids),
)
print(
    'Command codes in IANA but not in Wireshark:',
    sorted(iana_cmd_ids - wireshark_cmd_ids),
)
print(
    'Command codes in Wireshark but not in IANA:',
    sorted(wireshark_cmd_ids - iana_cmd_ids),
)

print(
    'Application IDs only in Diafuzzer + refreshed 3GPP specs:',
    sorted(old_diafuzzer_app_ids - wireshark_app_ids),
)
print(
    'Application IDs only in Wireshark:',
    sorted(wireshark_app_ids - old_diafuzzer_app_ids),
)

print()
print('# of AVPs in Diafuzzer:', len(sorted(old_diafuzzer_avp_ids)))
print('# of AVPs in Wireshark:', len(sorted(wireshark_avp_ids)))
print('# of AVPs in IANA:', len(sorted(iana_avp_ids)))
print(
    '# of Command codes in Diafuzzer + refreshed 3GPP specs:',
    len(sorted(old_diafuzzer_cmd_ids)),
)
print('# of Command codes in Wireshark:', len(sorted(wireshark_cmd_ids)))
print('# of Command codes in IANA:', len(sorted(iana_cmd_ids)))
print(
    '# of Application IDs in Diafuzzer + refreshed 3GPP specs:',
    len(sorted(old_diafuzzer_app_ids)),
)
print('# of Application IDs in Wireshark:', len(sorted(wireshark_app_ids)))
print('# of Application IDs in IANA:', len(sorted(iana_app_ids)))
print()
