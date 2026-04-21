#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

from re import findall, search, sub, match, IGNORECASE, DOTALL, MULTILINE
from lxml.etree import XMLParser, parse, dump, tostring, _Comment
from os.path import dirname, realpath, join
from typing import Set, List, Dict, Union
from collections import defaultdict
from typing import Dict, Set, List
from os import listdir, scandir
from datetime import datetime
from subprocess import run
from csv import DictReader
from requests import get
from io import StringIO
from time import time

from diameter_db.common.protorisk_data import obtain_spec_from_code

SCRIPT_DIR = dirname(realpath(__file__))
MODULE_DIR = dirname(realpath(SCRIPT_DIR))
SRC_DIR = dirname(realpath(MODULE_DIR))
ROOT_DIR = dirname(realpath(SRC_DIR))
DATA_DIR = realpath(join(ROOT_DIR, 'data'))

OLD_DIAFUZZER_DATA_DIR = realpath(
    ROOT_DIR + '/compare_data_sources/diafuzzer/specs/'
)
WIRESHARK_DATA_DIR = realpath(
    ROOT_DIR + '/compare_data_sources/wireshark/resources/protocols/diameter/'
)

EXTRACTED_CCF_FROM_3GPP_PATH = realpath(DATA_DIR + '/ccf_from_html')
IETF_RFCS_FOLDER = realpath(DATA_DIR + '/ietf_rfcs')

"""
    We'll parse the custom Diameter ABNF (CCF)
    from stripped 3GPP specifications (downloaded
    by the "./extract_abnf_from_3gpp.py" script
    which will be called if needed) and/or
    resources from Diafuzzer
    
    CCF is specified here: https://datatracker.ietf.org/doc/html/rfc6733#section-3.2
"""

CCF_AVP_REGEX = r'(?:[\d\s]*\*[\d\s]*)?(?:\s*\[[^\]]+?\s*\]\s*|\s*<[^>]+?\s*>(?!\s*::)\s*|\s*\{[^\}]*?\s*\}\s*)(?:;[^\n\]\[{}<>*]*[^0-9\n\]\[{}<>*]\s*)?'

CCF_MESSAGE_REGEX = (
    r'<?\s*([^<>\n ]+?)\s*>?\s*::\s*=\s*<\s*Diameter[-\s_]*Header([^>]*?)\s*>'
)
CCF_MESSAGE_REGEX += r'((?:' + CCF_AVP_REGEX + r')+)'

CCF_GROUPED_AVP_REGEX = r'<?\s*([^<>\n ]+?)\s*>?\s*::\s*=\s*<\s*AVP[-\s_]*Header\s*:?\s*([^>]*?)\s*>'
CCF_GROUPED_AVP_REGEX += r'((?:' + CCF_AVP_REGEX + r')+)'


# Ensure that we have messages defined in the CCF
# format and extracted from 3GPP specifications
# at our disposal

most_recent_ccf_extraction_date: int = None

for file_entry in scandir(EXTRACTED_CCF_FROM_3GPP_PATH):
    most_recent_ccf_extraction_date = file_entry.stat().st_mtime

if (
    not most_recent_ccf_extraction_date
    or most_recent_ccf_extraction_date < time() - 7 * 24 * 60 * 60
):
    print('[+] Downloading the most recent ABNF from the 3GPP...')

    run([SCRIPT_DIR + '/extract_abnf_from_3gpp.py'], check=True)


from diameter_db.common.database import *

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

    def create_or_merge_avp(
        avp_row_dict: dict,
        list_of_enum_value_row_dicts: List[dict],
        list_of_grouped_avp_row_dicts: List[dict],
        source_row_dict: dict,
        vendor_row_dict: dict = None,
    ):

        # Is there an existing row for this AVP?

        diameter_avp = (
            sql_session.query(DiameterAVPDefinition)
            .filter_by(object_id=avp_row_dict['object_id'])
            .first()
        )

        object_modified = False

        if not diameter_avp:
            sql_session.add(DiameterAVPDefinition(**avp_row_dict))

            object_modified = True

        else:
            for key, value in avp_row_dict.items():
                if (
                    key == 'avp_name'
                    and len(value) > len(diameter_avp.avp_name)
                ) or (
                    value is not None and getattr(diameter_avp, key) is None
                ):
                    object_modified = True

                    setattr(diameter_avp, key, value)

        if object_modified:
            sql_session.add(
                DiameterObjectUpdate(
                    **source_row_dict, object_id=avp_row_dict['object_id']
                )
            )

        # Is there an existing row for this AVP type?

        if avp_row_dict['avp_type']:
            avp_type_definition_entry = (
                sql_session.query(DiameterAVPTypeDefinition)
                .filter_by(diameter_type_name=avp_row_dict['avp_type'])
                .first()
            )

            if not avp_type_definition_entry:
                sql_session.add(
                    DiameterAVPTypeDefinition(
                        object_id='avp_type_' + avp_row_dict['avp_type'],
                        diameter_type_name=avp_row_dict['avp_type'],
                    )
                )

                sql_session.add(
                    DiameterObjectUpdate(
                        **source_row_dict,
                        object_id='avp_type_' + avp_row_dict['avp_type'],
                    )
                )

        if list_of_enum_value_row_dicts:
            for enum_value_row_dict in list_of_enum_value_row_dicts:
                # Is there an existing row for this "AVP Enum ID - AVP Enum Name" association?

                diameter_avp_enum_value_row = (
                    sql_session.query(DiameterAVPEnumValue)
                    .filter_by(object_id=enum_value_row_dict['object_id'])
                    .first()
                )

                if not diameter_avp_enum_value_row:
                    sql_session.add(
                        DiameterAVPEnumValue(**enum_value_row_dict)
                    )

                    sql_session.add(
                        DiameterObjectUpdate(
                            **source_row_dict,
                            object_id=enum_value_row_dict['object_id'],
                        )
                    )

        if list_of_grouped_avp_row_dicts:
            for grouped_avp_row_dict in list_of_grouped_avp_row_dicts:
                # Is there an existing row for this "Grouped AVP - Nested AVP" association?

                diameter_grouped_avp_row = (
                    sql_session.query(DiameterNestedAVPOccurrence)
                    .filter_by(object_id=grouped_avp_row_dict['object_id'])
                    .first()
                )

                if not diameter_grouped_avp_row:
                    sql_session.add(
                        DiameterNestedAVPOccurrence(**grouped_avp_row_dict)
                    )

                    sql_session.add(
                        DiameterObjectUpdate(
                            **source_row_dict,
                            object_id=grouped_avp_row_dict['object_id'],
                        )
                    )

        if vendor_row_dict:
            # Is there an existing row for this "Vendor ID - Vendor Name" association?

            diameter_vendor_row = (
                sql_session.query(DiameterVendor)
                .filter_by(object_id=vendor_row_dict['object_id'])
                .first()
            )

            if not diameter_vendor_row:
                sql_session.add(DiameterVendor(**vendor_row_dict))

                sql_session.add(
                    DiameterObjectUpdate(
                        **source_row_dict,
                        object_id=vendor_row_dict['object_id'],
                    )
                )

        sql_session.commit()

    """
        This function will take a file containing CCF (custom Diameter
        ABNF) command code and AVPs definition, and insert into the
        SQLAlchemy database the command code definitions extracted from
        it
    """

    def parse_extracted_ccf(
        file_contents: str,
        source: DiameterDataSource,
        source_url: str,
        spec_metadata_row_dict: dict,
    ):

        for cmd_code_name, cmd_code_header, cmd_code_elements in findall(
            CCF_MESSAGE_REGEX, file_contents, flags=IGNORECASE
        ):
            print(
                'Parse and insert this:',
                repr(
                    (
                        cmd_code_name,
                        cmd_code_header,
                        findall(CCF_AVP_REGEX, cmd_code_elements),
                    )
                ),
            )

            header_informations = list(
                map(
                    str.strip,
                    cmd_code_header.strip('\r\n\t \xa0-:').upper().split(','),
                )
            )

            if header_informations[0] in ('XXX', 'CODE'):
                continue

            command_code = int(header_informations[0])
            if (
                len(header_informations) > 1
                and header_informations[-1].isdigit()
            ):
                application_id = int(header_informations[-1])
            else:
                application_id = None

            req_bit = 'REQ' in header_informations
            pxy_bit = 'PXY' in header_informations
            # err_bit = 'ERR' in header_informations # Not present?

            cmd_code_name = cmd_code_name.strip()

            """
            three_char_prefix_regex = match(r'^([A-Z]{2})-([RA])(?:equest|nswer)', cmd_code_name, flags = MULTILINE)
            
            command_three_char_abbreviation = None
            if len(cmd_code_name) == 3 and cmd_code_name.isupper():
                command_three_char_abbreviation = cmd_code_name
            elif three_char_prefix_regex:
                command_three_char_abbreviation = three_char_prefix_regex.group(1) + three_char_prefix_regex.group(2)
            
            assert tgpp_spec_name.count('.') == 1
            
            if tgpp_spec_name:
                protorisk_spec_object = obtain_spec_from_code(tgpp_spec_name)
            """

            # AVPs are being parsed below

            for avp_index, avp in enumerate(
                findall(CCF_AVP_REGEX, cmd_code_elements)
            ):
                # See here for parsing individual AVP occurrence
                # references: https://datatracker.ietf.org/doc/html/rfc6733#section-3.2

                print(
                    '=====>>>>   DEBUG     AVP      =====+>>>>>>    ',
                    repr(avp),
                )

                min_occurrences: Union[int, None] = None
                max_occurrences: Union[int, None] = None

                min_max_references = match(r'^\s*(\d*)\s*\*\s*(\d*)\s*', avp)
                if min_max_references:
                    if min_max_references.group(1):
                        min_occurrences = int(min_max_references.group(1))
                    if min_max_references.group(2):
                        max_occurrences = int(min_max_references.group(2))
                else:
                    max_occurrences = 1

                avp_requirement: DiameterAVPRequirement = None

                if '<' in avp:
                    avp_requirement = DiameterAVPRequirement.fixed
                    if min_occurrences is None:
                        min_occurrences = 1
                    if max_occurrences is None:
                        max_occurrences = 1
                elif '{' in avp:
                    avp_requirement = DiameterAVPRequirement.required
                    if min_occurrences is None:
                        min_occurrences = 1
                    if max_occurrences is None:
                        max_occurrences = 1
                elif '[' in avp:
                    avp_requirement = DiameterAVPRequirement.optional
                    if min_occurrences is None:
                        min_occurrences = 0
                else:
                    raise ValueError('Invalid AVP definition')

                avp_name = avp.split('[')[-1].split('{')[-1].split('<')[-1]
                avp_name = avp_name.split(']')[0].split('}')[0].split('>')[0]
                avp_name = avp_name.strip()

                if avp_name == 'AVP':
                    continue  # Some forgotten placeholder? (for example: in TS 29.215)

                known_typos_from_rfc_4005 = {
                    'Acounting-Auth-Method': 'Accounting-Auth-Method',
                    'Connection-Info': 'ConnectInfo',
                    'Framed-Appletalk-Link': 'Framed-AppleTalk-Link',
                    'Framed-Appletalk-Network': 'Framed-AppleTalk-Network',
                    'Framed-Appletalk-Zone': 'Framed-AppleTalk-Zone',
                    'Qos-Filter-Rule': 'QoS-Filter-Rule',
                    'Redirect-Host-Usase': 'Redirect-Host-Usage',
                    'Redirected-Host': 'Redirect-Host',
                    'Redirected-Host-Usage': 'Redirect-Host-Usage',
                    'Redirected-Host-Cache-Time': 'Redirect-Max-Cache-Time',
                    'Redirected-Max-Cache-Time': 'Redirect-Max-Cache-Time',
                    # Also this one from RFC5866
                    'Acct-Multisession-Id': 'Acct-Multi-Session-Id',
                    'Authorization-Grace-Period': 'Auth-Grace-Period',
                    'Authorization-Session-Lifetime': 'Authorization-Lifetime',
                    'Redirect-Host-Max-Cache-Time': 'Redirect-Max-Cache-Time',
                    # And from RFC5778
                    'Multi-Round-Time': 'Multi-Round-Time-Out',
                    'MIP-Agent-Info': 'MIP6-Agent-Info',
                    # And from RFC3588
                    'Original-State-Id': 'Origin-State-Id',
                    'Redirect-Host-Cache-Time': 'Redirect-Max-Cache-Time',
                    # RFC4005, RFC7155
                    'Connection-Info': 'Connect-Info',
                    # From TS 29.334
                    'ProSe Subscription-Data': 'ProSe-Subscription-Data',
                    # From TS 29.329
                    'User-Data': 'Sh-User-Data',
                    # From TS 29.*
                    'TWAN-Identifier': '3GPP-TWAN-Identifier',
                    'SM-Delivery- Failure-Cause': 'SM-Delivery-Failure-Cause',
                }

                avp_name = known_typos_from_rfc_4005.get(avp_name, avp_name)

                avp_object = (
                    sql_session.query(DiameterAVPDefinition)
                    .filter_by(avp_name=avp_name)
                    .first()
                )
                if not avp_object and 'Acct' in avp_name:
                    avp_object = (
                        sql_session.query(DiameterAVPDefinition)
                        .filter_by(
                            avp_name=avp_name.replace('Acct', 'Accounting')
                        )
                        .first()
                    )
                elif not avp_object and 'Accounting' in avp_name:
                    avp_object = (
                        sql_session.query(DiameterAVPDefinition)
                        .filter_by(
                            avp_name=avp_name.replace('Accounting', 'Acct')
                        )
                        .first()
                    )

                if not avp_object and ' ' in avp_name:
                    avp_name = avp_name.replace(' ', '')

                    avp_object = (
                        sql_session.query(DiameterAVPDefinition)
                        .filter_by(avp_name=avp_name)
                        .first()
                    )

                if not avp_object:
                    if 'Authorization-Session-Volume' in avp_name:
                        continue  # Defined nowhere  - from RFC 5866

                    if 'Restart-Counter' in avp_name.title():
                        continue  # No attributed code  - from TS  29.816

                    if 'Application-Variant' in avp_name.title():
                        continue  # No attributed code  - from TS  29.909

                    print(
                        'Note:  Dismissing  a reference to an  AVP which is not present in our standard  databases, or defined in a stanard  format in our specifications:  "%s"'
                        % avp_name
                    )
                    continue

                assert avp_object

                avp_code = avp_object.avp_code
                vendor_id = avp_object.vendor_id

                avp_occurrence_row_dict = dict(
                    object_id='cmd_avp_%d_%d_%d_%d'
                    % (command_code, req_bit, avp_code, vendor_id or 0),
                    command_code=command_code,
                    req_bit=req_bit,
                    avp_index_within_command=avp_index,
                    min_occurrences=min_occurrences,
                    max_occurrences=max_occurrences,
                    avp_code=avp_code,
                    avp_vendor_id=vendor_id,
                    avp_object_id='avp_%d_%d' % (avp_code, vendor_id or 0),
                    avp_requirement=avp_requirement,
                    **spec_metadata_row_dict,
                )

                if (
                    not sql_session.query(DiameterCommandAVPOccurrence)
                    .filter_by(object_id=avp_occurrence_row_dict['object_id'])
                    .first()
                ):
                    sql_session.add(
                        DiameterCommandAVPOccurrence(**avp_occurrence_row_dict)
                    )

                    sql_session.add(
                        DiameterObjectUpdate(
                            object_id=avp_occurrence_row_dict['object_id'],
                            source=source,
                            source_url=source_url,
                            source_information_html_excerpts=None,
                            insertion_date=datetime.now(),
                        )
                    )

    """
        This functions takes a plain text RFC and extracts,
        in addition to the CCF (Command Code Format) which is
        extracted further:
        
        -  Grouped AVPs definitions (as defined in
           https://datatracker.ietf.org/doc/html/rfc6733#section-4.4)
        -  AVP types definitions
    """

    def extract_plain_text_avp_definitions_from_spec(
        rfc_contents: str,
        rfc_number: str,
        source: DiameterDataSource,
        source_url: str,
        also_parse_grouped_avps: bool = True,
    ):

        # 1. Parse AVP type definitions

        avp_name_to_code: Dict[str, int] = {}

        for (
            avp_name,
            avp_code,
            avp_section,
            avp_type,
            avp_line_trailer_and_flags,
            next_line_contents,
        ) in findall(
            r'^[ \t\xa0|]*(\S+)[ \t\xa0|]+(\d+)[ \t\xa0|]+(\d+\.[\d\.]+)[ \t\xa0|]+(\S+)(.+)(?=\n(.*))',
            rfc_contents,
            flags=MULTILINE,
        ):
            if avp_name.endswith('-'):  # Truncated AVP name
                next_line = next_line_contents.replace('|', '').strip()

                print(
                    'DEBUG:   using the next line of an AVP definition of a RFC document in order to reconstruct an AVP name split on multiple lines:  ',
                    (
                        avp_name,
                        avp_code,
                        avp_section,
                        avp_type,
                        avp_line_trailer_and_flags,
                        next_line_contents,
                    ),
                )

                assert len(next_line.split()) == 1

                avp_name += next_line

                assert not next_line.endswith('-')

            avp_code = int(avp_code)

            avp_name_to_code[avp_name] = avp_code

            # Create an AVP here only if no data is
            # available in the database, because
            # the information will be less precise
            # (there is no generic way to extract
            # information about AVP flags from RFCs
            # for example)

            if (
                not sql_session.query(DiameterAVPDefinition)
                .filter_by(avp_name=avp_name)
                .first()
            ):
                if (
                    sql_session.query(DiameterAVPDefinition)
                    .filter_by(avp_code=avp_code, vendor_id=None)
                    .first()
                ):
                    print(
                        'WARNING: The AVP with the code "%s" and the name "%s" from RFC %s may conflict with an existing type in base having this code, skipping for now'
                        % (avp_code, avp_name, rfc_number)
                    )

                    continue

                print(
                    'WARNING: The AVP with the code "%s" and the name "%s" is from RFC %s and the vendor ID has been set to 0 by default'
                    % (avp_code, avp_name, rfc_number)
                )

                sql_session.add(
                    DiameterAVPDefinition(
                        object_id='avp_%d_%d' % (avp_code, 0),
                        avp_name=avp_name,
                        avp_code=avp_code,
                        avp_type=avp_type,
                        is_grouped=(avp_type == 'Grouped'),
                    )
                )

                sql_session.add(
                    DiameterObjectUpdate(
                        object_id='avp_%d_%d' % (avp_code, 0),
                        source=source,
                        source_url=source_url,
                        insertion_date=datetime.now(),
                    )
                )

                sql_session.commit()

        # 1b. Parse plain text AVP type definitions

        for avp_name, avp_code, avp_type in findall(
            r'The ([\w\d-]+) AVP \(AVP Code (\d+)\) is of type ([\w\d-]+)',
            rfc_contents,
            flags=IGNORECASE,
        ):
            avp_code = int(avp_code)

            avp_name_to_code[avp_name] = avp_code

            # Create an AVP here only if no data is
            # available in the database, because
            # the information will be less precise
            # (there is no generic way to extract
            # information about AVP flags from RFCs
            # for example)

            if (
                not sql_session.query(DiameterAVPDefinition)
                .filter_by(avp_name=avp_name)
                .first()
            ):
                if (
                    sql_session.query(DiameterAVPDefinition)
                    .filter_by(avp_code=avp_code, vendor_id=None)
                    .first()
                ):
                    print(
                        'WARNING: The AVP with the code "%s" and the name "%s" from RFC %s may conflict with an existing type in base having this code, skipping for now'
                        % (avp_code, avp_name, rfc_number)
                    )

                    continue

                print(
                    'WARNING: The AVP with the code "%s" and the name "%s" is from RFC %s and the vendor ID has been set to 0 by default'
                    % (avp_code, avp_name, rfc_number)
                )

                sql_session.add(
                    DiameterAVPDefinition(
                        object_id='avp_%d_%d' % (avp_code, 0),
                        avp_name=avp_name,
                        avp_code=avp_code,
                        avp_type=avp_type,
                        is_grouped=(avp_type == 'Grouped'),
                    )
                )

                sql_session.add(
                    DiameterObjectUpdate(
                        object_id='avp_%d_%d' % (avp_code, 0),
                        source=source,
                        source_url=source_url,
                        insertion_date=datetime.now(),
                    )
                )

                sql_session.commit()

        if not also_parse_grouped_avps:
            return  # We'll iterate before all the other specs so that we know as much AVPs as possible before it

        # 2. Parse grouped AVP definitions

        for (
            grouped_avp_name,
            grouped_avp_header,
            grouped_avp_elements,
        ) in reversed(
            findall(CCF_GROUPED_AVP_REGEX, rfc_contents, flags=IGNORECASE)
        ):
            grouped_avp_header = grouped_avp_header.strip().split()

            if grouped_avp_header[0] in (
                'xxx',
                '????',
                'XXX',
                'TBD',
                'TBD1',
                'TBD2',
                'x',
            ):
                continue

            grouped_avp_code = int(grouped_avp_header[0].strip(','))

            grouped_avp_vendor_id = None
            if len(grouped_avp_header) > 1:
                grouped_avp_vendor_id = int(grouped_avp_header[1])

            if (
                not sql_session.query(DiameterAVPDefinition)
                .filter_by(avp_name=grouped_avp_name)
                .first()
            ):
                object_id = 'avp_%d_%d' % (
                    grouped_avp_code,
                    grouped_avp_vendor_id or 0,
                )

                existing_row = (
                    sql_session.query(DiameterAVPDefinition)
                    .filter_by(object_id=object_id)
                    .first()
                )
                if existing_row:
                    print(
                        'Note: not inserting duplicate grouped AVP definition which exists under different names: "%s"/"%s"'
                        % (grouped_avp_name, existing_row.avp_name)
                    )

                else:
                    sql_session.add(
                        DiameterAVPDefinition(
                            object_id=object_id,
                            avp_name=grouped_avp_name,
                            avp_code=grouped_avp_code,
                            avp_type='Grouped',
                            vendor_id=grouped_avp_vendor_id,
                            is_grouped=True,
                            vendor_specific_flag=grouped_avp_vendor_id
                            is not None,
                        )
                    )

                    sql_session.add(
                        DiameterObjectUpdate(
                            object_id=object_id,
                            source=source,
                            source_url=source_url,
                            insertion_date=datetime.now(),
                        )
                    )

                    sql_session.commit()

            for nested_avp_index, nested_avp in enumerate(
                findall(CCF_AVP_REGEX, grouped_avp_elements)
            ):
                nested_avp_name = (
                    nested_avp.split('[')[-1].split('{')[-1].split('<')[-1]
                )
                nested_avp_name = (
                    nested_avp_name.split(']')[0].split('}')[0].split('>')[0]
                )
                nested_avp_name = nested_avp_name.strip()

                if (
                    nested_avp_name == 'AVP'
                ):  # This is likely to be a kind of placeholder?
                    continue

                min_occurrences: Union[int, None] = None
                max_occurrences: Union[int, None] = None

                min_max_references = match(
                    r'^\s*(\d*)\s*\*\s*(\d*)\s*', nested_avp
                )
                if min_max_references:
                    if min_max_references.group(1):
                        min_occurrences = int(min_max_references.group(1))
                    if min_max_references.group(2):
                        max_occurrences = int(min_max_references.group(2))
                else:
                    max_occurrences = 1

                avp_requirement: DiameterAVPRequirement = None

                if '<' in nested_avp:
                    avp_requirement = DiameterAVPRequirement.fixed
                    if min_occurrences is None:
                        min_occurrences = 1
                    if max_occurrences is None:
                        max_occurrences = 1
                elif '{' in nested_avp:
                    avp_requirement = DiameterAVPRequirement.required
                    if min_occurrences is None:
                        min_occurrences = 1
                    if max_occurrences is None:
                        max_occurrences = 1
                elif '[' in nested_avp:
                    avp_requirement = DiameterAVPRequirement.optional
                    if min_occurrences is None:
                        min_occurrences = 0

                print(
                    '=>    DEBUG:    trying to fetch nested AVP code from RFC "%s" for "%s"'
                    % (rfc_number, nested_avp_name)
                )

                if nested_avp_name in (
                    'MIP-HA-to-MN-SPI',
                    'MIP-MN-FA-SPI',
                    'MIP-MN-HA-SPI',
                ):
                    continue  # Omissions from RFC   4004

                else:
                    nested_avp = (
                        sql_session.query(DiameterAVPDefinition)
                        .filter_by(avp_name=nested_avp_name)
                        .first()
                    )

                    if nested_avp:
                        nested_avp_code: int = nested_avp.avp_code
                        nested_avp_vendor_id: int = nested_avp.vendor_id or 0

                    elif nested_avp_name in avp_name_to_code:
                        nested_avp_code: int = avp_name_to_code[
                            nested_avp_name
                        ]
                        nested_avp_vendor_id: int = grouped_avp_vendor_id or 0

                    else:
                        print(
                            'NOTE:  Omitting nested AVP which is present in no known CCF definition:   %s'
                            % nested_avp_name
                        )

                        continue

                object_id = 'nested_avp_%d_%d' % (
                    int(grouped_avp_code),
                    nested_avp_code,
                )

                if (
                    not sql_session.query(DiameterNestedAVPOccurrence)
                    .filter_by(object_id=object_id)
                    .first()
                ):
                    sql_session.add(
                        DiameterNestedAVPOccurrence(
                            **{
                                'object_id': object_id,
                                'parent_avp_code': int(grouped_avp_code),
                                'parent_avp_object_id': 'avp_%d_%d'
                                % (
                                    grouped_avp_code,
                                    grouped_avp_vendor_id or 0,
                                ),
                                'avp_index_within_grouped_avp': nested_avp_index,
                                'nested_avp_code': nested_avp_code,
                                'nested_avp_object_id': 'avp_%d_%d'
                                % (nested_avp_code, nested_avp_vendor_id or 0),
                                'min_occurrences': min_occurrences,
                                'max_occurrences': max_occurrences,
                                'avp_requirement': avp_requirement,
                            }
                        )
                    )

                    sql_session.add(
                        DiameterObjectUpdate(
                            object_id=object_id,
                            source=source,
                            source_url=source_url,
                            insertion_date=datetime.now(),
                        )
                    )

                    sql_session.commit()

    """
        This function parses AVP types information contained
        in the Diafuzzer types, excluding CCF (Command Code Format)
        which is extracted further, and including:
        
        - Grouped AVP definitions
        - AVP enum values
        - AVP type definitions
        - AVP vendor definitions
    """

    def parse_diafuzzer_avp_types(diafuzzer_contents: str):

        diafuzzer_contents = sub(
            r'@inherits\s+(.+)',
            lambda match: open(
                OLD_DIAFUZZER_DATA_DIR
                + '/'
                + match.group(1).replace('/', '')
                + '.dia'
            ).read(),
            diafuzzer_contents,
        )

        current_prefix = ''

        avp_name_to_definition: Dict[str, Tuple[str, int, str, str]] = {}
        avp_name_to_vendor_id: Dict[str, int] = {}

        vendor_id_to_name: Dict[int, str] = {}

        enum_type_to_enum_key_to_enum_value: Dict[str, Dict[str, int]] = (
            defaultdict(dict)
        )

        grouped_avp_name_to_nested_avp_occurrence_rows: Dict[
            str, List[dict]
        ] = defaultdict(
            list
        )  # The nested dict is like like DiameterNestedAVPOccurrence

        for line in diafuzzer_contents.split('\n'):
            if line.strip():
                line = line.strip()

                if line[0] == '@':
                    current_prefix = line[1:]

                    if current_prefix.startswith('vendor'):
                        assert len(line.split()) == 3

                        prefix, vendor_id, vendor_name = line.split()

                        vendor_id_to_name[int(vendor_id)] = vendor_name

                else:
                    if current_prefix.startswith('avp_vendor_id'):
                        vendor_id = int(current_prefix.split()[1])

                        assert len(line.split()) == 1

                        avp_name_to_vendor_id[line.strip()] = vendor_id

                    elif current_prefix.startswith('avp_types'):
                        assert len(line.split()) == 4

                        avp_name, avp_code, avp_type, avp_flags = line.split()

                        avp_name_to_definition[avp_name] = (
                            avp_name,
                            int(avp_code),
                            avp_type,
                            avp_flags,
                        )

                    elif current_prefix.startswith('enum'):
                        enum_type = current_prefix.split()[1]

                        assert len(line.split()) == 2

                        enum_key, enum_value = line.split()

                        enum_type_to_enum_key_to_enum_value[enum_type][
                            enum_key
                        ] = int(enum_value)

        for (
            grouped_avp_name,
            grouped_avp_header,
            grouped_avp_elements,
        ) in findall(CCF_GROUPED_AVP_REGEX, file_contents, flags=IGNORECASE):
            grouped_avp_header = grouped_avp_header.strip().split()

            if grouped_avp_header[0] in (
                'xxx',
                '????',
                'XXX',
                'TBD',
                'TBD1',
                'TBD2',
                'x',
            ):
                continue

            grouped_avp_code = int(grouped_avp_header[0].strip(','))

            grouped_avp_vendor_id = None
            if len(grouped_avp_header) > 1:
                grouped_avp_vendor_id = int(grouped_avp_header[1])

            (
                grouped_avp_name,
                grouped_avp_code,
                grouped_avp_type,
                grouped_avp_flags,
            ) = avp_name_to_definition[grouped_avp_name]

            grouped_avp_vendor_id = (
                grouped_avp_vendor_id
                or avp_name_to_vendor_id.get(grouped_avp_name, 0)
            )

            for nested_avp_index, nested_avp in enumerate(
                findall(CCF_AVP_REGEX, grouped_avp_elements)
            ):
                nested_avp_name = (
                    nested_avp.split('[')[-1].split('{')[-1].split('<')[-1]
                )
                nested_avp_name = (
                    nested_avp_name.split(']')[0].split('}')[0].split('>')[0]
                )
                nested_avp_name = nested_avp_name.strip()

                if (
                    nested_avp_name == 'AVP'
                ):  # This is likely to be a kind of placeholder?
                    continue

                (
                    nested_avp_name,
                    nested_avp_code,
                    nested_avp_type,
                    nested_avp_flags,
                ) = avp_name_to_definition[nested_avp_name]

                nested_avp_vendor_id = avp_name_to_vendor_id.get(
                    nested_avp_name, 0
                )

                min_occurrences: Union[int, None] = None
                max_occurrences: Union[int, None] = None

                min_max_references = match(
                    r'^\s*(\d*)\s*\*\s*(\d*)\s*', nested_avp
                )
                if min_max_references:
                    if min_max_references.group(1):
                        min_occurrences = int(min_max_references.group(1))
                    if min_max_references.group(2):
                        max_occurrences = int(min_max_references.group(2))
                else:
                    max_occurrences = 1

                avp_requirement: DiameterAVPRequirement = None

                if '<' in nested_avp:
                    avp_requirement = DiameterAVPRequirement.fixed
                    if min_occurrences is None:
                        min_occurrences = 1
                    if max_occurrences is None:
                        max_occurrences = 1
                elif '{' in nested_avp:
                    avp_requirement = DiameterAVPRequirement.required
                    if min_occurrences is None:
                        min_occurrences = 1
                    if max_occurrences is None:
                        max_occurrences = 1
                elif '[' in nested_avp:
                    avp_requirement = DiameterAVPRequirement.optional
                    if min_occurrences is None:
                        min_occurrences = 0

                grouped_avp_name_to_nested_avp_occurrence_rows[
                    grouped_avp_name
                ].append(
                    {
                        'object_id': 'nested_avp_%d_%d'
                        % (int(grouped_avp_code), nested_avp_code),
                        'parent_avp_code': int(grouped_avp_code),
                        'parent_avp_object_id': 'avp_%d_%d'
                        % (grouped_avp_code, grouped_avp_vendor_id or 0),
                        'avp_index_within_grouped_avp': nested_avp_index,
                        'nested_avp_code': nested_avp_code,
                        'nested_avp_object_id': 'avp_%d_%d'
                        % (nested_avp_code, nested_avp_vendor_id or 0),
                        'min_occurrences': min_occurrences,
                        'max_occurrences': max_occurrences,
                        'avp_requirement': avp_requirement,
                    }
                )

        for (
            avp_name,
            avp_code,
            avp_type,
            avp_flags,
        ) in avp_name_to_definition.values():
            assert ('V' in avp_flags) == (avp_name in avp_name_to_vendor_id)
            assert 'P' not in avp_flags

            vendor_id = None
            vendor_row = None
            if 'V' in avp_flags:
                vendor_id = avp_name_to_vendor_id[avp_name]

                """
                vendor_row =   dict( # DiameterVendor row
                    object_id = 'vendor_%d' % vendor_id,
                    vendor_id = vendor_id,
                    vendor_name =       vendor_id_to_name[vendor_id]
                )
                """
                # ^ the vendor names from Wireshark are likely
                # to already encompass these from Diafuzzer
                # and be better formatted

            create_or_merge_avp(
                avp_row_dict=dict(  # based on DiameterAvpDefinition
                    object_id='avp_%d_%d' % (avp_code, vendor_id or 0),
                    vendor_id=vendor_id,
                    mandatory_flag=(True if 'M' in avp_flags else None),
                    vendor_specific_flag=(True if 'V' in avp_flags else False),
                    avp_code=avp_code,
                    avp_name=avp_name,
                    avp_type=avp_type,
                    is_grouped=True if (avp_type == 'Grouped') else False,
                ),
                list_of_enum_value_row_dicts=[
                    dict(  #  like DiameterAVPEnumValue
                        object_id='avp_enum_%d_%d_%d'
                        % (avp_code, vendor_id or 0, enum_value),
                        avp_code=avp_code,
                        avp_vendor_id=vendor_id,
                        avp_object_id='avp_%d_%d' % (avp_code, vendor_id or 0),
                        enum_name_string=enum_key.strip(),
                        enum_value_integer=enum_value,
                    )
                    for enum_key, enum_value in enum_type_to_enum_key_to_enum_value[
                        avp_name
                    ].items()
                ]
                if avp_name in enum_type_to_enum_key_to_enum_value
                else None,
                list_of_grouped_avp_row_dicts=grouped_avp_name_to_nested_avp_occurrence_rows[
                    avp_name
                ]
                or None,  #  list of dicts like DiameterNestedAVPOccurrence
                source_row_dict=dict(  # DiameterObjectUpdate without "object_id"
                    source=DiameterDataSource.diafuzzer_database,
                    source_url='https://github.com/Orange-OpenSource/diafuzzer/tree/master/specs',
                    source_information_html_excerpts=None,
                    #   source_update_date = ,
                    insertion_date=datetime.now(),
                ),
                vendor_row_dict=vendor_row,
            )

    """
        1) Add information from Wireshark (containg the specification of AVP themselves)
    """

    xml_parser = XMLParser(
        resolve_entities=True
    )  # load_dtd = True, no_network = False

    xml_file = parse(
        WIRESHARK_DATA_DIR + '/' + 'dictionary.xml', parser=xml_parser
    )

    for avp_tag in xml_file.iterfind('.//avp'):
        grouped_tag = avp_tag.xpath('.//grouped')
        is_grouped: bool = False

        if grouped_tag != []:
            grouped_tag = grouped_tag[0]

            is_grouped = True

        else:
            type_tag = avp_tag.xpath('.//type')[0]

        parent_base_tag = avp_tag.xpath('ancestor::base')
        parent_application_tag = avp_tag.xpath('ancestor::application')
        parent_vendor_tag = avp_tag.xpath('ancestor::vendor')

        # Obtain the Application ID, if available

        application_id: int = None

        if parent_application_tag != []:
            parent_application_tag = parent_application_tag[0]

            application_id = int(parent_application_tag.get('id'))

        # If any source for the application is mentioned, indicate it

        spec_information = {}

        if parent_application_tag != [] and parent_application_tag.get('uri'):
            spec_information['spec_url'] = parent_application_tag.get('uri')
            spec_information['short_spec_name'] = parent_application_tag.get(
                'name'
            ).strip()
            spec_information['long_spec_name_prefix'] = (
                parent_application_tag.get('name').strip()
            )

        # Evaluate the different information bit flags
        # that may be assigned to a Diameter object
        # (see https://github.com/wireshark/wireshark/blob/master/resources/protocols/diameter/dictionary.dtd#L50)

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
        avp_vendor_id: int = None

        if parent_vendor_tag != []:
            parent_vendor_tag = parent_vendor_tag[0]

        if (
            parent_vendor_tag == []
            and avp_tag.get('vendor-id')
            and avp_tag.get('vendor-id') != 'None'
        ):
            parent_vendor_tag = xml_file.xpath(
                './/vendor[@vendor-id="%s"]' % avp_tag.get('vendor-id')
            )[0]

        if parent_vendor_tag != []:
            avp_vendor_id = int(parent_vendor_tag.get('code'))
            vendor_name = parent_vendor_tag.get('name').strip()

            vendor_row = dict(  # DiameterVendor row
                object_id='vendor_%d' % avp_vendor_id,
                vendor_id=avp_vendor_id,
                vendor_name=vendor_name,
            )

        avp_code = int(avp_tag.get('code'))

        if avp_tag.get('vendor-bit') in ('mustnot', 'no'):
            # assert not bool(avp_vendor_id)
            avp_vendor_id = None
        elif avp_tag.get('vendor-bit') in ('must', 'yes'):
            assert bool(avp_vendor_id)

        print(
            '=>',
            avp_code,
            '/',
            avp_tag.get('name').strip(),
            '/',
            avp_vendor_id,
            '/',
            vendor_row,
            '/////////////',
            '/',
            parent_vendor_tag,
            '///',
            bool(parent_vendor_tag),
            '///////',
            avp_tag.get('vendor-id'),
            ' DEBUGGGGGGGG  ',
        )

        if grouped_tag != []:
            for avp_index, gavp_tag in enumerate(grouped_tag.xpath('.//gavp')):
                print(
                    '=>',
                    gavp_tag,
                    '      /////////         ',
                    gavp_tag.get('name').strip(),
                    ' =====>    DEBUG        ===========>       ',
                    xml_file.xpath(
                        './/avp[@name="%s" or @name="%s "]'
                        % (
                            gavp_tag.get('name').strip(),
                            gavp_tag.get('name').strip(),
                        )
                    ),
                )  #       DEBUG

        list_of_grouped_avp_row_dicts: List[Dict[str, dict]] = None

        if grouped_tag != []:
            list_of_grouped_avp_row_dicts = []

            for avp_index, gavp_tag in enumerate(grouped_tag.xpath('.//gavp')):
                nested_avp_tag = xml_file.xpath(
                    './/avp[@name="%s" or @name="%s "]'
                    % (
                        gavp_tag.get('name').strip(),
                        gavp_tag.get('name').strip(),
                    )
                )[0]

                if nested_avp_tag.get('vendor-bit') == 'must':
                    nested_avp_vendor_id: Union[int, None] = int(
                        (
                            xml_file.xpath('ancestor::vendor')
                            or xml_file.xpath(
                                'vendor[@vendor-id="%s"]'
                                % nested_avp_tag.get('vendor-id')
                            )
                        )[0].get('code')
                    )
                else:
                    nested_avp_vendor_id: Union[int, None] = None

                list_of_grouped_avp_row_dicts.append(
                    dict(  #  like DiameterNestedAVPOccurrence
                        object_id='nested_avp_%d_%d'
                        % (
                            avp_code,
                            int(
                                xml_file.xpath(
                                    './/avp[@name="%s" or @name="%s "]'
                                    % (
                                        gavp_tag.get('name').strip(),
                                        gavp_tag.get('name').strip(),
                                    )
                                )[0].get('code')
                            ),
                        ),
                        parent_avp_code=avp_code,
                        parent_avp_object_id='avp_%d_%d'
                        % (avp_code, avp_vendor_id or 0),
                        avp_index_within_grouped_avp=avp_index,
                        nested_avp_code=int(nested_avp_tag.get('code')),
                        nested_avp_object_id='avp_%d_%d'
                        % (
                            int(nested_avp_tag.get('code')),
                            nested_avp_vendor_id or 0,
                        ),
                    )
                )

        create_or_merge_avp(
            avp_row_dict=dict(  # based on DiameterAvpDefinition
                object_id='avp_%d_%d'
                % (int(avp_tag.get('code')), avp_vendor_id or 0),
                application_id=application_id,
                vendor_id=avp_vendor_id,
                mandatory_flag=mandatory_flag,
                protected_flag=protected_flag,
                vendor_specific_flag=vendor_bit,
                may_encrypt=may_encrypt,
                avp_code=avp_code,
                avp_name=avp_tag.get('name').strip()
                if avp_tag.get('name') != 'PSR-Address'
                else 'PPR-Address',
                avp_type='Grouped'
                if is_grouped
                else type_tag.get('type-name'),
                is_grouped=is_grouped,
                **spec_information,
            ),
            list_of_enum_value_row_dicts=[
                dict(  #  like DiameterAVPEnumValue
                    object_id='avp_enum_%d_%d_%d'
                    % (
                        avp_code,
                        avp_vendor_id or 0,
                        int(enum_tag.get('code')),
                    ),
                    avp_code=avp_code,
                    avp_vendor_id=avp_vendor_id,
                    avp_object_id='avp_%d_%d' % (avp_code, avp_vendor_id or 0),
                    enum_name_string=enum_tag.get('name').strip(),
                    enum_value_integer=int(enum_tag.get('code')),
                )
                for enum_tag in avp_tag.xpath('.//enum')
            ],
            list_of_grouped_avp_row_dicts=list_of_grouped_avp_row_dicts,
            source_row_dict=dict(  # DiameterObjectUpdate without "object_id"
                source=DiameterDataSource.wireshark_database,
                source_url='https://github.com/wireshark/wireshark/tree/master/resources/protocols/diameter',
                source_information_html_excerpts=None,
                #   source_update_date = ,
                insertion_date=datetime.now(),
            ),
            vendor_row_dict=vendor_row,
        )

        # , [tostring(i).split('>')[0] + '>' for i in parent_vendor_tag]

    """
        2. Add AVP definition from Diafuzzer (the link between
           command codes and AVPs will be made, through parsing
           CCF, at a latter step)
    """

    for file_entry in scandir(OLD_DIAFUZZER_DATA_DIR):
        with open(file_entry.path) as fd:
            file_contents = fd.read()

            parse_diafuzzer_avp_types(file_contents)

    """
        3. Parse AVP definitions present in 3GPP+IETF which were
           not specifications which were not encountered in Wireshark
           or Diafuzzer so far
    """

    for also_parse_grouped_avps in (False, True):
        for file_entry in sorted(
            scandir(IETF_RFCS_FOLDER), key=lambda file_entry: file_entry.name
        ):
            with open(file_entry.path) as fd:
                file_contents = fd.read()

                rfc_number = int(search(r'\d+', file_entry.name).group(0))

                extract_plain_text_avp_definitions_from_spec(
                    file_contents,
                    rfc_number,
                    source=DiameterDataSource.ietf_specifications,
                    source_url='https://datatracker.ietf.org/doc/html/rfc%d'
                    % rfc_number,
                    also_parse_grouped_avps=also_parse_grouped_avps,
                )

        for file_entry in sorted(
            scandir(EXTRACTED_CCF_FROM_3GPP_PATH),
            key=lambda file_entry: (
                '00' if '29.336' in file_entry.name else file_entry.name
            ),
        ):
            with open(file_entry.path) as fd:
                file_contents = fd.read()

                tgpp_spec_name = file_entry.name.rsplit('.', 1)[0]

                extract_plain_text_avp_definitions_from_spec(
                    file_contents,
                    tgpp_spec_name,
                    source=DiameterDataSource.tgpp_specifications,
                    source_url='https://www.3gpp.org/DynaReport/%s.htm'
                    % (tgpp_spec_name.replace('.', '')),
                    also_parse_grouped_avps=also_parse_grouped_avps,
                )

    """
        4. Add information from 3GPP+IETF (containing the list of AVPs for each
           message)
    """

    for file_entry in scandir(IETF_RFCS_FOLDER):
        with open(file_entry.path) as fd:
            file_contents = fd.read()

            rfc_number = int(search(r'\d+', file_entry.name).group(0))

            source_url = (
                'https://datatracker.ietf.org/doc/html/rfc%d' % rfc_number
            )

            parse_extracted_ccf(
                file_contents,
                source=DiameterDataSource.ietf_specifications,
                source_url=source_url,
                spec_metadata_row_dict=dict(
                    spec_url=source_url,
                    short_spec_name='RFC %s' % rfc_number,
                    long_spec_name_prefix=('IETF RFC %s' % rfc_number),
                    long_spec_name_suffix=search(
                        r'<title>(.+?)</title>',
                        get(
                            'https://datatracker.ietf.org/doc/html/rfc%s'
                            % rfc_number
                        ).text,
                        DOTALL,
                    )
                    .group(1)
                    .split('-', 1)[1]
                    .strip(),
                ),
            )

    for file_entry in scandir(EXTRACTED_CCF_FROM_3GPP_PATH):
        with open(file_entry.path) as fd:
            file_contents = fd.read()

            tgpp_spec_name = file_entry.name.rsplit('.', 1)[0]

            protorisk_spec_object = obtain_spec_from_code(tgpp_spec_name)

            source_url = (
                'http://www.3gpp.org/DynaReport/%s.htm'
                % tgpp_spec_name.replace('.', '')
            )

            parse_extracted_ccf(
                file_contents,
                source=DiameterDataSource.tgpp_specifications,
                source_url=source_url,
                spec_metadata_row_dict=dict(
                    spec_url=source_url,
                    alternate_spec_url='https://protorisk.p1sec.com/3gpp/%s.html'
                    % tgpp_spec_name,
                    short_spec_name='%s %s'
                    % (protorisk_spec_object.type, protorisk_spec_object.code),
                    long_spec_name_prefix=(
                        '3GPP %s %s'
                        % (
                            protorisk_spec_object.type,
                            protorisk_spec_object.code,
                        )
                    ),
                    long_spec_name_suffix=protorisk_spec_object.name,
                ),
            )

    sql_session.commit()

    """
        5) Add information from Diafuzzer (a subset of the above,
           originally in an enriched format)
    """

    for file_name in listdir(
        OLD_DIAFUZZER_DATA_DIR
    ):  # ['29.272.html']: # DEBUG
        with open(OLD_DIAFUZZER_DATA_DIR + '/' + file_name) as fd:
            file_contents = fd.read()

            parse_extracted_ccf(
                file_contents,
                source=DiameterDataSource.diafuzzer_database,
                source_url='https://github.com/Orange-OpenSource/diafuzzer/tree/master/specs',
                spec_metadata_row_dict={},
            )

    sql_session.commit()

    """
        6) Also add unused vendor IDs from Wireshark
    """

    for vendor_tag in xml_file.iterfind('.//vendor'):
        avp_vendor_id = int(vendor_tag.get('code'))
        vendor_name = vendor_tag.get('name').strip()

        vendor_row_dict = dict(  # DiameterVendor row
            object_id='vendor_%d' % avp_vendor_id,
            vendor_id=avp_vendor_id,
            vendor_name=vendor_name,
        )

        # Is there an existing row for this "Vendor ID - Vendor Name" association?

        diameter_vendor_row = (
            sql_session.query(DiameterVendor)
            .filter_by(object_id=vendor_row_dict['object_id'])
            .first()
        )

        if not diameter_vendor_row:
            sql_session.add(DiameterVendor(**vendor_row_dict))

            source_row_dict = dict(  # DiameterObjectUpdate without "object_id"
                source=DiameterDataSource.wireshark_database,
                source_url='https://github.com/wireshark/wireshark/tree/master/resources/protocols/diameter',
                source_information_html_excerpts=None,
                #   source_update_date = ,
                insertion_date=datetime.now(),
            )

            sql_session.add(
                DiameterObjectUpdate(
                    **source_row_dict, object_id=vendor_row_dict['object_id']
                )
            )

    sql_session.commit()

    """
        6) Add information from IANA
    """


finally:
    sql_session.close()
