#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

from re import findall, search, match, IGNORECASE, DOTALL, MULTILINE
from lxml.etree import XMLParser, parse, dump, tostring, _Comment
from os.path import dirname, realpath, join
from typing import Set, List, Dict, Union
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


# Ensure that we have messages defined in the CCF
# format and extracted from 3GPP specifications
# at our disposal

most_recent_ccf_extraction_date: int = 0

for file_entry in scandir(EXTRACTED_CCF_FROM_3GPP_PATH):
    most_recent_ccf_extraction_date = max(
        most_recent_ccf_extraction_date, file_entry.stat().st_mtime
    )

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
        command code name is longer than the existing one
        
        @param command_row_dict: Dict resembling DiameterCommand
        @param command_application_row_dict: Dict resembling
            DiameterCommandApplicationOccurrence
        @param source_row_dict: Dict resembling DiameterObjectUpdate
            (without the "object_id" column, because it will be used both
            as a base to set the objects derivating "command_row_dict"
            and "command_application_row_dict")
        @param vendor_row_dict: Dict resembling DiameterVendor
    """

    def create_or_merge_command_code(
        command_row_dict,
        command_application_row_dict,
        source_row_dict: dict,
        vendor_row_dict: dict = None,
    ):

        # Is there an existing row for this command code?

        diameter_command = (
            sql_session.query(DiameterCommand)
            .filter_by(object_id=command_row_dict['object_id'])
            .first()
        )

        object_modified = False

        if not diameter_command:
            sql_session.add(DiameterCommand(**command_row_dict))

            object_modified = True

        else:
            for key, value in command_row_dict.items():
                if (
                    key == 'command_name'
                    and len(value) > len(diameter_command.command_name)
                ) or (
                    value is not None
                    and getattr(diameter_command, key) is None
                ):
                    object_modified = True

                    setattr(diameter_command, key, value)

        if object_modified:
            sql_session.add(
                DiameterObjectUpdate(
                    **source_row_dict, object_id=command_row_dict['object_id']
                )
            )

        if command_application_row_dict:
            # Is there an existing row for this "Command code - Application ID" association?

            diameter_command_to_application = (
                sql_session.query(DiameterCommandApplicationOccurrence)
                .filter_by(object_id=command_application_row_dict['object_id'])
                .first()
            )

            if not diameter_command_to_application:
                sql_session.add(
                    DiameterCommandApplicationOccurrence(
                        **command_application_row_dict
                    )
                )

                sql_session.add(
                    DiameterObjectUpdate(
                        **source_row_dict,
                        object_id=command_application_row_dict['object_id'],
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
                # ⚠️ When the application_id is not
                #  explictly specified, cross-link data
                #  from diameter_application.spec_url
                #  when it matches
                #  'http://www.3gpp.org/DynaReport/%s.htm'
                #  with the code of the current spec
                diameter_application = (
                    sql_session.query(DiameterApplication)
                    .filter_by(spec_url=source_url)
                    .first()
                )
                if diameter_application:
                    application_id = diameter_application.application_id
                else:
                    application_id = None

            req_bit = 'REQ' in header_informations
            pxy_bit = 'PXY' in header_informations
            # err_bit = 'ERR' in header_informations # Not present?

            cmd_code_name = cmd_code_name.strip()

            three_char_prefix_regex = match(
                r'^([A-Z]{2})-([RA])(?:equest|nswer)',
                cmd_code_name,
                flags=MULTILINE,
            )

            command_three_char_abbreviation = None
            if (
                len(cmd_code_name) in (3, 4)
                and cmd_code_name.isupper()
                and '-' not in cmd_code_name
            ):
                command_three_char_abbreviation = cmd_code_name
            elif three_char_prefix_regex:
                command_three_char_abbreviation = (
                    three_char_prefix_regex.group(1)
                    + three_char_prefix_regex.group(2)
                )

            create_or_merge_command_code(
                dict(  # DiameterCommand row
                    object_id='cmd_%d_%d' % (command_code, req_bit),
                    command_code=command_code,
                    req_bit=req_bit,
                    pxy_bit=pxy_bit,
                    command_name=cmd_code_name,
                    command_three_char_abbreviation=command_three_char_abbreviation,
                    **spec_metadata_row_dict,
                ),
                dict(  # DiameterCommandApplicationOccurrence row
                    object_id='cmd_app_%d_%d_%d'
                    % (command_code, req_bit, application_id),
                    application_id=application_id,
                    command_code=command_code,
                )
                if application_id
                else None,
                dict(  # DiameterObjectUpdate without "object_id"
                    #   object_id = 'cmd_%d_%d' % (command_code, req_bit),
                    source=source,
                    source_url=source_url,
                    # source_update_date = ,
                    insertion_date=datetime.now(),
                ),
            )

    """
        Parse command codes extracted from wireshark (XML tags or comments)
    """

    def insert_from_wireshark(
        is_request_bool: bool,
        command_name: str,
        command_trigram: str,
        command_code: int,
        command_vendor_id: int,
        command_vendor_name: str,
        tgpp_ts_code: str,
        itu_code: str,
        rfc_code: str,
        base_tag,
        application_tag,
    ):

        req_bit = int(is_request_bool)

        # Build a row enabling to jump to the corresponding specifications, if available

        spec_information = {}

        if (
            not rfc_code
            and application_tag
            and application_tag.get('uri')
            and 'rfc' in application_tag.get('uri')
        ):
            rfc_code = search(r'rfc([\d+])', application_tag.get('uri')).group(
                1
            )

        if tgpp_ts_code:
            protorisk_spec_object = obtain_spec_from_code(tgpp_ts_code)

            spec_information = dict(
                spec_url='http://www.3gpp.org/DynaReport/%s.htm'
                % tgpp_ts_code.replace('.', ''),
                alternate_spec_url='https://protorisk.p1sec.com/3gpp/%s.html'
                % tgpp_ts_code,
                short_spec_name='%s %s'
                % (protorisk_spec_object.type, protorisk_spec_object.code),
                long_spec_name_prefix='3GPP %s %s'
                % (protorisk_spec_object.type, protorisk_spec_object.code),
                long_spec_name_suffix=protorisk_spec_object.name,
            )

        elif itu_code:
            spec_information = dict(
                spec_url='https://www.itu.int/rec/T-REC-%s' % itu_code,
                alternate_spec_url=None,
                short_spec_name='Rec.' + itu_code,
                long_spec_name_prefix='ITU-T Rec. %s' % (itu_code),
                long_spec_name_suffix=search(
                    r'<title>(.+?)</title>',
                    get('https://www.itu.int/rec/T-REC-%s' % itu_code).text,
                )
                .group(1)
                .split(':', 1)[1]
                .strip(),
            )

        elif rfc_code:
            spec_information = dict(
                spec_url='https://datatracker.ietf.org/doc/html/rfc%s'
                % rfc_code,
                alternate_spec_url=None,
                short_spec_name='RFC ' + rfc_code,
                long_spec_name_prefix='IETF RFC ' + rfc_code,
                long_spec_name_suffix=search(
                    r'<title>(.+?)</title>',
                    get(
                        'https://datatracker.ietf.org/doc/html/rfc%s'
                        % rfc_code
                    ).text,
                    DOTALL,
                )
                .group(1)
                .split('-', 1)[1]
                .strip(),
            )

        # Obtain the Application ID, if available

        application_id: int = None

        if application_tag not in ([], None):
            application_id = int(application_tag.get('id'))

        # Build a SQL row for the corresponding vendor,
        # if any is specified

        vendor_row = None

        if command_vendor_id is not None and command_vendor_name:
            vendor_row = dict(  # DiameterVendor row
                object_id='vendor_%d' % command_vendor_id,
                vendor_id=command_vendor_id,
                vendor_name=command_vendor_name,
            )

        create_or_merge_command_code(
            dict(  # DiameterCommand row
                object_id='cmd_%d_%d' % (command_code, req_bit),
                vendor_id=command_vendor_id,
                command_code=command_code,
                command_name=command_name,
                command_three_char_abbreviation=command_trigram,
                req_bit=is_request_bool,
                pxy_bit=None,
                err_bit=None,
                **spec_information,
            ),
            dict(  # DiameterCommandApplicationOccurrence row
                object_id='cmd_app_%d_%d_%d'
                % (command_code, req_bit, application_id),
                application_id=application_id,
                command_code=command_code,
            )
            if application_id
            else None,
            dict(  # DiameterObjectUpdate without "object_id"
                #   object_id = 'cmd_%d_%d' % (command_code, req_bit),
                source=DiameterDataSource.wireshark_database,
                source_url='https://github.com/wireshark/wireshark/tree/master/resources/protocols/resources/protocols/diameter',
                # source_update_date = ,
                insertion_date=datetime.now(),
            ),
            vendor_row,
        )

    """
        1. Add information from 3GPP+IETF (the best quality information)
    """

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
                    long_spec_name_suffix=protorisk_spec_object.name
                    if tgpp_spec_name
                    else None,
                ),
            )

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
                        '<title>(.+?)</title>',
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

    sql_session.commit()

    """
        2) Add information from Diafuzzer (a subset of the above,
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
        3) Add information from Wireshark
    """

    xml_parser = XMLParser(
        resolve_entities=True
    )  # load_dtd = True, no_network = False

    xml_file = parse(
        WIRESHARK_DATA_DIR + '/' + 'dictionary.xml', parser=xml_parser
    )

    for cmd in xml_file.iterfind('.//command'):
        cmd_id = int(cmd.get('code'))
        cmd_name = cmd.get('name')
        cmd_vendor_id = (
            cmd.get('vendor-id')
            if cmd.get('vendor-id') and cmd.get('vendor-id') != 'None'
            else None
        )  # Vendor ID (string) per the Wireshark meaning

        parent_base_tag = cmd.xpath('ancestor::base')
        parent_application_tag = cmd.xpath('ancestor::application')
        parent_vendor_tag = cmd.xpath('ancestor::vendor')

        print(
            tostring(cmd),
            '/',
            cmd.getnext() if isinstance(cmd.getnext(), _Comment) else None,
            '=>',
            [
                tostring(i).decode('utf8').split('>')[0] + '>'
                for i in parent_base_tag
            ],
            [
                tostring(i).decode('utf8').split('>')[0] + '>'
                for i in parent_application_tag
            ],
        )

        assert parent_vendor_tag == []

        vendor_code: int = None  # Vendor ID (code) per the Diameter meaning
        vendor_name: str = None

        if cmd_vendor_id:
            vendor_tag = xml_file.xpath(
                './/vendor[@vendor-id="%s"]' % cmd_vendor_id
            )[0]

            vendor_code = int(vendor_tag.get('code'))
            vendor_name = vendor_tag.get('name')

        # Is there any reference to a 3GPP specification, a
        # RFC or to three-character command names in an adjacent
        # comment?

        tgpp_ts_code: str = None
        rfc_code: str = None
        itu_code: str = None
        trigram_prefix: str = None  # If the command code trigram pair is AAR/AAA, then store "AA" here

        if isinstance(cmd.getnext(), _Comment):
            comment_text = cmd.getnext().text

            if '\n' not in comment_text:
                if 'TS ' in comment_text:
                    tgpp_ts_code = search(
                        r'TS\s*(\d+\.\d+)', comment_text
                    ).group(1)

                elif 'ITU-T Rec.' in comment_text:
                    itu_code = search(
                        r'ITU(?:-T)?\s*Rec\.*\s*(Q\.[\d.]+)', comment_text
                    ).group(1)

                elif 'RFC' in comment_text:
                    rfc_code = search(r'RFC\s*(\d+)', comment_text).group(1)

                if search(r'[A-Z]{2,}R\s*/\s*[A-Z]{2,}[AI]', comment_text):
                    trigram_prefix = search(
                        r'([A-Z]{2,})R\s*/\s*[A-Z]{2,}[AI]', comment_text
                    ).group(1)

                    # There is a "GPR/GPI" pair in TS 29.230, we'll consider
                    # it as a mistake for "GPR/GPA"

                elif search(r'[A-Z]{2,}[AI]', comment_text):
                    trigram_prefix = search(
                        r'([A-Z]{2,})[AI]', comment_text
                    ).group(1)

        # Split this command in one Request and one Answer
        # occurrence, if needed

        if 'request/answer' in cmd_name.lower():
            assert cmd_name.endswith('-Request/Answer')

            cmd_name = cmd_name.replace('-Request/Answer', '')

        assert 'answer' not in cmd_name.lower()
        assert 'request' not in cmd_name.lower()

        assert cmd_name[-1] != 'A' or cmd_name == 'AA'
        assert cmd_name[-1] != 'R'
        assert '(' not in cmd_name

        for command_name, is_request_bool, command_trigram in [
            (
                cmd_name + '-Request',
                True,
                (trigram_prefix + 'R') if trigram_prefix else None,
            ),
            (
                cmd_name + '-Answer',
                False,
                (trigram_prefix + 'A') if trigram_prefix else None,
            ),
        ]:
            insert_from_wireshark(
                is_request_bool=is_request_bool,
                command_name=command_name,
                command_trigram=command_trigram,
                command_code=cmd_id,
                command_vendor_id=vendor_code,
                command_vendor_name=vendor_name,
                tgpp_ts_code=tgpp_ts_code,
                itu_code=itu_code,
                rfc_code=rfc_code,
                base_tag=parent_base_tag[0] if parent_base_tag != [] else None,
                application_tag=parent_application_tag[0]
                if parent_application_tag != []
                else None,
            )

        # , [tostring(i).split('>')[0] + '>' for i in parent_vendor_tag]

    """
        4) Add information from IANA
    """


finally:
    sql_session.close()
