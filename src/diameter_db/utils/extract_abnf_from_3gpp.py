#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

from re import sub, findall, search, IGNORECASE, MULTILINE, DOTALL
from datetime import datetime
from html import unescape
from os.path import join
from os import listdir

from diameter_db.common.config import (
    HTML_3GPP_DOCS_PATH,
    EXTRACTED_CCF_FROM_3GPP_PATH,
)

"""
    We'll extract the custom Diameter ABNF (CCF)
    from all 3GPP specifications, and put these
    in text files
    
    CCF is specified here: https://datatracker.ietf.org/doc/html/rfc6733#section-3.2
"""

CCF_AVP_REGEX = r'(?:[\d\s]*\*[\d\s]*)?(?:\s*\[[^\]]+?\s*\]\s*|\s*<[^>]+?\s*>(?!\s*::)\s*|\s*\{[^\}]*?\s*\}\s*)(?:;[^\n\]\[{}<>*]*[^0-9\n\]\[{}<>*]\s*)?'

CCF_MESSAGE_REGEX = (
    r'<?\s*([^<>\n ]+?)\s*>?\s*::\s*=\s*<\s*Diameter[-\s_]*Header([^>]*?)\s*>'
)
CCF_MESSAGE_REGEX += r'((?:' + CCF_AVP_REGEX + r')+)'

CCF_GROUPED_AVP_REGEX = r'<?\s*([^<>\n ]+?)\s*>?\s*::\s*=\s*<\s*AVP[-\s_]*Header\s*:?\s*([^>]*?)\s*>'
CCF_GROUPED_AVP_REGEX += r'((?:' + CCF_AVP_REGEX + r')+)'

already_processed = set()

for revision in map(
    str, reversed(sorted(map(int, listdir(HTML_3GPP_DOCS_PATH))))
):
    for file_name in listdir(sorted(join(HTML_3GPP_DOCS_PATH, revision))):
        if file_name in already_processed:
            continue
        print(
            '[%s] Scanning %s/%s...'
            % (datetime.now().isoformat(), revision, file_name)
        )

        obtained_ccf_contents = ''

        with open(join(HTML_3GPP_DOCS_PATH, revision, file_name)) as fd:
            file_contents = unescape(
                sub(r'<.+?>', '', fd.read(), flags=DOTALL)
            )
            file_contents = sub(r'\s+', ' ', file_contents)

            if 'diameter' not in file_contents.lower() or (
                not search(
                    r'(?:diameter|avp)[-\s_]*header',
                    file_contents,
                    flags=IGNORECASE,
                )
                and 'is of type' not in file_contents
            ):
                continue  # Optimization

            print('(may contain AVP data)')

            for cmd_code_name, cmd_code_header, cmd_code_elements in findall(
                CCF_MESSAGE_REGEX, file_contents, flags=IGNORECASE
            ):
                print(
                    file_name,
                    '=>',
                    repr((cmd_code_name, cmd_code_header, cmd_code_elements)),
                )

                obtained_ccf_contents += (
                    '< %s > ::= < Diameter-Header%s >\n%s\n\n'
                    % (
                        cmd_code_name,
                        cmd_code_header,
                        '\n'.join(
                            map(
                                str.strip,
                                findall(CCF_AVP_REGEX, cmd_code_elements),
                            )
                        ),
                    )
                )

            for (
                grouped_avp_name,
                grouped_avp_header,
                grouped_avp_elements,
            ) in findall(
                CCF_GROUPED_AVP_REGEX, file_contents, flags=IGNORECASE
            ):
                print(
                    file_name,
                    '=>',
                    repr(
                        (
                            grouped_avp_name,
                            grouped_avp_header,
                            grouped_avp_elements,
                        )
                    ),
                )

                obtained_ccf_contents += (
                    '< %s > ::= < AVP-Header: %s >\n%s\n\n'
                    % (
                        grouped_avp_name,
                        grouped_avp_header.strip(':'),
                        '\n'.join(
                            map(
                                str.strip,
                                findall(CCF_AVP_REGEX, grouped_avp_elements),
                            )
                        ),
                    )
                )

            for plain_text_avp_definition in findall(
                r'The [\w\d-]+ AVP \(AVP Code \d+\) is of type [\w\d-]+',
                file_contents,
                flags=IGNORECASE,
            ):
                obtained_ccf_contents += plain_text_avp_definition + '\n'

        if obtained_ccf_contents:
            with open(
                EXTRACTED_CCF_FROM_3GPP_PATH
                + '/'
                + file_name.rsplit('.', 1)[0]
                + '.ccf',
                'w',
            ) as out_fd:
                out_fd.write(obtained_ccf_contents.strip() + '\n')

            already_processed.add(file_name)
