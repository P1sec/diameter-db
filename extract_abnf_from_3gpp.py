#!/usr/bin/python3.7 -Su
#-*- encoding: Utf-8 -*-

import usercustomize

from re import sub, findall, IGNORECASE, MULTILINE, DOTALL
from html import unescape
from os import listdir

from config import HTML_3GPP_DOCS_PATH, EXTRACTED_CCF_FROM_3GPP_PATH

"""
    We'll extract the custom Diameter ABNF (CCF)
    from all 3GPP specifications, and put these
    in text files
    
    CCF is specified here: https://tools.ietf.org/html/rfc6733#section-3.2
"""

CCF_AVP_REGEX = '(?:[\d\s]*\*[\d\s]*)?(?:\s*\[[^\]]+?\s*\]\s*|\s*<[^>]+?\s*>\s*(?!::\s*=)|\s*\{[^\}]*?\s*\}\s*)'

CCF_MESSAGE_REGEX = r'<\s*([^>]+?)\s*>\s*::\s*=\s*<\s*Diameter[-\s_]*Header([^>]*?)\s*>'
CCF_MESSAGE_REGEX += r'((?:' + CCF_AVP_REGEX + ')+)'

for file_name in listdir(HTML_3GPP_DOCS_PATH): # ['29.272.html']: # DEBUG
    
    obtained_ccf_contents = ''
    
    with open(HTML_3GPP_DOCS_PATH + '/' + file_name) as fd:
        
        file_contents = unescape(sub('<.+?>', '', fd.read()))
        file_contents = sub('\s+', ' ', file_contents)
        
        for cmd_code_name, cmd_code_header, cmd_code_elements in findall(CCF_MESSAGE_REGEX, file_contents, flags = IGNORECASE):
            print(file_name, '=>', repr((cmd_code_name, cmd_code_header, cmd_code_elements)))
            
            obtained_ccf_contents += '< %s > ::= < Diameter-Header%s >\n%s\n\n' % (cmd_code_name, cmd_code_header, '\n'.join(map(str.strip, findall(CCF_AVP_REGEX, cmd_code_elements))))
    
    if obtained_ccf_contents:
        
        with open(EXTRACTED_CCF_FROM_3GPP_PATH + '/' + file_name.rsplit('.', 1)[0] + '.ccf', 'w') as out_fd:
            
            out_fd.write(obtained_ccf_contents.strip() + '\n')
        
