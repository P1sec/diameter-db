#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

from os.path import dirname, realpath, join
from sys import path

EXAMPLES_DIR = dirname(realpath(__file__))
ROOT_DIR = dirname(realpath(EXAMPLES_DIR))
SRC_DIR = realpath(join(EXAMPLES_DIR, 'src'))

path.append(SRC_DIR)

from diameter_db.common.database import *

# Note: certain rare commands may be linked to no application, and will not be displayed by this script

session = Session()
try:
    for application in session.query(DiameterApplication):
        print()

        print('Iterating over:', application.application_name)
        for command in application.commands:
            for avp_occurrence in command.avp_occurrences:
                print(
                    'Writing AVP "%s" (code %d) in command "%s"...'
                    % (
                        avp_occurrence.avp.avp_name,
                        avp_occurrence.avp.avp_code,
                        command.command_name,
                    )
                )
finally:
    session.close()
