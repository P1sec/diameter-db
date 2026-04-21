#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

from os.path import dirname, realpath, join
from sys import path

EXAMPLES_DIR = dirname(realpath(__file__))
ROOT_DIR = dirname(realpath(EXAMPLES_DIR))
SRC_DIR = realpath(join(EXAMPLES_DIR, 'src'))

path.append(SRC_DIR)

from diameter_db.common.database import *

session = Session()
try:
    for command in session.query(DiameterCommand):
        print()

        if command.applications:
            print(
                'Iterating over command:',
                command.command_name,
                'from applications',
                ', '.join(
                    '"%s"' % application.application_name
                    for application in command.applications
                ),
            )
        else:
            print('Iterating over command:', command.command_name)
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
