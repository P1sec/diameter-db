#!/usr/bin/python3.7 -Su
#-*- encoding: Utf-8 -*-

import usercustomize

from os.path import dirname, realpath
from sys import path

EXAMPLES_DIR = realpath(dirname(__file__))
DIAMETER_DB_DIR = realpath(EXAMPLES_DIR + '/..')

path.append(DIAMETER_DB_DIR)

from database_diameter import *

session = Session()
try:
    for command in session.query(DiameterCommand):
        print()
        
        if command.applications:
            print('Iterating over command:', command.command_name       , 'from applications', ', '.join('"%s"' % application.application_name for application  in command.applications))        
        else:
            print('Iterating over command:', command.command_name)
        for avp_occurrence in command.avp_occurrences:
            print('Writing AVP "%s" (code %d) in command "%s"...' % (avp_occurrence.avp.avp_name, avp_occurrence.avp.avp_code, command.command_name))
finally:
    session.close()

