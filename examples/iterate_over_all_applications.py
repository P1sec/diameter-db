#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from os.path import dirname, realpath
from sys import path

EXAMPLES_DIR = realpath(dirname(__file__))
DIAMETER_DB_DIR = realpath(EXAMPLES_DIR + '/..')

path.append(DIAMETER_DB_DIR)

from database_diameter import *

# Note: certain rare commands may be linked to no application, and will not be displayed by this script

session = Session()
try:
    for application in session.query(DiameterApplication):
        print()
        
        print('Iterating over:', application.application_name)        
        for command in application.commands:
            for avp_occurrence in command.avp_occurrences:
                print('Writing AVP "%s" (code %d) in command "%s"...' % (avp_occurrence.avp.avp_name, avp_occurrence.avp.avp_code, command.command_name))
finally:
    session.close()

