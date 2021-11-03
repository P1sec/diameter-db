#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from quart import session, redirect, request, Response, websocket
from csv import DictReader, QUOTE_NONE
from os.path import dirname, realpath
from urllib.parse import quote_plus
from traceback import print_exc
from functools import wraps
from re import sub, search
from io import StringIO




"""

    This is a wrapper class allowing to retrieve information
    relating the current OpenProject user which access the
    application, such as it name, e-mail or trigram.
"""

class OpenProjectUser:
    
    def __init__(self):
        
        self.session = session._get_current_object()
    
    def get_full_name(self):
        
        if session.get('project_full_name'):
            
            return self.session['project_full_name'].split('(')[0].strip()
    
    def get_trigram(self, full_name = None):
        
        full_name = full_name or self.get_full_name()
        
        tokenized_full_name = full_name.split('(')[0].strip()
        tokenized_full_name = sub('[\s-]+', ' ', tokenized_full_name).strip()
        tokenized_full_name = tokenized_full_name.upper().split(' ')
        
        initials = [token[0] for token in tokenized_full_name]
        
        if len(initials) > 2:
            return ''.join(initials[:3])
        
        else:
            return (
                tokenized_full_name[0][0] +
                tokenized_full_name[1][0] +
                tokenized_full_name[1][-1]
            )
    
    def get_email(self):
        
        return self.session['project_email']
    


"""
    Authentication-related functions
"""

# Check whether the user is authenticated,
# and the session cookies contains OpenProjet
# account-related information, such as the e-mail,
# user ID and full name of the user (previously
# it was not the case)

async def is_authenticated():
    
    is_project_authenticated = (session.get('authenticated') and
        session.get('project_user_id') and
        session.get('project_email') and
        session.get('project_full_name'))
    
    if not is_project_authenticated:
        return False
    
    elif session.get('user_group') in ('p1', 'admin'):
        return True
    
    return False

def login_required(function):
    
    @wraps(function)
    async def decorated_function(*args, **kwargs):
        
        if not await is_authenticated():
            return redirect_authentication()
        
        return await function(*args, **kwargs)
    
    #          decorated_function.__wrapped__ = function
    
    return decorated_function


# Redirect the user to Protorisk in order
# to handle authentication.

def redirect_authentication():
    # Specify the "force_reauthenticate=1" GET parameter
    # so that when the user is already in on Protorisk,
    # but its OpenProject account-relation information
    # has not been retrieved yet, it can be retrieved
    # and stored in both the database and the session now
        
    return redirect('https://protorisk.p1sec.com/?return_to=' + quote_plus(request.url.replace('http://', 'https://')) + '&force_reauthenticate=1')
