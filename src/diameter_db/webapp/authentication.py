#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

from quart import session, redirect, request, Response, websocket
from itsdangerous import BadSignature, base64_decode
from csv import DictReader, QUOTE_NONE
from os.path import dirname, realpath
from urllib.parse import quote_plus
from traceback import print_exc
from zlib import decompress
from functools import wraps
from re import sub, search
from hmac import digest
from io import StringIO
from json import loads

from diameter_db.webapp.flask_salt import FLASK_SALT

ID024_EPOCH = 1293840000

"""
    This function provides compatibility with the itsdangerous 0.24
    session cookie format (implemented here:
    https://github.com/pallets/itsdangerous/blob/0.24/itsdangerous.py)
"""


def verify_and_decode_legacy_cookie(payload) -> bytes:

    signed_data = payload.rsplit('.', 1)[0]

    is_compressed = False
    if payload.startswith('.'):
        payload = payload[1:]
        is_compressed = True

    payload, timestamp, signature = map(base64_decode, payload.split('.'))

    if is_compressed:
        payload = decompress(payload)

    payload = loads(payload)

    timestamp = int.from_bytes(timestamp, 'big')

    raw_key = digest(FLASK_SALT.encode('utf-8'), b'cookie-session', 'sha1')

    calculated_signature = digest(raw_key, signed_data.encode('utf-8'), 'sha1')

    if calculated_signature != signature:
        raise BadSignature(
            'Could not check signature correctly for: %r' % payload
        )

    # print(payload, '/', ID024_EPOCH + timestamp, '/', signature.hex())
    # print('=>', calculated_signature.hex())

    return payload


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

    def get_trigram(self, full_name=None):

        full_name = full_name or self.get_full_name()

        tokenized_full_name = full_name.split('(')[0].strip()
        tokenized_full_name = sub(r'[\s-]+', ' ', tokenized_full_name).strip()
        tokenized_full_name = tokenized_full_name.upper().split(' ')

        initials = [token[0] for token in tokenized_full_name]

        if len(initials) > 2:
            return ''.join(initials[:3])

        else:
            return (
                tokenized_full_name[0][0]
                + tokenized_full_name[1][0]
                + tokenized_full_name[1][-1]
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


def is_authenticated():

    is_project_authenticated = (
        session.get('authenticated')
        and session.get('project_user_id')
        and session.get('project_email')
        and session.get('project_full_name')
    )

    if not is_project_authenticated:
        return False

    elif session.get('user_group') in ('p1', 'admin'):
        return True

    return False


def login_required(function):

    @wraps(function)
    async def decorated_function(*args, **kwargs):

        if not is_authenticated():
            return redirect_authentication()

        return await function(*args, **kwargs)

    return decorated_function


# Redirect the user to Protorisk in order
# to handle authentication.


def redirect_authentication():
    # Specify the "force_reauthenticate=1" GET parameter
    # so that when the user is already in on Protorisk,
    # but its OpenProject account-relation information
    # has not been retrieved yet, it can be retrieved
    # and stored in both the database and the session now

    return redirect(
        'https://protorisk.p1sec.com/?return_to='
        + quote_plus(request.url)
        + '&force_reauthenticate=1'
    )
