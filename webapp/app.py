#!/usr/bin/python3.7 -Su
#-*- encoding: Utf-8 -*-

import usercustomize

from quart import Quart as Flask, request, redirect, render_template, session, send_from_directory, abort, Response, send_file, redirect, jsonify
from argparse import ArgumentParser
from os.path import dirname, realpath
from itsdangerous import BadSignature
from typing import List, Union, Dict, Tuple, Set
from asyncio import get_event_loop
from sys import path
from os import chdir

WEBAPP_DIR = realpath(dirname(__file__))
DIAMETER_DB_DIR = realpath(WEBAPP_DIR + '/..')

path.append(DIAMETER_DB_DIR)

chdir(dirname(__file__))

from database_diameter import *
from authentication import login_required

from flask_salt import FLASK_SALT



app = Flask('bus-app')

app.secret_key = FLASK_SALT

app.config['PROPAGATE_EXCEPTIONS'] = True

#app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.jinja_env.auto_reload = True

app.jinja_env.filters['zip'] = zip

@app.route('/')
@login_required
async def index():
    
    sql_session  = Session()
    
    try:
        return await render_template('index.html',
            all_applications = sql_session.query(DiameterApplication).order_by(DiameterApplication.application_name.asc()).all(),
            alone_command_codes = sql_session.query(DiameterCommand).order_by(DiameterCommand.command_name.asc()).filter(~DiameterCommand.applications.any()),
            
            num_of_applications = sql_session.query(DiameterApplication).count(),
            num_of_commands = sql_session.query(DiameterCommand).count(),
            num_of_vendors = sql_session.query(DiameterVendor).count(),
            
            num_of_avps = sql_session.query(DiameterAVPDefinition).count(),
            num_of_avps_occurrences = sql_session.query(DiameterCommandAVPOccurrence).count(),
            
            
            object_id_arborescence = None)
    
    finally:
        sql_session.close()

# Here we have the endpoint names matching
# the CSS class suffix of the respective
# tree view objects, for simplicity

@app.route('/application/<object_id>') # object_id of DiameterApplication here
@login_required
async def serve_application(object_id):
    object_id_arborescence : List[str] = []
    
    if request.args.get('object-id-arborescence'):
        object_id_arborescence =  request.args.get('object-id-arborescence').split(',')

    object_id_arborescence.append(object_id)

    sql_session =  Session()
    try:
        application =  sql_session.query(DiameterApplication).filter_by(object_id  = object_id).first()
        return await render_template('application.html',
            application = application,
            
            all_applications = sql_session.query(DiameterApplication).order_by(DiameterApplication.application_name.asc()).all(),
            alone_command_codes = sql_session.query(DiameterCommand).order_by(DiameterCommand.command_name.asc()).filter(~DiameterCommand.applications.any()),
            
            object_id_arborescence = object_id_arborescence,
            
        )
    finally:
        sql_session.close()

@app.route('/command-code/<object_id>') # object_id of DiameterCommand
@login_required
async def serve_command_code(object_id):
    object_id_arborescence : List[str] = []
    
    if request.args.get('object-id-arborescence'):
        object_id_arborescence =  request.args.get('object-id-arborescence').split(',')

    object_id_arborescence.append(object_id)

    sql_session =  Session()
    try:
        command =  sql_session.query(DiameterCommand).filter_by(object_id  = object_id).first()
        return await render_template('command_code.html',
            command = command,
            
            DiameterAVPRequirement = DiameterAVPRequirement,
            
            all_applications = sql_session.query(DiameterApplication).order_by(DiameterApplication.application_name.asc()).all(),
            alone_command_codes = sql_session.query(DiameterCommand).order_by(DiameterCommand.command_name.asc()).filter(~DiameterCommand.applications.any()),
            
            object_id_arborescence = object_id_arborescence,
            
        )
    finally:
        sql_session.close()

@app.route('/avp/<object_id>') # object_id of DiameterAVPDefinition
@login_required
async def serve_avp(object_id):
    object_id_arborescence : List[str] = []
    
    if request.args.get('object-id-arborescence'):
        object_id_arborescence =  request.args.get('object-id-arborescence').split(',')

    object_id_arborescence.append(object_id)

    sql_session =  Session()
    try:
        avp =  sql_session.query(DiameterAVPDefinition).filter_by(object_id  = object_id).first()
        return await render_template('avp.html',
            avp = avp,
            
            DiameterAVPRequirement = DiameterAVPRequirement,
            
            all_applications = sql_session.query(DiameterApplication).order_by(DiameterApplication.application_name.asc()).all(),
            alone_command_codes = sql_session.query(DiameterCommand).order_by(DiameterCommand.command_name.asc()).filter(~DiameterCommand.applications.any()),
            
            object_id_arborescence = object_id_arborescence,
            
        )
    finally:
        sql_session.close()


@app.route('/jevoudraisdussoafindemidentifierencrossdomainpourdesraisonsdegouvernancesurnosracinesdnsinternes', methods=['POST'])
async def sso_endpoint():
    
    form = await request.form
    
    try:
        
        remote_session = app.session_interface.get_signing_serializer(app).loads(
            form['cookie'], max_age=app.permanent_session_lifetime.total_seconds()
        )
        
        print('==>', remote_session)
        
        for key, value in remote_session.items():
            print(key, '=>', value)
            session[key] = value
    
    except BadSignature:
        
        return Response('cookie deserialization error')
    
    else:
        
        return redirect(form['return_to'])



if __name__ == '__main__':
    
    args = ArgumentParser()
    
    args.add_argument('-p', '--port', help = 'Port number to serve on 0.0.0.0', type = int, default = 9999)
    
    args = args.parse_args()
    
    # Ensure to share the same event loop as the task
    # that was scheduled when importing other potential modules
    
    app.run(host = '0.0.0.0', loop = get_event_loop(), port = args.port)

