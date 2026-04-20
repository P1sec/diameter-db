#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

from quart import (
    Quart as Flask,
    request,
    redirect,
    render_template,
    session,
    send_from_directory,
    abort,
    Response,
    send_file,
    redirect,
    jsonify,
)
from argparse import ArgumentParser
from os.path import dirname, realpath
from itsdangerous import BadSignature
from typing import List, Union, Dict, Tuple, Set
from asyncio import run
from aiohttp import ClientSession
from re import findall, search, sub, IGNORECASE, match, DOTALL, MULTILINE
from urllib.parse import quote
from html import unescape, escape
from math import ceil
from sys import path
from os import chdir

WEBAPP_DIR = realpath(dirname(__file__))
DIAMETER_DB_DIR = realpath(WEBAPP_DIR + '/..')

path.append(DIAMETER_DB_DIR)

chdir(dirname(__file__))

from diameter_db.common.database import *
from diameter_db.webapp.authentication import (
    login_required,
    verify_and_decode_legacy_cookie,
)

from diameter_db.webapp.flask_salt import FLASK_SALT

app = Flask('diameter-db')

app.secret_key = FLASK_SALT

app.config['PROPAGATE_EXCEPTIONS'] = True

# app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.jinja_env.auto_reload = True

app.jinja_env.filters['zip'] = zip


@app.route('/')
@login_required
async def index():

    sql_session = Session()

    try:
        return await render_template(
            'index.html',
            all_applications=sql_session.query(DiameterApplication)
            .order_by(DiameterApplication.application_name.asc())
            .all(),
            alone_command_codes=sql_session.query(DiameterCommand)
            .order_by(DiameterCommand.command_name.asc())
            .filter(~DiameterCommand.applications.any()),
            num_of_applications=sql_session.query(DiameterApplication).count(),
            num_of_commands=sql_session.query(DiameterCommand).count(),
            num_of_vendors=sql_session.query(DiameterVendor).count(),
            num_of_avps=sql_session.query(DiameterAVPDefinition).count(),
            num_of_avps_occurrences=sql_session.query(
                DiameterCommandAVPOccurrence
            ).count(),
            object_id_arborescence=None,
        )

    finally:
        sql_session.close()


# Here we have the endpoint names matching
# the CSS class suffix of the respective
# tree view objects, for simplicity


@app.route('/application/<object_id>')  # object_id of DiameterApplication here
@login_required
async def serve_application(object_id):
    object_id_arborescence: List[str] = []

    if request.args.get('object-id-arborescence'):
        object_id_arborescence = request.args.get(
            'object-id-arborescence'
        ).split(',')

    object_id_arborescence.append(object_id)

    sql_session = Session()
    try:
        application = (
            sql_session.query(DiameterApplication)
            .filter_by(object_id=object_id)
            .first()
        )
        if not application:
            return abort(404)
        return await render_template(
            'application.html',
            application=application,
            all_applications=sql_session.query(DiameterApplication)
            .order_by(DiameterApplication.application_name.asc())
            .all(),
            alone_command_codes=sql_session.query(DiameterCommand)
            .order_by(DiameterCommand.command_name.asc())
            .filter(~DiameterCommand.applications.any()),
            object_id_arborescence=object_id_arborescence,
        )
    finally:
        sql_session.close()


@app.route('/command-code/<object_id>')  # object_id of DiameterCommand
@login_required
async def serve_command_code(object_id):
    object_id_arborescence: List[str] = []

    if request.args.get('object-id-arborescence'):
        object_id_arborescence = request.args.get(
            'object-id-arborescence'
        ).split(',')

    object_id_arborescence.append(object_id)

    sql_session = Session()
    try:
        command = (
            sql_session.query(DiameterCommand)
            .filter_by(object_id=object_id)
            .first()
        )
        if not command:
            return abort(404)
        return await render_template(
            'command_code.html',
            command=command,
            DiameterAVPRequirement=DiameterAVPRequirement,
            all_applications=sql_session.query(DiameterApplication)
            .order_by(DiameterApplication.application_name.asc())
            .all(),
            alone_command_codes=sql_session.query(DiameterCommand)
            .order_by(DiameterCommand.command_name.asc())
            .filter(~DiameterCommand.applications.any()),
            object_id_arborescence=object_id_arborescence,
        )
    finally:
        sql_session.close()


@app.route('/avp/<object_id>')  # object_id of DiameterAVPDefinition
@login_required
async def serve_avp(object_id):
    object_id_arborescence: List[str] = []

    if request.args.get('object-id-arborescence'):
        object_id_arborescence = request.args.get(
            'object-id-arborescence'
        ).split(',')

    object_id_arborescence.append(object_id)

    sql_session = Session()
    try:
        avp = (
            sql_session.query(DiameterAVPDefinition)
            .filter_by(object_id=object_id)
            .first()
        )
        if not avp:
            return abort(404)
        return await render_template(
            'avp.html',
            avp=avp,
            DiameterAVPRequirement=DiameterAVPRequirement,
            all_applications=sql_session.query(DiameterApplication)
            .order_by(DiameterApplication.application_name.asc())
            .all(),
            alone_command_codes=sql_session.query(DiameterCommand)
            .order_by(DiameterCommand.command_name.asc())
            .filter(~DiameterCommand.applications.any()),
            object_id_arborescence=object_id_arborescence,
        )
    finally:
        sql_session.close()


@app.route('/expanded_arborescence_item', methods=['GET'])
async def expanded_arborescence_item():  # Called through Ajax when expanding a tree item on the side panel

    sql_session = Session()

    try:
        object_to_render = (
            sql_session.query(VersionedDiameterObject)
            .filter_by(object_id=request.args['object_id'])
            .one()
        )

        # querying_class = with_polymorphic(VersionedDiameterObject, [DiameterApplication, DiameterAVPDefinition, DiameterCommand])

        contents = object_to_render.to_html_tree_entry(
            current_page_object_id_arborescence=[request.args['object_id']]
            if request.args['do_expand'] == '1'
            else None,
            this_object__parent_object_id_arborescence=(
                request.args['object_id_arborescence'].split(',')
                if request.args['object_id_arborescence']
                else None
            ),
        )

        resp = Response(contents)
        resp.headers['X-Robots-Tag'] = 'noindex'
        return resp

    finally:
        sql_session.close


@app.route(
    '/jevoudraisdussoafindemidentifierencrossdomainpourdesraisonsdegouvernancesurnosracinesdnsinternes',
    methods=['POST'],
)
async def sso_endpoint():

    form = await request.form

    try:
        try:
            remote_session = app.session_interface.get_signing_serializer(
                app
            ).loads(
                form['cookie'],
                max_age=app.permanent_session_lifetime.total_seconds(),
            )

        except BadSignature:
            remote_session = verify_and_decode_legacy_cookie(form['cookie'])

        print('==>', remote_session)

        for key, value in remote_session.items():
            print(key, '=>', value)
            session[key] = value

    except BadSignature:
        return Response('cookie deserialization error')

    else:
        return redirect(form['return_to'])


@app.route('/search', methods=['GET'])
async def search_engine():

    sql_session = Session()

    try:
        async with ClientSession() as client_session:
            RESULTS_PER_PAGE = 15
            wanted_page = max(1, int(request.args.get('page', 1)))

            async with client_session.post(
                'http://localhost:9200/diameter_db_pages/indexated_page/_search',
                params={
                    'from': (wanted_page - 1) * RESULTS_PER_PAGE,
                    'size': RESULTS_PER_PAGE,
                },
                json={
                    'query': {
                        'simple_query_string': {
                            'query': request.args.get('query', ''),
                            'fields': ['title', 'contents'],
                            'default_operator': 'and',
                        }
                    },
                    'highlight': {
                        'pre_tags': ['__BOLDSTART__'],
                        'post_tags': ['__BOLDEND__'],
                        'fields': {
                            'title': {
                                'no_match_size': 2000,
                                'number_of_fragments': 1,
                                'fragment_size': 2000,
                            },
                            'contents': {
                                'no_match_size': 300,
                                'number_of_fragments': 3,
                                'fragment_size': 200,
                            },
                        },
                    },
                },
                timeout=30,
            ) as response:
                elastic_results = await response.json()

                print(
                    'DEBUG: JSON response from Elasticsearch:  ',
                    repr(elastic_results),
                )

                number_results = '{:,}'.format(
                    elastic_results['hits']['total']
                )

                total_pages = ceil(
                    elastic_results['hits']['total'] / RESULTS_PER_PAGE
                )

                # Results

                results_object = []

                for result in elastic_results['hits']['hits']:
                    found_title = ' ... '.join(result['highlight']['title'])
                    found_snippet = ' ... '.join(
                        ['', *result['highlight']['contents'], '']
                    )

                    if '__BOLDSTART__' not in found_snippet:
                        found_snippet = found_snippet.replace(' ... ', '', 1)

                    results_object.append(
                        {
                            'url': result['_source']['url'],
                            'title': escape(found_title)
                            .replace('__BOLDSTART__', '<b>')
                            .replace('__BOLDEND__', '</b>'),
                            'snippet': escape(found_snippet)
                            .replace('__BOLDSTART__', '<b>')
                            .replace('__BOLDEND__', '</b>'),
                        }
                    )

                # Pagination

                pagination_html = ''

                show_pages = set()

                for page in range(1, min(total_pages, 5) + 1):
                    show_pages.add(page)

                for page in range(
                    max(1, wanted_page - 5),
                    min(total_pages, wanted_page + 5) + 1,
                ):
                    show_pages.add(page)

                for page in range(max(1, total_pages - 5), total_pages + 1):
                    show_pages.add(page)

                prev_page = 0

                for page in sorted(show_pages):
                    if prev_page != page - 1:
                        pagination_html += '... '

                    if page != wanted_page:
                        pagination_html += '<a href="%s&page=%d">%d</a> ' % (
                            sub(
                                r'&?page=[^&]+', '', escape(request.full_path)
                            ),
                            page,
                            page,
                        )

                    else:
                        pagination_html += '<b>%d</b> ' % page

                    prev_page = page

                return await render_template(
                    'search.html',
                    results=results_object,
                    number_results=number_results,
                    pagination=pagination_html,
                    search_term=request.args.get('query', ''),
                    all_applications=sql_session.query(DiameterApplication)
                    .order_by(DiameterApplication.application_name.asc())
                    .all(),
                    alone_command_codes=sql_session.query(DiameterCommand)
                    .order_by(DiameterCommand.command_name.asc())
                    .filter(~DiameterCommand.applications.any()),
                    object_id_arborescence=None,
                )

    finally:
        sql_session.close()


async def indexate_app():
    def undecorate_endpoint(endpoint_function):
        return endpoint_function.__wrapped__

    sql_session = Session()

    try:
        for endpoint, url_prefix, possible_endpoint_values in [
            (index, '/', None),
            (
                serve_application,
                '/application/',
                [
                    application.object_id
                    for application in sql_session.query(DiameterApplication)
                ],
            ),
            (
                serve_command_code,
                '/command-code/',
                [
                    command.object_id
                    for command in sql_session.query(DiameterCommand)
                ],
            ),
            (
                serve_avp,
                '/avp/',
                [
                    avp.object_id
                    for avp in sql_session.query(DiameterAVPDefinition)
                ],
            ),
        ]:
            for possible_value in possible_endpoint_values or [None]:
                async with app.test_request_context(
                    url_prefix + (possible_value or '')
                ):
                    if possible_value:
                        rendered_html = await undecorate_endpoint(endpoint)(
                            possible_value
                        )
                    else:
                        rendered_html = await undecorate_endpoint(endpoint)()

                    async with ClientSession() as client_session:
                        ELASTICSEARCH_HOST = 'localhost:9200'

                        elastic_url = (
                            'http://%s/diameter_db_pages/indexated_page/%s'
                            % (ELASTICSEARCH_HOST, possible_value or 'index')
                        )

                        title_html = (
                            search(
                                r'<title>(.+?)</title>',
                                rendered_html,
                                flags=DOTALL | MULTILINE,
                            )
                            .group(1)
                            .split(' - diameter-db')[0]
                        )
                        main_html = search(
                            r'<main>(.+?)</main>',
                            rendered_html,
                            flags=DOTALL | MULTILINE,
                        ).group(1)

                        data = {
                            'title': unescape(
                                sub(r'<.+?>', '', title_html, flags=IGNORECASE)
                            ).strip(),
                            'contents': unescape(
                                sub(r'<.+?>', '', main_html, flags=IGNORECASE)
                            ).strip(),
                        }

                        data['url'] = url_prefix + (possible_value or '')

                        async with client_session.put(
                            elastic_url,
                            json=data,
                            headers={
                                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0'
                            },
                            timeout=30,
                        ) as resp:
                            print(
                                'DEBUG: indexating the vulnerability form contents into Elasticsearch returned:',
                                await resp.read(),
                            )

    finally:
        sql_session.close()


def main():
    args = ArgumentParser()

    args.add_argument(
        '-p',
        '--port',
        help='Port number to serve on 127.0.0.1',
        type=int,
        default=9999,
    )
    args.add_argument(
        '-r',
        '--reindexate-elasticsearch',
        help='Reindexate AVP values into elasticsearch',
        action='store_true',
    )

    args = args.parse_args()

    # Ensure to share the same event loop as the task
    # that was scheduled when importing other potential modules

    if args.reindexate_elasticsearch:
        run(indexate_app())
    else:
        app.run(host='127.0.0.1', port=args.port)


if __name__ == '__main__':
    main()
