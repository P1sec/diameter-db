#!/bin/bash

cd "$(dirname "$0")"

set -ex

rm -f ../../../database.sqlite3

# uv run ./extract_abnf_from_3gpp.py # Quite slow, don't always run
uv run ./download_rfcs.sh
uv run ./database_diameter.py # Creates the database or missing tables
uv run ./insert_application_ids.py
uv run ./insert_command_codes.py
uv run ./insert_avps.py

mkdir -p /tmp/csv_export_diameter_db/

for table in $(sqlite3 ../../../database.sqlite3 .tables); do
    time sqlite3 -header -csv ../../../database.sqlite3 "select * from ${table};" > /tmp/csv_export_diameter_db/${table}.csv
done

time rm -f csv_in_zip_database_export.zip
7z a ../../../data/csv_in_zip_database_export.zip /tmp/csv_export_diameter_db/

if [ -d /usr/share/elasticsearch/ ]; then
    uv run ../webapp/app.py --reindexate-elasticsearch
fi
