#!/bin/bash

cd "$(dirname "$0")"

set -ex


rm -f database.sqlite3

# ./extract_abnf_from_3gpp.py      # Quite slow, don't always run

./download_rfcs.sh

./database_diameter.py

./insert_application_ids.py

./insert_command_codes.py

./insert_avps.py

for table in $(sqlite3 database.sqlite3 .tables); do
    time sqlite3 -header -csv database.sqlite3 "select * from ${table};" > /tmp/csv_export_diameter_db/${table}.csv
done

time rm -f csv_in_zip_database_export.zip
7z a csv_in_zip_database_export.zip /tmp/csv_export_diameter_db/

if [ -d /usr/share/elasticsearch/ ]; then
    ./webapp/app.py --reindexate-elasticsearch
fi
