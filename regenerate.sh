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
