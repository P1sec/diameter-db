#!/bin/sh

# From https://www.google.com/search?q=%22Diameter+Header%22+OR+%22AVP+header%22+site:https://tools.ietf.org/html+-inurl:draft++-inurl:dime+%22diameter%22

DIAMETER_RFCS="3588 4004 4005 4006 4072 4740 5191 5447 5624 5777 5778 5779 5866 6159 6733 6734 6735 6736 6737 6738 6942 7155 7423 7660 7678 7683 8506 8581 8582 8583"

set -ex
cd "$(dirname "$0")"

mkdir -p ietf_rfcs
cd ietf_rfcs

for rfc_number in ${DIAMETER_RFCS}; do
    if [ ! -e "rfc${rfc_number}.txt" ]; then
        wget "https://tools.ietf.org/rfc/rfc${rfc_number}.txt" -O "rfc${rfc_number}.txt"
    fi
done
