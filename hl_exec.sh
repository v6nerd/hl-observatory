#!/bin/bash
EXECPATH="/hl-observatory"

$EXECPATH/get_geoinfo.sh
python3 observatory.py -n $(cat $EXECPATH/hostinfo) -t alexa_*.list
