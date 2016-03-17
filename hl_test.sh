#!/bin/bash
LOGFILE="/var/log/hl-observatory.setup"
FMTDATE=$(date +%d-%m-%y' '%H:%M:%S)
./get_geoinfo.sh
python3 observatory.py -n test_$(cat hostinfo) -t targets.lst
if [ $(cat ./results/*test*.json | python3 -m json.tool | wc -l) -gt 10 ];then echo "$FMTDATE - Initial Test Successful!" >> $LOGFILE;else echo "$FMTDATE - Initial Test Failed" >> $LOGFILE;fi
