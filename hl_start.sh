#!/bin/bash
./get_geoinfo.sh && cat hostinfo
python3 observatory.py -n test_$(cat hostinfo) -t targets.lst
if [ $(cat ./results/*test*.json | python3 -m json.tool | wc -l) -gt 10 ];then python3 observatory.py -n $(cat hostinfo) -t alexa_*.list;else echo "Test Failed";fi

