#!/bin/bash
./get_geoinfo.sh && cat hostinfo
python3 observatory.py -n test_$(cat hostinfo) -t targets.lst
