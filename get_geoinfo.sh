#!/bin/bash
#This Script retrives the geo ip information and exports detailed geoip.info and an abbrivated hostname file
geoip=$(curl -s api.ipify.org)
curl -s ipinfo.io/$geoip > geoip.info && cat geoip.info | sed -e 's/[{}:"]/''/g' | grep -E "ip|hostname|country" | awk -F" " '{print $2}' | tr -d "\r\n" | tr ',' '_' | sed s/.$//g > hostinfo
