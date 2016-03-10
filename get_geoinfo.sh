#!/bin/bash
#This Script retrives the geo ip information and exports detailed geoip.info file and sets hostinfo as an enviorment variable
geoip=$(curl -s api.ipify.org)
curl -s ipinfo.io/$geoip > geoip.info && export hostinfo=$(cat geoip.info | sed -e 's/[{}:"]/''/g' | grep -E "ip|hostname|country" | awk -F" " '{print $2}' | tr -d "\r\n" | tr ',' '_' | sed s/.$//g)
