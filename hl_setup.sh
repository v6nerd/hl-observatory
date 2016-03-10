#HL-Observatory SETUP script over SSH - Tested (single)
echo SETUP STARTED at  $(date +%d-%m-%y' '%H:%M:%S) >> /var/log/hl-observatory.setup
apt-get update && apt-get install -y docker.io >> /var/log/hl-observatory.setup
docker pull v6nerd/hl-observatory:latest && echo SETUP ENDED at $(date +%d-%m-%y' '%H:%M:%S)  >> /var/log/hl-observatory.setup
docker run --name default -i v6nerd/hl-observatory:latest /bin/bash
./get_geoinfo.sh && python3 /hl-observatory/observatory.py -n $(cat ./hostinfo) -t targets.lst && cat ./results/*.json 
exit
