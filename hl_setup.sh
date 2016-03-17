#HL-Observatory SETUP script over SSH - Tested (single)
echo SETUP STARTED at  $(date +%d-%m-%y' '%H:%M:%S) >> /var/log/hl-observatory.setup
apt-get update && apt-get install -y docker.io >> /var/log/hl-observatory.setup
docker pull v6nerd/hl-observatory:latest && echo SETUP ENDED at $(date +%d-%m-%y' '%H:%M:%S)  >> /var/log/hl-observatory.setup

#Removes existing Docker Instances
docker kill default
docker rm default

#Run HL-Observatory Docker instance
docker run -d -h dockerinstance --name default -i v6nerd/hl-observatory:latest
