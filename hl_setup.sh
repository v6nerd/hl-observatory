#HL-Observatory SETUP script over SSH - Tested (single)
LOGFILE="/var/log/hl-observatory.setup"
FMTDATE=$(date +%d-%m-%y' '%H:%M:%S)
echo SETUP STARTED at  $FMTDATE >> $LOGFILE
apt-get update && apt-get install -y docker.io >> $LOGFILE
docker pull v6nerd/hl-observatory:latest && echo SETUP ENDED at $FMTDATE  >> $LOGFILE

#Removes existing Docker Instances(if any)
docker kill observatory
docker rm observatory

#Run HL-Observatory Docker instance
docker run -d -h dockerinstance --name observatory -i v6nerd/hl-observatory:latest
