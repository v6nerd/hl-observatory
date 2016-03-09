#pre-docker setup scrip over SSH - tested
apt-get update && apt-get install -y docker.io
docker pull v6nerd/hl-observatory:v1 && docker run -i v6nerd/hl-observatory:v1 /bin/bash
cat ./results/*.json
exit
