# HL Observatory #

## Installation ##

Run the following commond line:

`pip3 install flask daemonize` 

## Usage ##

Run the following:

`python3 observatory.py`

This will start the server on your localhost port 5000

Then the API can be called using curl, e.g.

`curl http://localhost:5000?domain=google.com`

## Result ##

The result of the API call will be the following:

`{ 
  "dns": [
    "213.239.154.20"
  ],
  "ssl": {
    "ciphers": [
      "ECDHE-RSA-AES128-GCM-SHA256",
      "TLSv1/SSLv3",
      128
    ],
    "sha1": "2834ab86630f35e6aa439a0e127a072adef570ca",
    "sha256": "5a42fd817ffe266336acf83e8ac1e47170e7627ea94a643327edb8322b21018c"
  }
}%`

