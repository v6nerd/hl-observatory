# HL Observatory #

## Installation ##

Run the following commond line:

`pip3 install flask rsa` 

## Usage ##

Run the following:

`python3 observatory.py`

This will run the application and analyse all domains listed in target. The results will be placed in the results directory. 

Each result file will also contain a referenced `.asc` file that contains the encrypted hash256sum of the result. 

## Result ##

The results will be stored in the JSON format in the results directory. 

In order to minimise storage, all whitespaces have been removed. To make it more readable use:
`cat result.json | python -m json.tool`

```
{
    "amazon.com": {
        "dns": [
            "54.239.17.6",
            "54.239.25.208",
            "54.239.26.128",
            "54.239.25.200",
            "54.239.25.192",
            "54.239.17.7"
        ],
        "ssl": {
            "ciphers": [
                "ECDHE-RSA-AES128-GCM-SHA256",
                "TLSv1/SSLv3",
                128
            ],
            "sha1": "5c003b1a9aecef9e41eba5e8a5061a85200fd4ad",
            "sha256": "779d46c104c7336a75c3c47d0cc97d095f641d6524e6f05063128d2eb9c7aef2"
        }
    },
    "facebook.com": {
        "dns": [
            "2a03:2880:2040:7f21:face:b00c:0:25de",
            "66.220.156.68"
        ],
        "ssl": {
            "ciphers": [
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "TLSv1/SSLv3",
                128
            ],
            "sha1": "a04eafb348c26b15a8c1aa87a333caa3cdeec9c9",
            "sha256": "a626b154cc65634181250b810b1bd4c89ec277cea08d785eebe7e768bda7bb00"
        }
    },
```
