import os
import rsa
import sys
import time
import base64
import hashlib
import logging
import argparse
#import logging.handlers

log = logging.getLogger("Verification")

def setup_logging(debug):
    formatter = logging.Formatter("[%(asctime)s] (%(levelname)s) %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    if debug:
        log.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
    log.addHandler(ch)
try:
    syslog = logging.handlers.SysLogHandler(address='/dev/log')
    syslog.setLevel(logging.WARN)
    syslog.setFormatter(formatter)
    log.addHandler(syslog)

except:
	pass

def setup_arguments():
    parser = argparse.ArgumentParser(description='Hacking Labs Observatory')
    parser.add_argument('-d', action='store_true', dest='debug',default=False, help='Enable debug logging')
    parser.add_argument('-p', action='store', type=str, required=True, dest='private_key',default=False, help='Set the location of the private key')
    parser.add_argument('-t', action='store', type=str, required=True, dest='data_dir',default=False,help='Path of the directory containing the data files')
    return parser.parse_args()

def read_pub_key():
    with open('pubkey.pem','rb') as f:
        keydata = f.read()

    return rsa.PublicKey.load_pkcs1(keydata)

def main():
    error_list = list()
    files = correct = 0
    log.info("Hacking Labs data verification started")

    if not os.path.isfile(args.private_key):
        log.error('Private key does not exist')
        exit(1)

    if not os.path.isdir(args.data_dir):
        log.error('Data directory does not exist')
        exit(1)

    with open(args.private_key, 'rb') as f:
        keydata = f.read()

    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    data_files = [os.path.join(args.data_dir,f) for f in os.listdir(args.data_dir) 
            if os.path.isfile(os.path.join(args.data_dir, f)) and f.endswith('.json')]

    for json in data_files:
        asc = '{0}.asc'.format(json)
        if not os.path.isfile(asc):
            error = 'Signature file not found: {0}'.format(json)
            log.error(error)
            error_list.append(error)
        else:
            files += 1

        with open(asc, 'rb') as f:
            enc_sign = f.read()

        with open(json, 'r') as f:
            data = f.read()

        sign = rsa.decrypt(enc_sign, privkey)
        checksum = hashlib.sha256(data).hexdigest()
        if sign != checksum:
            error = 'Invalid signature found: {0}'.format(json)
            log.error(error)
            error_list.append(error)
        else:
            correct += 1

    log.info("Verification ended")
    log.info("Results: [%d] files verified, [%d] correct, [%d] errors", files, correct, len(error_list))
    
    if len(error_list) > 0:
        log.error('Following errors found:')
        for error in error_list:
            log.error(error)

if __name__ == "__main__":

    global args
    args = setup_arguments()
    setup_logging(args.debug)

    main()
