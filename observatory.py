import os
import rsa
import api
import sys
import json
import math
import time
import atexit
import base64
import random
import signal
import hashlib
import logging
import argparse
import datetime
import logging.handlers

from analyse import analyse
from threading import Thread

pid = '/tmp/observatory.pid'
log = logging.getLogger("Observatory")

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
try:
    syslog = logging.handlers.SysLogHandler(address='/dev/log')
    syslog.setLevel(logging.WARN)
    syslog.setFormatter(formatter)
    log.addHandler(syslog)
    log.addHandler(ch)

except:
	pass

def setup_arguments():
    parser = argparse.ArgumentParser(description='Hacking Labs Observatory')
    parser.add_argument('-d', action='store_true', dest='debug',default=False, help='Enable debug logging')
    parser.add_argument('-f', action='store_true', dest='foreground',default=False, help='Keep application in foreground')
    parser.add_argument('-n', action='store', type=str, required=True, dest='name',default=False, help='Set unique name for this instance of hl observatory')
    parser.add_argument('-i', action='store', type=str, required=True, dest='filename',default=False,help='specify domain target list')	
    return parser.parse_args()

def exit_handler():
    pass

def start():
    log.debug("Starting analyse thread")
    t = Thread(None, run, None, (args.name,))
    t.start()
    return t

def read_pub_key():
    with open('pubkey.pem','rb') as f:
        keydata = f.read()

    return rsa.PublicKey.load_pkcs1(keydata)

def write_to_file(location, data, mode='w'):
    with open(location, mode) as f:
        f.write(data)
    log.debug("Written to: %s",location)

def run(name):
    results = dict()

    with open(args.filename,'r') as f:

        lines = f.readlines()
        for line in lines:
            dst = line.strip()
            results[dst] = analyse.analyse_domain(dst)

    json_io = json.dumps(results, separators=(',', ':'), sort_keys=True) #remove whitespaces
    sha256sum = hashlib.sha256(json_io.encode('utf-8')).hexdigest()
    log.info("Results: [%s] %s",sha256sum,json_io)

    now = datetime.datetime.now()
    str_now = now.strftime("%H%M%d%m%y")
    file_name = "{0}_{1}.json".format(name,str_now)

    # Write results
    loc = 'results/{0}'.format(file_name)
    write_to_file(loc, json_io)

    # Write encrypted signature
    loc = 'results/{0}.asc'.format(file_name)
    pubkey = read_pub_key()
    enc_sign = rsa.encrypt(sha256sum.encode('utf-8'), pubkey)
    write_to_file(loc, enc_sign,'wb')

def main():

    log.info("Hacking Labs Observatory started")
    atexit.register(exit_handler)

    thread = start()
    thread.join()
    log.info("Observatory ended")

if __name__ == "__main__":

    global args
    args = setup_arguments()
    setup_logging(args.debug)

    main()
