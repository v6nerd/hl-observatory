import os
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

    syslog = logging.handlers.SysLogHandler(address='/dev/log')
    syslog.setLevel(logging.WARN)
    syslog.setFormatter(formatter)
    log.addHandler(syslog)
    log.addHandler(ch)

def setup_arguments():
    parser = argparse.ArgumentParser(description='Hacking Labs Observatory')
    parser.add_argument('-d', action='store_true', dest='debug',default=False, help='Enable debug logging')
    parser.add_argument('-f', action='store_true', dest='foreground',default=False, help='Keep application in foreground')
    parser.add_argument('-n', action='store', type=str, required=True, dest='name',default=False, help='Set unique name for this instance of hl observatory')
    return parser.parse_args()

def exit_handler():
    pass

def start():
    log.debug("Starting analyse thread")
    t = Thread(None, run, None, (args.name,))
    t.start()
    return t

def run(name):
    results = dict()

    with open('targets.lst','r') as f:

        lines = f.readlines()
        for line in lines:
            dst = line.strip()
            results[dst] = analyse.analyse_domain(dst)

    json_io = json.dumps(results,separators=(',', ':')) #remove whitespaces
    log.info("[Results] %s",json_io)

    now = datetime.datetime.now()
    str_now = now.strftime("%H%M_%d%m%y")
    file_name = "{0}_{1}.json".format(name,str_now)

    with open('results/'+file_name,'w') as f:
        f.write(json_io)

    log.info("Written results to file: %s",file_name)

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
