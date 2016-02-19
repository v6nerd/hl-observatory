import os
import api
import sys
import math
import time
import atexit
import base64
import random
import signal
import logging
import argparse
import logging.handlers

from https import ssl_observatory
from daemonize import Daemonize

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
    return parser.parse_args()

def exit_handler():
    global run

    run = False
    log.debug("Application exiting")

def main():

    log.info("Hacking Labs Observatory started")
    atexit.register(exit_handler)

    api.start_server(args.debug)

    log.info("Observatory ended")

if __name__ == "__main__":

    global args
    args = setup_arguments()
    setup_logging(args.debug)

    main()
