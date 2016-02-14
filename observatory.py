import os
import sys
import math
import time
import numpy
import base64
import random
import logging
import argparse
import logging.handlers

from https import ssl_observatory

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
    log.addHandler(syslog)
    log.addHandler(ch)

def setup_arguments():
    parser = argparse.ArgumentParser(description='Hacking Labs Observatory')
    parser.add_argument('-d', action='store_true', dest='debug',default=False, help='Enable debug logging')
    return parser.parse_args()


def main():

    args = setup_arguments()
    setup_logging(args.debug)

    log.info("Hacking Labs Observatory started")

    ssl_observatory.start()


    log.info("Observatory ended")

if __name__ == "__main__":
    main()

