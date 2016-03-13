import os
import rsa
import sys
import json
import math
import time
import atexit
import base64
import random
import signal
import hashlib
import argparse
import datetime
import queue

import logging
import logging.handlers

from analyse import analyse

import threading
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
    parser.add_argument('-f', action='store_true', dest='foreground',default=False, help='Keep application in foreground')
    parser.add_argument('-n', action='store', type=str, required=True, dest='name',default=False, help='Set unique name for this instance of hl observatory')
    parser.add_argument('-t', action='store', type=str, required=True, dest='filename',default=False,help='Domain target list')
    parser.add_argument('--threads', action='store', type=int, required=False, dest='threads',default=7,help='Set number of threads')
    return parser.parse_args()

def exit_handler():
    thread_stop.set()
    result_thread.join()
    log.info('Cleaned up, exiting')

def read_pub_key():
    with open('pubkey.pem','rb') as f:
        keydata = f.read()

    return rsa.PublicKey.load_pkcs1(keydata)

def write_to_file(location, data, mode='w'):
    with open(location, mode) as f:
        f.write(data)
    log.debug("Written to: %s",location)

def generate_results_name():
    now = datetime.datetime.now()
    str_now = now.strftime("%H%M%d%m%y")
    file_name = "{0}_{1}.json".format(args.name,str_now)
    return file_name


def write_results(results, file_name):

    json_io = json.dumps(results, separators=(',', ':'), sort_keys=True) #remove whitespaces
    sha256sum = hashlib.sha256(json_io.encode('utf-8')).hexdigest()

    # Write results
    loc_json = 'results/{0}'.format(file_name)
    write_to_file(loc_json, json_io)

    # Write encrypted signature
    loc_asc = 'results/{0}.asc'.format(file_name)
    pubkey = read_pub_key()
    enc_sign = rsa.encrypt(sha256sum.encode('utf-8'), pubkey)
    #write_to_file(loc_asc, sha256sum,'w')
    write_to_file(loc_asc, enc_sign,'wb')

    log.debug('Results: %s [%s]', loc_json, sha256sum)

def results_run(tid, domain_queue, result_queue, thread_stop):

    results = dict()
    results_name = generate_results_name()

    log.debug('Starting result thread [%d]', tid)
    # Write results when available
    # verify every 5 seconds whether threads finished
    while not domain_queue.empty() and not thread_stop.is_set():
        try:
            (dst, result) = result_queue.get(True,5)
        except:
            continue

        results[dst] = result
        result_queue.task_done()
        write_results(results,results_name)

    # If SIGINT is thrown, write results and exit
    if thread_stop.is_set():
        log.info('Result thread stopped')
        return

    # Wait for every thread to finish
    domain_queue.join()

    # One final loop to verify that all results
    # will be written
    while not result_queue.empty():
        try:
            (dst, result) = result_queue.get()
        except:
            break
        results[dst] = result
        result_queue.task_done()
        write_results(results)

def main():

    global thread_stop, result_thread

    thread_stop= threading.Event()
    domain_queue = queue.Queue()
    result_queue = queue.Queue()

    log.info("Hacking Labs Observatory started")
    atexit.register(exit_handler)

    with open(args.filename,'r') as f:
        lines = f.readlines()

    for line in lines:
        domain = line.strip()
        domain_queue.put(domain)

    # Start threads
    threads = list()
    for i in range(args.threads):
        thread = Thread(None, analyse.run, None, (i, domain_queue, result_queue, thread_stop))
        threads.append(thread)
        thread.start()

    # Start thread which write results
    result_thread = Thread(None, results_run, None, (10, domain_queue, result_queue, thread_stop))
    result_thread.start()

    log.info("Observatory ended")

if __name__ == "__main__":

    global args
    args = setup_arguments()
    setup_logging(args.debug)

    main()
