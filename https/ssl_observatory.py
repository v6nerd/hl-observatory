import ssl, socket
import logging
from threading import Thread

"""
Functionality which verifies the SSL connection with different procedures

The following details are requested with each connection
  - SSL/TLS version
  - Cert fingerprint
  - Certificate Chain
  - TLS Cipher modes
"""

log = logging.getLogger("Observatory.ssl")

# Configure SSL Context
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.verify_mode = ssl.CERT_OPTIONAL
context.check_hostname = True
context.load_default_certs()

def start():
    log.info("SSL observatory started")
    log.debug("Starting SSL thread")
    t = Thread(None, run, None, ())
    t.start()

def stop():
    pass

def run():
    with open('https/targets.lst','r') as f:
        lines = f.readlines()
        for line in lines:
            analyse_host(line.strip())


def analyse_host(domain):
    dst = "https://{0}".format(domain)
    log.info("SSL analyze %s", dst)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_socket = context.wrap_socket(s, server_hostname=domain)
    ssl_socket.connect((domain, 443))

def tls_server_callback(socket, dst, context):
    log.debug("TLS connecting to %s",dst)
