import hashlib
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
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23) # No support for SSLv2
#context.options |= ssl.PROTOCOL_SSLv2        Todo: option is needed to enable SSLv2, 
#                                             however is only avalable if openssl is compiled without OPENSSL_NO_SSL2 flag
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
    log.debug("SSL analyze %s", dst)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_socket = context.wrap_socket(s, server_hostname=domain)
        ssl_socket.connect((domain, 443))

        cert = ssl_socket.getpeercert(False)
        bin_cert = ssl_socket.getpeercert(True)
        ciphers = ssl_socket.cipher()

        sha1sum = hashlib.sha1(bin_cert).hexdigest()
        sha256sum = hashlib.sha256(bin_cert).hexdigest()

        log.info("[%s] Fingerprint (SHA1): %s", domain, sha1sum)
        log.info("[%s] Fingerprint (SHA256): %s", domain, sha256sum)
        log.info("[%s] Ciphers: %s", domain, ciphers)
    except Exception as e:
        log.warning("Error connecting [%s] %s", dst, e)


def tls_server_callback(socket, dst, context):
    log.debug("TLS connecting to %s",dst)
