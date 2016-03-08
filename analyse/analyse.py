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

def analyse_ssl(domain):
    result = dict()
    dst = "https://{0}".format(domain)
    log.debug("SSL Analyze %s", dst)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_socket = context.wrap_socket(s, server_hostname=domain)
    ssl_socket.connect((domain, 443))

    cert = ssl_socket.getpeercert(False)
    bin_cert = ssl_socket.getpeercert(True)
    ciphers = ssl_socket.cipher()

    sha1sum = hashlib.sha1(bin_cert).hexdigest()
    sha256sum = hashlib.sha256(bin_cert).hexdigest()

    result['sha1'] = sha1sum
    result['sha256'] = sha256sum
    result['ciphers'] = ciphers

    log.debug("[%s] Cert: %s", domain, cert['subject'])
    log.debug("[%s] Fingerprint (SHA1): %s", domain, sha1sum)
    log.debug("[%s] Fingerprint (SHA256): %s", domain, sha256sum)
    log.debug("[%s] Ciphers: %s", domain, ciphers)

    return result

def analyse_dns(domain):
    log.debug("DNS Analyze %s", domain)

    # Get DNS info and retrieve IPv4/IPv6 addresses
    dns = socket.getaddrinfo(domain, 443)
    results = [record[4][0] for record in dns]
    results = list(set(results)) # Some records are the same, set removes duplicated, return to list to make iterable

    if len(results) == 0:
        raise Exception('No DNS resolving')

    return results

def analyse_domain(domain):
    result = dict()
    try:
        result['ssl'] = analyse_ssl(domain)
        result['dns'] = analyse_dns(domain)
    except Exception as e:
        message = str(e)
        log.error('[%s] %s', domain, message)
        result['error'] = message
    return result

def tls_server_callback(socket, dst, context):
    log.debug("TLS connecting to %s",dst)
