#!/usr/bin/env python
################################
# utils.py
#
# Version: 0.0.0.1
# Date: 2018-12-03
# Authors: Sophian Mehboub
################################
import gnupg
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
from jinja2 import Environment, FileSystemLoader
import os
import socket
import platform
from uuid import getnode

class GPGException(Exception):
        pass


class DownloadFileException(Exception):
        pass

def downloadFile(url, path):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    r = requests.get(url, stream=True, verify=False)
    if r.status_code == 200:
        with open(path, 'wb') as f:
            for chunk in r:
                f.write(chunk)
    else:
        raise DownloadFileException("The file %s is unavailable" % url)

def append(path, content):
    f = open(path, "w")
    f.write(content)
    f.close()

def aptKeyAdd(keyring, pubkey):
    gpg = gnupg.GPG(keyring=keyring)
    importres = gpg.import_keys(pubkey)
    if importres.results[0]['fingerprint'] == None:
        raise GPGException(importres.results[0]['text'])

class CertificateUtils():
    def __init__(self, certs):
        self.certs = certs
    def getCert(self):
        start_cert = '-----BEGIN CERTIFICATE-----\n'
        end_cert = '\n-----END CERTIFICATE-----'
        cert = self.certs[self.certs.find(start_cert)+len(start_cert):self.certs.rfind(end_cert)]
        cert = '%s%s%s\n' % (start_cert, cert, end_cert)
        return cert
    def getKey(self):
        start_key = '-----BEGIN RSA PRIVATE KEY-----\n'
        end_key = '\n-----END RSA PRIVATE KEY-----'
        key = self.certs[self.certs.find(start_key)+len(start_key):self.certs.rfind(end_key)]
        key = '%s%s%s\n' % (start_key, key, end_key)
        return key


def write(path, content):
    f = open(path, "w")
    f.write(content)

def downloadCertificates(url=None, username=None, password=None, cacert=False):
    r = requests.get(url, auth=requests.auth.HTTPBasicAuth(username, password), verify=cacert)
    return r.text


def generate_file_from_template(vars, source, destination):
    source_dir = os.path.dirname(source)
    source_file = os.path.basename(source)
    env = Environment( loader = FileSystemLoader(source_dir) )
    template = env.get_template(source_file)
    with open(destination, 'w') as fh:
        fh.write(template.render(vars))

def getInfoFqdn(fqdn):
    domain = ''
    parts_fqdn = fqdn.split('.')
    for i in range(1, len(parts_fqdn) -1):
        domain_dns_test = ".".join(parts_fqdn[i:])
        try:
            socket.gethostbyname(domain_dns_test)
            domain = domain_dns_test
            short_hostname = ".".join(parts_fqdn[:i])
            break
        except socket.gaierror:
            pass
    if len(parts_fqdn) == 1:
        short_hostname = fqdn
        domain = None
    elif domain == '':
        short_hostname = fqdn.partition('.')[0]
        domain = fqdn.partition('.')[2]
    return {'short_hostname':short_hostname, 'domain':domain}

def getMacAddr():
    hex_mac_address = str(":".join(re.findall('..', '%012x' % getnode())))
    return hex_mac_address

