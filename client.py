#!/bin/env python3


import argparse
import socket
import ssl
import base64
import requests
import sys
import os

import http.client as httplib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from datetime import datetime
from urllib.parse import urljoin

import warnings

warnings.filterwarnings('ignore', category=DeprecationWarning)


def get_cert_for_hostname(hostname, port):
    conn = ssl.create_connection((hostname, port))
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sock = context.wrap_socket(conn, server_hostname=hostname)
    certDER = sock.getpeercert(True)
    certPEM = ssl.DER_cert_to_PEM_cert(certDER)
    return x509.load_pem_x509_certificate(certPEM.encode('ascii'), default_backend())


def get_issuer(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    issuers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
    if not issuers:
        raise Exception('No issuers entry in AIA')
    return issuers[0].access_location.value


def get_issuer_cert(ca_issuer):
    issuer_response = requests.get(ca_issuer)
    if issuer_response.ok:
        issuerDER = issuer_response.content
        issuerPEM = ssl.DER_cert_to_PEM_cert(issuerDER)
        return x509.load_pem_x509_certificate(issuerPEM.encode('ascii'), default_backend())
    raise Exception(f'Fetching issuer certificate failed with response status: {issuer_response.status_code}')


def get_ocsp_server(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
    if not ocsps:
        raise Exception('No OCSP server entry in AIA')
    return ocsps[0].access_location.value


def main():
    parser = argparse.ArgumentParser(description='OCSP Client')
    parser.add_argument('--host', type=str)
    parser.add_argument('--port', type=int)
    parser.add_argument('--cert', type=str)

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(-1)

    if args.host is not None and args.port is not None:
        try:
            cert = get_cert_for_hostname(args.host, args.port)
        except socket.gaierror:
            sys.stderr.write('Name or service not known\n')
            sys.exit(-1)
    elif args.cert is not None:
        if not os.path.isfile(args.cert):
            sys.stderr.write('File not found\n')
            sys.exit(-1)

        with open(args.cert, 'rb') as f:
            data = f.read()
        cert = x509.load_pem_x509_certificate(data)
    else:
        sys.stderr.write('Not enough arguments\n')
        sys.exit(-1)

    if cert.not_valid_after.__str__() < datetime.now().__str__().split('.')[0]:
        print('Certificate Status: Expired')
        print(f'Expired in {cert.not_valid_after}')
        return

    ca_issuer = get_issuer(cert)
    issuer_cert = get_issuer_cert(ca_issuer)
    ocsp_server = get_ocsp_server(cert)

    conn = httplib.HTTPConnection('127.0.0.1', 8080)

    # Build OCSP request
    ocsp_req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer_cert, SHA256()).build()
    req_path = base64.b64encode(ocsp_req.public_bytes(serialization.Encoding.DER))

    conn.request('GET', urljoin(ocsp_server + '/', req_path.decode('ascii')))

    rsp = conn.getresponse()

    conn.close()

    rsp_bytes = rsp.read()
    ocsp_decoded = ocsp.load_der_ocsp_response(rsp_bytes)
    cert_status = ocsp_decoded.certificate_status.__str__()

    if args.host is not None:
        print(f'Hostname: {args.host}')

    print(f'Issuer: {ca_issuer}')
    print(f'OCSP Server: {ocsp_server}')
    if cert_status.strip() != '':
        print(f'Certificate Status: {cert_status}')


if __name__ == '__main__':
    main()
