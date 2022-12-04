#!/bin/env python3


from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus

import requests


class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)

        # send header first
        self.send_header('Content-type', 'text-html')
        self.end_headers()

        ocsp_response = requests.get(self.path)
        if ocsp_response.ok:
            ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_response.content)
            if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
                self.wfile.write(ocsp_response.content)
                return
            else:
                raise Exception(f'Decoding OCSP response failed: {ocsp_decoded.response_status}')
        raise Exception(f'Fetching OCSP certificate status failed with response status: {ocsp_response.status_code}')


def main():
    print('Server starting...')
    server_address = ('127.0.0.1', 8080)
    httpd = HTTPServer(server_address, HTTPRequestHandler)
    print('Server running on 127.0.0.1:8080')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('Shutting down server...')


if __name__ == '__main__':
    main()
