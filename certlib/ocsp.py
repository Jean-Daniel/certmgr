import datetime
import logging
import urllib
from typing import Optional, Union
from urllib import request, parse, error

from asn1crypto import ocsp


class OCSP(object):

    def __init__(self, response: ocsp.OCSPResponse):
        self.asn1 = response

    def encode(self) -> bytes:
        return self.asn1.dump()

    @classmethod
    def decode(cls, ocsp_data):
        return OCSP(ocsp.OCSPResponse.load(ocsp_data))

    @property
    def serial_number(self) -> Optional[int]:
        try:
            cert_id = self.asn1.response_data['responses'][0]['cert_id']
            if cert_id:
                return cert_id['serial_number'].native
        except KeyError:
            pass
        return None

    @property
    def this_update(self) -> Optional[datetime.datetime]:
        try:
            this_update = self.asn1.response_data['responses'][0]['this_update']
            if this_update:
                return datetime.datetime.strptime(str(this_update), "%Y%m%d%H%M%SZ")
        except KeyError:
            pass
        return None

    @property
    def next_update(self):
        try:
            next_update = self.asn1.response_data['responses'][0]['next_update']
            if next_update:
                return datetime.datetime.strptime(str(next_update), "%Y%m%d%H%M%SZ")
        except KeyError:
            pass
        return None

    @property
    def response_status(self):
        return self.asn1.response_data['responses'][0]['cert_status'].name

    @staticmethod
    def load(filepath: str) -> Optional['OCSP']:
        try:
            with open(filepath, 'rb') as ocsp_file:
                return OCSP.decode(ocsp_file.read())
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.warning('OSCP response "%s" loading failed: %s', filepath, str(e))
        return None

    @staticmethod
    def fetch(ocsp_url, ocsp_request, last_update) -> Union[Optional['OCSP'], bool]:
        req = urllib.request.Request(url=ocsp_url, data=ocsp_request.dump())
        req.add_header('Content-Type', 'application/ocsp-req')
        req.add_header('Accept', 'application/ocsp-response')
        req.add_header('Host', urllib.parse.urlparse(ocsp_url).hostname)
        if last_update:
            req.add_header('If-Modified-Since', last_update.strftime('%a, %d %b %Y %H:%M:%S GMT'))
        try:
            with urllib.request.urlopen(req) as response:
                # XXX add validation of response
                return OCSP.decode(response.read())
        except urllib.error.HTTPError as e:
            if last_update and (304 == e.code):
                return False
            if (400 <= e.code) and (e.code < 500):
                logging.warning('Unable to retrieve OCSP response from %s (HTTP error: %s %s):\n%s', ocsp_url, e.code, e.reason, e.read())
            else:
                logging.warning('Unable to retrieve OCSP response from %s (HTTP error: %s %s)', ocsp_url, e.code, e.reason)
        except urllib.error.URLError as e:
            logging.warning('Unable to retrieve OCSP response from %s: %s', ocsp_url, e.reason)
        except Exception as e:
            logging.warning('Unable to retrieve OCSP response from %s: %s', ocsp_url, str(e))
        return None
