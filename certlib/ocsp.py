import datetime
import logging
from typing import Optional, Union

import requests
from asn1crypto import ocsp


class OCSP:

    def __init__(self, response: ocsp.OCSPResponse):
        self.asn1 = response

    def encode(self) -> bytes:
        return self.asn1.dump()

    @classmethod
    def decode(cls, ocsp_data):
        return OCSP(ocsp.OCSPResponse.load(ocsp_data))

    @property
    def response_status(self) -> str:
        return self.asn1['response_status'].native

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
    def cert_status(self):
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
        headers = {
            'Content-Type': 'application/ocsp-req',
            'Accept': 'application/ocsp-response'
        }
        if last_update:
            headers['If-Modified-Since'] = last_update.strftime('%a, %d %b %Y %H:%M:%S GMT')
        req = requests.post(url=ocsp_url, headers=headers, data=ocsp_request.dump())
        try:
            if last_update and req.status_code == requests.codes.not_modified:
                return False
            if req.status_code == requests.codes.ok:
                return OCSP.decode(req.content)

            if 400 <= req.status_code < 500:
                logging.warning('Unable to retrieve OCSP response from %s (HTTP error: %s %s):\n%s', ocsp_url, req.status_code, req.reason, req.content)
            else:
                logging.warning('Unable to retrieve OCSP response from %s (HTTP error: %s %s)', ocsp_url, req.status_code, req.reason)
        except Exception as e:
            logging.warning('Unable to retrieve OCSP response from %s: %s', ocsp_url, str(e))
        return None
