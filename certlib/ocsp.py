import logging
import urllib
from datetime import datetime
from typing import Optional
from urllib import request, parse, error

from asn1crypto import ocsp


def load_ocsp_response(filepath: str) -> Optional[ocsp.OCSPResponse]:
    try:
        with open(filepath, 'rb') as ocsp_file:
            return ocsp.OCSPResponse.load(ocsp_file.read())
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.warning('OSCP response "%s" loading failed: %s', filepath, str(e))
    return None


def ocsp_response_serial_number(ocsp_response):
    if 'cert_id' in ocsp_response.response_data['responses'][0]:
        return ocsp_response.response_data['responses'][0]['cert_id']['serial_number'].native
    return None


def ocsp_response_this_update(ocsp_response):
    if 'this_update' in ocsp_response.response_data['responses'][0]:
        return datetime.strptime(str(ocsp_response.response_data['responses'][0]['this_update']), "%Y%m%d%H%M%SZ")
    return None


def ocsp_response_next_update(ocsp_response):
    if 'next_update' in ocsp_response.response_data['responses'][0]:
        return datetime.strptime(str(ocsp_response.response_data['responses'][0]['next_update']), "%Y%m%d%H%M%SZ")
    return None


def ocsp_response_status(ocsp_response):
    return ocsp_response.response_data['responses'][0]['cert_status'].name


def fetch_ocsp_response(ocsp_url, ocsp_request, last_update):
    req = urllib.request.Request(url=ocsp_url, data=ocsp_request.dump())
    req.add_header('Content-Type', 'application/ocsp-req')
    req.add_header('Accept', 'application/ocsp-response')
    req.add_header('Host', urllib.parse.urlparse(ocsp_url).hostname)
    if last_update:
        req.add_header('If-Modified-Since', last_update.strftime('%a, %d %b %Y %H:%M:%S GMT'))
    try:
        with urllib.request.urlopen(req) as response:
            # XXX add validation of response
            return ocsp.OCSPResponse.load(response.read())
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
