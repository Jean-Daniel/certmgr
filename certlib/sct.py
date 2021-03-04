# SCT Support
import base64
from typing import List, NamedTuple, Optional

import requests

from .crypto import Certificate
from .logging import log


class SCTLog(NamedTuple):
    name: str
    id: bytes
    url: str


class SCTData(NamedTuple):
    version: int
    id: bytes
    timestamp: int
    extensions: bytes
    signature: Optional[bytes]


def fetch_sct(ct_log: SCTLog, certificate: Certificate, chain: List[Certificate]) -> SCTData:
    certificates = ([base64.b64encode(certificate.encode(pem=False)).decode('ascii')]
                    + [base64.b64encode(chain_certificate.encode(pem=False)).decode('ascii') for chain_certificate in chain])

    req = requests.post(ct_log.url + '/ct/v1/add-chain', json={'chain': certificates})
    try:
        if req.status_code == 200:
            sct = req.json()
            sid = sct.get('id')
            ext = sct.get('extensions')
            sign = sct.get('signature')
            return SCTData(sct.get('sct_version'), base64.b64decode(sid) if sid else b'', sct.get('timestamp'),
                           base64.b64decode(ext) if ext else b'', base64.b64decode(sign) if sign else None)
        if 400 <= req.status_code < 500:
            log.warning('Unable to retrieve SCT from log %s (HTTP error: %s %s): "%s"', ct_log.name, req.status_code, req.reason, req.content)
        else:
            log.warning('Unable to retrieve SCT from log %s (HTTP error: %s %s)', ct_log.name, req.status_code, req.reason)
    except Exception as e:
        log.warning('Unable to retrieve SCT from log %s: %s', ct_log.name, str(e), print_exc=True)
