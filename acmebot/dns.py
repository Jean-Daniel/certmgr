import binascii
import subprocess

import collections
import logging
import time

import DNS

TLSAData = collections.namedtuple('TLSAData', ['host', 'port', 'usage', 'selector', 'protocol', 'ttl',
                                               'certificates', 'chain', 'private_keys'])


def _dns_request(name, ty, name_server=None):
    try:
        request = DNS.Request(server=name_server) if name_server else DNS.Request()
        response = request.req(name=name, qtype=ty, protocol='tcp')
        attempt_count = 9
        while ('SERVFAIL' == response.header['status']) and (0 < attempt_count):
            time.sleep(5)
            response = request.req(name=name, qtype=ty, protocol='tcp')
            attempt_count -= 1
        if 'NOERROR' == response.header['status']:
            return response, None
        return None, response.header['status']
    except Exception as error:
        logging.warning('DNS Error requesting "%s" record for "%s%s": %s', str(ty), name, (' @' + name_server) if name_server else '', str(error))
    return None, None


def get_primary_name_server(zone_name):
    response, status = _dns_request(zone_name, 'SOA')
    if response:
        return response.answers[0]['data'][0]
    logging.warning('Unable to find primary name server for "%s": %s', zone_name, status)
    return None


def get_name_servers(zone_name):
    response, status = _dns_request(zone_name, 'NS')
    if response:
        return [answer['data'] for answer in response.answers]
    logging.warning('Unable to find name servers for "%s": %s', zone_name, status)
    return []


def lookup_dns_challenge(name_server, domain_name):
    response, _ = _dns_request('_acme-challenge.' + domain_name, 'TXT', name_server)
    if response:
        return [answer['data'][0].decode('ascii') for answer in response.answers]
    return []


def lookup_tlsa_records(name_server, host, port, protocol):
    response, _ = _dns_request('_{port}._{protocol}.{host}'.format(port=port, protocol=protocol, host=host), 52, name_server)
    if response:
        return ['{} {} {} {}'.format(answer['data'][0], answer['data'][1], answer['data'][2], binascii.hexlify(answer['data'][3:]).decode('ascii'))
                for answer in response.answers]
    return []


def tlsa_data(records, certificates=None, chain=None, private_keys=None):
    data = []
    for record in records:
        if isinstance(record, str):
            record = {'host': record}
        data.append(TLSAData(record.get('host', '@'), record.get('port', 443),
                             record.get('usage', 'pkix-ee'), record.get('selector', 'spki'),
                             record.get('protocol', 'tcp'), record.get('ttl', 300),
                             certificates, chain or [], private_keys))
    return data


def reload_zone(reload_command, zone_name, critical=True):
    if not reload_command:
        if critical:
            logging.error('reload_zone_command not configured and needed for local DNS updates, '
                          'either configure local DNS updates or switch to http authorizations')
        return
    try:
        subprocess.check_output([reload_command, zone_name], stderr=subprocess.STDOUT)
        logging.debug('Reloading zone "%s"', zone_name)
        time.sleep(2)
    except subprocess.CalledProcessError as error:
        if critical:
            logging.error('Failed to reload zone "%s", code: %s: %s', zone_name, error.returncode, str(error.output))
        else:
            logging.warning('Failed to reload zone "%s", code: %s: %s', zone_name, error.returncode, str(error.output))
    except Exception as error:
        if critical:
            logging.error('Failed to reload zone "%s": %s', zone_name, str(error))
        else:
            logging.warning('Failed to reload zone "%s": %s', zone_name, str(error))


def update_zone(update_command, updates, zone_name, zone_key, operation):
    server = 'server {server} {port}\n'.format(server=zone_key['server'], port=zone_key.get('port', '')) if ('server' in zone_key) else ''
    update_commands = '{server}zone {zone}\n{update}\nsend\n'.format(server=server, zone=zone_name, update='\n'.join(updates))
    try:
        logging.debug('nsupdate:\n%s', update_commands)
        subprocess.check_output([update_command, '-v', '-k', zone_key['file']],
                                input=update_commands.encode('ascii'), stderr=subprocess.STDOUT)
        logging.debug('%s records for %s', operation, zone_name)
        return True
    except subprocess.CalledProcessError as error:
        logging.warning('%s records failed for %s, code: %s:\n%s', operation, zone_name, error.returncode, str(error.output))
    except Exception as error:
        logging.warning('%s records failed for %s: %s', operation, zone_name, str(error))
    return False
