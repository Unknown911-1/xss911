import time
from lib.core.attack_vectors import form_vectors, url_vectors, http_vectors
from lib.core.blind_xss import form_vector, url_vector, http_vector
from lib.payloads.payload import Payloads
from lib.core.dom_scanner import dom_xss_attack
from lib.utils.logger import logger, log_traffic_in, log_traffic_out, log_payload

def load_payloads(type, action):
    # Log the action of loading payloads for XSS scans
    logger.info(f'Loading {type} payloads for action: {action}')

    payloads = None
    if type in ['blind', 'reflective', 'stored', 'dom']:
        payloads = Payloads(action, type)
        log_payload(f'Loaded {len(payloads)} payloads for type: {type} and action: {action}')
    else:
        logger.error('Invalid payload type')

    return payloads

def reflective_scan(url, type, action, payloads):
    # Log outgoing scan action
    log_traffic_out(f'Starting reflective XSS scan on {url}')

    form_vectors(url, type, action, payloads)
    url_vectors(url, action, payloads)
    http_vectors(url, action, payloads)

    # Log completion of scan
    log_traffic_in(f'Reflective XSS scan completed on {url}')

def blind_scan(url, type, action, payloads):
    # Log outgoing scan action
    log_traffic_out(f'Starting blind XSS scan on {url}')

    form_vector(url, type, action, payloads)
    url_vector(url, action, payloads)
    http_vector(url, action, payloads)

    # Log completion of scan
    log_traffic_in(f'Blind XSS scan completed on {url}')

def scan(url, action, type):
    start_time = time.time()

    if type == 'reflective':
        logger.info(f'Scanning for reflective XSS on {url}')
        payloads = load_payloads(type, action)
        reflective_scan(url, type, action, payloads)

    elif type == 'stored':
        logger.info(f'Scanning for stored XSS on {url}')
        payloads = load_payloads(type, action)
        form_vectors(url, type, action, payloads)

    elif type == 'blind':
        logger.info(f'Scanning for blind XSS on {url}')
        payloads = load_payloads(type, action)
        blind_scan(url, type, action, payloads)

    elif type == 'dom':
        logger.info(f'Scanning for DOM-Based XSS on {url}')
        payloads = load_payloads(type, action)
        dom_xss_attack(url, action)

    else:
        logger.error(f'Invalid scan type: {type}')
        return

    end_time = time.time()
    total_time = end_time - start_time
    logger.info(f'{type.capitalize()} XSS scan completed in {total_time:.2f} seconds')
