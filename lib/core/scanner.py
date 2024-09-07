import time
from lib.core.attack_vectors import form_vectors, url_vectors, http_vectors
from lib.core.blind_xss import form_vector, url_vector, http_vector
from lib.payloads.payload import Payloads
from lib.core.dom_scanner import dom_xss_attack
from lib.analyzers.response_analyzer import LimitReachedException
from lib.utils.logger import logger, log_traffic_in, log_traffic_out, log_payload

DISPLAY_LIMIT = 3
found_vulnerabilities = 0

def load_payloads(type, action):
    # Log the action of loading payloads for XSS scans
    logger.info(f'Loading {type} payloads for action: {action}')

    payloads = None
    if type in ['blind', 'reflective', 'stored', 'dom']:
        payloads = Payloads(action, type)
        if payloads:
            log_payload(f'Loaded {len(payloads)} payloads for type: {type} and action: {action}')
        else:
            logger.error(f'Failed to load payloads for type: {type} and action: {action}')
    else:
        logger.error('Invalid payload type')

    return payloads

def reflective_scan(url, type, action, payloads):
    log_traffic_out(f'Starting reflective XSS scan on {url}')

    try:
        if not payloads:
            logger.error(f'No payloads available for reflective scan on {url}')
            return

        for payload in payloads:
            # Check if limit has been reached before processing the payload
            if found_vulnerabilities >= DISPLAY_LIMIT:
                raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")

            form_vectors(url, type, action, [payload])
            url_vectors(url, action, [payload])
            http_vectors(url, action, [payload])

    except LimitReachedException as e:
        logger.info(f"Reflective scan stopped: {e}")
        return  # Stop the scan when limit is reached

    log_traffic_in(f'Reflective XSS scan completed on {url}')

def blind_scan(url, type, action, payloads):
    log_traffic_out(f'Starting blind XSS scan on {url}')

    try:
        if not payloads:
            logger.error(f'No payloads available for blind scan on {url}')
            return

        for payload in payloads:
            # Check if limit has been reached before processing the payload
            if found_vulnerabilities >= DISPLAY_LIMIT:
                raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")

            form_vector(url, type, action, [payload])
            url_vector(url, action, [payload])
            http_vector(url, action, [payload])

    except LimitReachedException as e:
        logger.info(f"Blind scan stopped: {e}")
        return  # Stop the scan when limit is reached

    log_traffic_in(f'Blind XSS scan completed on {url}')

def scan(url, action, type):
    start_time = time.time()

    try:
        payloads = load_payloads(type, action)

        if type == 'reflective':
            logger.info(f'Scanning for reflective XSS on {url}')
            reflective_scan(url, type, action, payloads)

        elif type == 'stored':
            logger.info(f'Scanning for stored XSS on {url}')
            if payloads:
                form_vectors(url, type, action, payloads)
            else:
                logger.error(f'No payloads available for stored scan on {url}')

        elif type == 'blind':
            logger.info(f'Scanning for blind XSS on {url}')
            blind_scan(url, type, action, payloads)

        elif type == 'dom':
            logger.info(f'Scanning for DOM-Based XSS on {url}')
            if payloads:
                dom_xss_attack(url, action, payloads)
            else:
                logger.error(f'No payloads available for DOM-based scan on {url}')

        else:
            logger.error(f'Invalid scan type: {type}')
            return

    except LimitReachedException as e:
        logger.info(f"Scan stopped: {e}")

    end_time = time.time()
    total_time = end_time - start_time
    logger.info(f'{type.capitalize()} XSS scan completed in {total_time:.2f} seconds')
