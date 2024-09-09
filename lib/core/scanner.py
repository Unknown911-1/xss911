import time
import json
import os
from lib.core.attack_vectors import form_vectors, url_vectors, http_vectors
from lib.core.blind_xss import form_vector, url_vector, http_vector
from lib.payloads.payload import Payloads
from lib.core.dom_scanner import dom_xss_attack
from lib.analyzers.response_analyzer import LimitReachedException
from lib.utils.logger import logger, log_traffic_in, log_traffic_out, log_payload
from server import start_server

def get_limits():
    with open('settings/limits.json', 'r') as f:
        limits = json.load(f)
        if 'vuln_limit' in limits:
            return limits['vuln_limit']
        else:
            limits['vuln_limit'] = 5
            json.dump(limits, open('settings/limits.json', 'w'))
            return limits['vuln_limit']

DISPLAY_LIMIT = get_limits()
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


def blind_check():
    with open('xss911/settings/blind.json', 'r') as f:
        data = json.load(f)
        if data['server'] == 'yes':
            return True

        elif data['server'] == 'no':
            return False
        else:
            return False

def delete_blind_check():
    files = 'settings/blind.json'
    if os.path.exists(files):
        os.remove(files)
    file = 'lib/requests/session.pkl'
    if os.path.exists(file):
        os.remove(file)
    
def blind_scan(url, type, action, payloads):
    log_traffic_out(f'Starting blind XSS scan on {url}')

    

    try:
        if blind_check():
            start_server()
            
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
        delete_blind_check()
        logger.info(f"Blind scan stopped: {e}")
        return  # Stop the scan when limit is reached
        
    log_traffic_in(f'Blind XSS scan completed on {url}')
    delete_blind_check()


        
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

    except Exception as e:
        logger.error(f'Error occurred during scan: {e}')
        
    except KeyboardInterrupt:
        logger.info(f"Scan interrupted by user. Exiting...")
        exit()

    end_time = time.time()
    total_time = end_time - start_time
    logger.info(f'{type.capitalize()} XSS scan completed in {total_time:.2f} seconds')

