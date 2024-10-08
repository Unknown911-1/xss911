import re
import time
import requests
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from lib.utils.logger import logger, log_payload, log_traffic_in, log_traffic_out
from lib.requests.req import session_get


def get_limits():
    with open('settings/limits.json', 'r') as f:
        limits = json.load(f)
        if 'vuln_limit' in limits:
            return limits['vuln_limit']
        else:
            limits['vuln_limit'] = 5
            json.dump(limits, open('settings/limits.json', 'w'))
            return limits['vuln_limit']

VULNERABILITY_LIMIT = get_limits()
found_vulnerabilities = 0


def req_settings():
    try:
        with open('settings/request.json', 'r') as f:
            settings = json.load(f)
            if settings['request'] == 'session':
                return True

            elif settings['request'] == 'request':
                return False

    except FileNotFoundError:
        logger.error("Request settings file not found.")
        return False


# Set the limit for the number of vulnerabilities to sto

class LimitReachedException(Exception):
    pass

def reset_vulnerability_counter():
    global found_vulnerabilities
    found_vulnerabilities = 0

def res_analyzer(res, payload, type='blind'):
    global found_vulnerabilities

    if found_vulnerabilities >= VULNERABILITY_LIMIT:
        raise LimitReachedException("Vulnerability limit reached. Stopping the scan.")

    start_time = time.time()

    # Analyze the response
    response_text = res.text
    payload_in_text = payload in response_text
    payload_in_content = payload in str(res.content)
    script_execution_indicators = re.search(r'<script|alert\(', response_text, re.IGNORECASE)

    response_time = time.time() - start_time

    # Logging traffic received
    log_traffic_in(f"Received response from {res.url} with status {res.status_code}")

    # Pattern Matching
    if payload_in_text or payload_in_content:
        log_payload(f"Blind XSS found with payload: {payload}\nURL: {res.url}")
        found_vulnerabilities += 1
        if found_vulnerabilities >= VULNERABILITY_LIMIT:
            raise LimitReachedException("Vulnerability limit reached. Stopping the scan.")
        return True
    elif script_execution_indicators:
        log_payload(f"Script execution indicator found with payload: {payload}\nURL: {res.url}")
        found_vulnerabilities += 1
        if found_vulnerabilities >= VULNERABILITY_LIMIT:
            raise LimitReachedException("Vulnerability limit reached. Stopping the scan.")
        return True

    logger.debug(f"No XSS or script execution detected with payload: {payload}\nURL: {res.url}")
    return False

def send_request_with_header_payloads(url, payload, headers=None):
    try:
        if headers is None:
            headers = {
                'User-Agent': payload,
                'Referer': payload,
                'Cookie': f'test={payload}'
            }
        # Log the outgoing request
        log_traffic_out(f"Sending request with payload in headers to {url}")
        if req_settings():
            session = session_get(url)
            response = session.get(url, headers=headers, timeout=10)
        else:
            response = requests.get(url, headers=headers)
        return response
    except requests.RequestException as e:
        logger.error(f'Error sending request with payload {payload}: {e}')
        return None

def form_request(url, data, method, payload):
    try:
        log_traffic_out(f"Sending {method.upper()} request to {url} with payload: {payload}")
        if method == 'post':
            if req_settings():
                session = session_get(url)
                res = session.post(url, data=data, timeout=10)

            else:
                res = requests.post(url, data=data, timeout=10)
        elif method == 'get':
            if req_settings():
                session = session_get(url)
                res = session.get(url, params=data, timeout=10)
            else:
                res = requests.get(url, params=data, timeout=10)
        else:
            logger.error(f'Invalid method: {method}')
            return None
        res_analyzer(res, payload)
        return res
    except requests.RequestException as e:
        logger.error(f'Error fetching the URL {url} with method {method}: {e}')
        return None

def url_request(url, data, payload, action):
    try:
        parsed_url = urlparse(url)

        if action == 'query':
            query_params = parse_qs(parsed_url.query)
            for param in query_params:
                query_params[param] = [payload]
            modified_query = urlencode(query_params, doseq=True)
            modified_url = urlunparse(parsed_url._replace(query=modified_query))
            log_traffic_out(f"Sending GET request with payload in query params to {modified_url}")
            if req_settings():
                session = session_get(url)
                res = session.get(modified_url, timeout=10)
            else:
                response = requests.get(modified_url, timeout=10)

        elif action == 'fragment':
            fragment_url = f'{url}#{payload}' if not parsed_url.fragment else f'{url}#{payload}'
            log_traffic_out(f"Sending GET request with payload in fragment to {fragment_url}")
            if req_settings():
                session = session_get(url)
                response = requests.get(fragment_url, timeout=10)
            else:
                response = requests.get(fragment_url, timeout=10)
                
        elif action == 'path':
            path_url = f'{url}/{payload}' if not parsed_url.path else f'{url}/{payload}'
            log_traffic_out(f"Sending GET request with payload in path to {path_url}")
            if req_settings():
                session = session_get(url)
                response = requests.get(path_url, timeout=10)
            else:
                response = requests.get(path_url, timeout=10)

        else:
            logger.error(f'Invalid action: {action}')
            return None

        if response.status_code == 200:
            res_analyzer(response, payload)
            return response
        else:
            logger.error(f'Unexpected status code {response.status_code} for URL: {url}')
            return None

    except requests.RequestException as e:
        logger.error(f'Error in URL request: {e}')
        return None

def check_stored_payload(url, payload):
    try:
        log_traffic_out(f"Checking stored payload by sending GET request to {url}")
        if req_settings():
            session = session_get(url)
            response = session.get(url, timeout=10)
        else:
            response = requests.get(url)
            
        response.raise_for_status()
        type = 'stored'
        res_analyzer(response, payload, type)

    except requests.RequestException as e:
        logger.error(f'Error in URL request: {e}')
        return None
