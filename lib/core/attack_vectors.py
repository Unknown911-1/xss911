import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from lib.utils.logger import logger
from lib.core.request_handler import send_request_with_header_payloads as send_request, form_request, url_request, check_stored_payload
from reports.reports import record_request_params, record_request_form, record_request_headers
from lib.analyzers.response_analyzer import LimitReachedException
from lib.requests.req import session_get

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

def form_vectors(url, type, action, payloads):
    global found_vulnerabilities
    try:
        if req_settings():
            session = session_get(url)
            response = session.get(url, timeout=10)
        else:
            response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f'Error fetching the URL {url}: {e}')
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        logger.info(f'No forms found on the page: {url}')
        return

    for form in forms:
        actions = form.get('action')
        method = form.get('method', 'get').lower()
        form_url = urljoin(url, actions) if actions else url

        for payload in payloads:
            if found_vulnerabilities >= DISPLAY_LIMIT:
                raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")

            data = {}
            for input_tag in form.find_all(['input', 'textarea']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    if input_type in ['text', 'textarea', 'email', 'password']:
                        data[input_name] = payload
                    elif input_type == 'hidden':
                        data[input_name] = input_tag.get('value', '')

            res = form_request(form_url, data, method, payload)
            if res:
                logger.debug(f"Form Request Payload: {payload}, Status Code: {res.status_code}, Content: {res.text}")
                if res.status_code == 200:
                    found_vulnerabilities += 1
                record_request_form(url, data, payload, res.status_code)

def find_params(url):
    try:
        if req_settings():
            session = session_get(url)
            response = session.get(url, timeout=10)
        else:
            response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        params = []
        for input_tag in soup.find_all('input'):
            if 'name' in input_tag.attrs:
                params.append(input_tag['name'])
        return params

    except requests.exceptions.RequestException as e:
        logger.error(f'Error fetching parameters from {url}: {e}')
        return []

def url_vectors(url, action, payloads):
    global found_vulnerabilities
    parsed_url = urlparse(url)

    if parsed_url.query:
        parsed_query = parsed_url.query.split('&')
        for query in parsed_query:
            if '=' in query:
                key, _ = query.split('=')
                for payload in payloads:
                    if found_vulnerabilities >= DISPLAY_LIMIT:
                        raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")
                    res = url_request(url, {key: payload}, payload, 'query')
                    if res:
                        logger.debug(f"URL Request Query Payload: {payload}, Status Code: {res.status_code}, Content: {res.text}")
                        if res.status_code == 200:
                            found_vulnerabilities += 1
                        record_request_params(url, {key: payload}, payload, res.status_code)

    elif parsed_url.fragment:
        for payload in payloads:
            if found_vulnerabilities >= DISPLAY_LIMIT:
                raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")
            res = url_request(url, {}, payload, 'fragment')
            if res:
                logger.debug(f"URL Request Fragment Payload: {payload}, Status Code: {res.status_code}, Content: {res.text}")
                if res.status_code == 200:
                    found_vulnerabilities += 1
                record_request_params(url, {parsed_url.fragment: payload}, payload, res.status_code)

    elif parsed_url.path:
        if parsed_url.path.endswith('/'):
            parsed_path = parsed_url.path[:-1]
            for payload in payloads:
                if found_vulnerabilities >= DISPLAY_LIMIT:
                    raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")
                res = url_request(url, {}, payload, 'path')
                if res:
                    logger.debug(f"URL Request Path Payload: {payload}, Status Code: {res.status_code}, Content: {res.text}")
                    if res.status_code == 200:
                        found_vulnerabilities += 1
                    record_request_params(url, {parsed_path: payload}, payload, res.status_code)
        else:
            for payload in payloads:
                if found_vulnerabilities >= DISPLAY_LIMIT:
                    raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")
                params = find_params(url)
                for param in params:
                    res = url_request(url, {param: payload}, payload, 'param')
                    if res:
                        logger.debug(f"URL Request Param Payload: {payload}, Status Code: {res.status_code}, Content: {res.text}")
                        if res.status_code == 200:
                            found_vulnerabilities += 1
                        record_request_params(url, {param: payload}, payload, res.status_code)

    else:
        for payload in payloads:
            if found_vulnerabilities >= DISPLAY_LIMIT:
                raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")
            record_request_params(url, {}, payload, 'no_params')

def http_vectors(url, action, payloads, headers=None):
    global found_vulnerabilities
    for payload in payloads:
        if found_vulnerabilities >= DISPLAY_LIMIT:
            raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")
        res = send_request(url, payload, headers)
        if res:
            logger.debug(f"HTTP Request Payload: {payload}, Status Code: {res.status_code}, Content: {res.text}")
            if res.status_code == 200:
                found_vulnerabilities += 1
            record_request_headers(url, headers if headers else res.headers, payload, res.status_code)


