import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from lib.utils.logger import logger
from lib.analyzers.blind_analyzer import send_request_with_header_payloads as send_request, form_request, url_request, LimitReachedException
from reports.reports import blind_xss_report

def form_vector(url, type, action, payloads):
    try:
        response = requests.get(url)
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
        action = form.get('action')
        method = form.get('method', 'get').lower()
        form_url = urljoin(url, action) if action else url

        for payload in payloads:
            data = {}
            for input_tag in form.find_all(['input', 'textarea']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    if input_type in ['text', 'textarea', 'email', 'password']:
                        data[input_name] = payload
                    elif input_type == 'hidden':
                        data[input_name] = input_tag.get('value', '')
            try:
                
                res = form_request(form_url, data, method, payload)
                blind_xss_report(url, data, payload, res.status_code)

            except LimitReachedException as e:
                logger.info(f"Stopping scan: {e}")
                return

def find_params(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        params = []
        for input_tag in soup.find_all('input'):
            if 'name' in input_tag.attrs:
                params.append(input_tag['name'])
        return params

    except requests.exceptions.RequestException as e:
        return False


def url_vector(url, action, payloads):
    parsed_url = urlparse(url)

    try:
        if parsed_url.query:
            parsed_query = parsed_url.query.split('&')
            for query in parsed_query:
                if '=' in query:
                    key, _ = query.split('=')
                    for payload in payloads:
                        res = url_request(url, {key: payload}, payload, 'query')
                        blind_xss_report(url, {key: payload}, payload, res.status_code)

        elif parsed_url.fragment:
            for payload in payloads:
                res = url_request(url, {}, payload, 'fragment')
                blind_xss_report(url, {parsed_url.fragment: payload}, payload, res.status_code)

        elif parsed_url.path:
            if parsed_url.path.endswith('/'):
                parsed_path = parsed_url.path[:-1]
                for payload in payloads:
                    res = url_request(url, {}, payload, 'path')
                    blind_xss_report(url, {parsed_path: payload}, payload, res.status_code)
            else:
                for payload in payloads:
                    params = find_params(url)
                    for param in params:
                        res = url_request(url, {param: payload}, payload, 'param')
                        blind_xss_report(url, {param: payload}, payload, res.status_code)

        else:
            for payload in payloads:
                blind_xss_report(url, 'none', payload)

    except LimitReachedException as e:
        logger.info(f"Stopping scan: {e}")
        return

def http_vector(url, action, payloads, headers=None):
    for payload in payloads:
        try:
            
            res = send_request(url, payload, headers)
            blind_xss_report(url, headers if headers else res.headers, payload, res.status_code)
        except LimitReachedException as e:
            logger.info(f"Stopping scan: {e}")
            return