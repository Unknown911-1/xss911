import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from lib.utils.logger import logger
from lib.analyzers.response_analyzer import res_analyzer, LimitReachedException

def send_request_with_header_payloads(url, payload, headers=None):
    if headers is None:
        headers = {
            'User-Agent': payload,
            'Referer': payload,
            'Cookie': f'test={payload}'
        }
    try:
        response = requests.get(url, headers=headers)
        return response
    except requests.RequestException as e:
        logger.error(f'Error sending request with payload {payload}: {e}')
        return None

def form_request(url, data, method, payload):
    try:
        if method == 'post':
            res = requests.post(url, data=data)
        elif method == 'get':
            res = requests.get(url, params=data)
        else:
            logger.error(f'Invalid method: {method}')
            return None
        res_analyzer(res, payload)
        return res
    except requests.RequestException as e:
        logger.error(f'Error fetching the URL {url} with method {method}: {e}')
        return None

    except LimitReachedException as e:
        logger.info(f"Stopping scan: {e}")
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
            response = requests.get(modified_url, timeout=10)

        elif action == 'fragment':
            fragment_url = f'{url}#{payload}' if not parsed_url.fragment else f'{url}#{payload}'
            response = requests.get(fragment_url, timeout=10)

        elif action == 'path':
            path_url = f'{url}/{payload}' if not parsed_url.path else f'{url}/{payload}'
            response = requests.get(path_url, timeout=10)

        elif action == 'param':
            if not data:
                logger.error('No parameters provided for URL action.')
                return None
            param = list(data.keys())[0]
            param_url = f'{url}?{param}={payload}'
            response = requests.get(param_url, timeout=10)

        else:
            logger.error(f'Invalid action: {action}')
            return None

        if response and response.status_code == 200:
            res_analyzer(response, payload)
            return response
        else:
            if response:
                logger.error(f'Unexpected status code {response.status_code} for URL: {url}')
            else:
                logger.error(f'Failed to get a response from URL: {url}')
            return response

    except requests.RequestException as e:
        logger.error(f'Error in URL request: {e}')
        return None

    except LimitReachedException as e:
        logger.info(f"Stopping scan: {e}")
        return None

def check_stored_payload(url, payload):
    # Perform a second request to check if the payload is reflected
    try:
        response = requests.get(url)
        response.raise_for_status()
        type = 'stored'
        res_analyzer(response, payload, type)

    except requests.RequestException as e:
        logger.error(f'Error in URL request: {e}')
        return None

    except LimitReachedException as e:
        logger.info(f"Stopping scan: {e}")
        return None
