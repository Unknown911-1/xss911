import requests
import json
from urllib.parse import urlparse, parse_qs
from lib.analyzers.dom_analyzer import dom_xss_analyzer, LimitReachedException
from lib.utils.logger import logger
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
        
def dom_xss_attack(url, action, payloads):
    try:
        # Send a GET request to the URL
        if req_settings():
            session = session_get(url)
            res = session.get(url, timeout=10)
        else:
            res = requests.get(url, timeout=10)
            
        res.raise_for_status()

        # Parse the URL to extract query parameters
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)

        if url_params:
            for key in url_params.keys():
                logger.info(f"Scanning for DOM-Based XSS on parameter: {key}")
                dom_xss_analyzer(url, res, key, action, payloads)

    except requests.RequestException as e:
        logger.error(f'Error in URL request: {e}')
        return None

    except LimitReachedException as e:
        logger.info(f"Stopping scan: {e}")
        return None
