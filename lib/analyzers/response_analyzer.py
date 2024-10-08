import re
import sys
import time
import json
from lib.utils.logger import logger, log_payload, log_traffic_in, log_traffic_out


# Set the limit for the number of vulnerabilities to display
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

class LimitReachedException(Exception):
    pass

def reset_vulnerability_counter():
    global found_vulnerabilities
    found_vulnerabilities = 0

def res_analyzer(res, payload, type='reflective'):
    global found_vulnerabilities

    if found_vulnerabilities >= DISPLAY_LIMIT:
        raise LimitReachedException("DISPLAY_LIMIT reached. Stopping the scan.")

    start_time = time.time()

    # Log outgoing request (sending the payload)
    log_traffic_out(f"Sending payload: {payload} to {res.url}")

    # Analyze the response
    response_text = res.text
    payload_in_text = payload in response_text
    payload_in_content = payload in str(res.content)
    script_execution_indicators = re.search(r'<script|alert\(', response_text, re.IGNORECASE)

    # Log incoming response
    log_traffic_in(f"Received response from {res.url} with status {res.status_code}")

    response_time = time.time() - start_time

    # Reflective XSS Detection
    if type == 'reflective':
        if payload_in_text or payload_in_content:
            if found_vulnerabilities < DISPLAY_LIMIT:
                log_payload(f"Reflected XSS found with payload: {payload}\nURL: {res.url}")
                found_vulnerabilities += 1
            return True
        elif script_execution_indicators:
            if found_vulnerabilities < DISPLAY_LIMIT:
                log_payload(f"Script execution indicator found with payload: {payload}\nURL: {res.url}")
                found_vulnerabilities += 1
            return True

    # Stored XSS Detection
    elif type == 'stored':
        if payload_in_text or payload_in_content:
            if found_vulnerabilities < DISPLAY_LIMIT:
                log_payload(f"Stored XSS found with payload: {payload}\nURL: {res.url}")
                found_vulnerabilities += 1
            return True

    # Response Time Analysis
    if response_time > 2:  # Threshold of 2 seconds; adjust as needed
        if found_vulnerabilities < DISPLAY_LIMIT:
            logger.warning(f"Slow response detected with payload: {payload}\nURL: {res.url} Response Time: {response_time:.2f} seconds")
            found_vulnerabilities += 1
        return True

    # Response Validation (Sanitization Check)
    if not is_content_sanitized(response_text):
        if found_vulnerabilities < DISPLAY_LIMIT:
            logger.error(f"Potential XSS vulnerability detected with payload: {payload}\nURL: {res.url}")
            found_vulnerabilities += 1
        return True

    logger.debug(f"No XSS or script execution detected with payload: {payload}\nURL: {res.url}")
    return False

def is_content_sanitized(content):
    """
    Check if the response content properly sanitizes or escapes potential XSS payloads.
    """
    unsanitized_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'on\w+=[\'"]?javascript:',
        r'&lt;script&gt;',
        r'&lt;img.*?src=[\'"]?javascript:'
    ]

    # Check for the presence of any unsanitized patterns
    for pattern in unsanitized_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return False

    return True
