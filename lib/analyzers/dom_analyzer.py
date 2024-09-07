import re
import time
from bs4 import BeautifulSoup
from lib.utils.logger import logger, log_payload, log_traffic_in, log_traffic_out
from reports.reports import record_dom_attacks

# All known dangerous sinks for DOM-based XSS
SINKS = [
    'innerHTML', 'outerHTML', 'document.write', 'eval', 'setTimeout',
    'setInterval', 'location.href', 'location.hash', 'location.search',
    'window.location', 'element.src', 'element.href', 'element.action',
    'document.cookie', 'localStorage', 'sessionStorage', 'postMessage',
    'onload', 'onclick', 'onmouseover'
]

# Set the limit for the number of vulnerabilities to stop
VULNERABILITY_LIMIT = 3
found_vulnerabilities = 0

class LimitReachedException(Exception):
    pass

def reset_vulnerability_counter():
    global found_vulnerabilities
    found_vulnerabilities = 0

def parse_javascript(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    scripts = soup.find_all('script')
    inline_handlers = soup.find_all(True, {"onclick": True, "onload": True, "onsubmit": True})

    js_code = []

    # Log traffic incoming (the response containing the scripts)
    log_traffic_in(f"Parsing JavaScript from {response.url}")

    for script in scripts:
        if script.string:
            js_code.append(script.string)

    for tag in inline_handlers:
        # Append inline JavaScript code as string from attributes
        js_code.append(" ".join([f"{key}={value}" for key, value in tag.attrs.items() if key.startswith('on')]))

    return js_code

def inspect_dom_manipulation(js_code, url_parameters):
    global found_vulnerabilities

    if found_vulnerabilities >= VULNERABILITY_LIMIT:
        raise LimitReachedException("Vulnerability limit reached. Stopping the scan.")

    vulnerable_code = []

    # Inspect each piece of JavaScript code for dangerous sinks
    for js in js_code:
        for sink in SINKS:
            if sink in js and any(param in js for param in url_parameters):
                logger.warning(f"User input passed to dangerous sink: {sink}")
                vulnerable_code.append(js)
                found_vulnerabilities += 1
                if found_vulnerabilities >= VULNERABILITY_LIMIT:
                    raise LimitReachedException("Vulnerability limit reached. Stopping the scan.")
    return vulnerable_code

def test_payload_injection(url, vulnerable_code, payloads, res):
    for code in vulnerable_code:
        for payload in payloads:
            # Attempt to simulate XSS injection
            injected_code = code.replace("user_input", payload)
            if "alert" in injected_code:  # Simplified detection
                log_payload(f"Potential DOM-Based XSS found: {injected_code}")
                record_dom_attacks(url, code, payload, res)  # Log to reports

def detect_execution(response_time, js_code, payloads):
    for payload in payloads:
        for code in js_code:
            if re.search(payload, code):
                if response_time > 2:  # Detect slow, possibly asynchronous payload execution
                    logger.critical(f"XSS payload executed asynchronously: {payload}")
                else:
                    logger.critical(f"XSS payload detected: {payload}")

def dom_xss_analyzer(url, response, url_parameters, action, payloads):
    global found_vulnerabilities

    # Log the outgoing request that generated this response
    log_traffic_out(f"Analyzing DOM-based XSS for URL: {url}")

    try:
        suspicious_js = parse_javascript(response)
        vulnerable_code = inspect_dom_manipulation(suspicious_js, url_parameters)

        if vulnerable_code:
            test_payload_injection(url, vulnerable_code, payloads, response)

            # Simulate a request handling cycle
            start_time = time.time()
            time.sleep(1)  # Simulate some delay in response processing
            response_time = time.time() - start_time

            # Detect potential XSS execution
            detect_execution(response_time, vulnerable_code, payloads)
        else:
            logger.debug(f"No vulnerable DOM sinks found in the response for {url}.")
    except LimitReachedException as e:
        logger.info(f"Stopping DOM XSS analysis: {e}")
