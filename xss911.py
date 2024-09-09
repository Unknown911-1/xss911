import argparse
from colorama import Fore, Style, init
import os
import json
import requests
from lib.utils.logger import logger, set_verbose_mode
from lib.payloads.payload import Payloads, blind_url_injection
from settings import settings


def banner():
    banner = f'''
    {Fore.CYAN}                                                                      
    {Fore.RED}________  ____ ____ 
    {Fore.YELLOW}___  ___  {Fore.CYAN}______ ______/   __   \/_   /_   |
    \  \/  / {Fore.GREEN}/  ___//  ___/\____    / |   ||   |
    {Fore.BLUE}>    <  {Fore.MAGENTA}\___ \ \___ \    /    /  |   ||   |
    {Fore.RED}/__/\_ \/____  >{Fore.YELLOW}____  >  /____/   |___||___|
    '''
    print(banner)

# Assuming login_json is needed, this function should handle login info
def login_json(data):
    with open('settings/request.json', 'w') as f:
        json.dump(data, f, indent=2)

# Check if the URL redirects
def check_url_redirect(url):
    try:
        response = requests.get(url, allow_redirects=False)
        data = {}

        if response.is_redirect or response.is_permanent_redirect:
            redirect_location = response.headers.get('Location')
            logger.error(f"URL {url} is redirected to {redirect_location}")
            data['request'] = 'session'
            login_json(data)
            return False
        else:
            logger.info(f"URL {url} is not redirected. Status code: {response.status_code}")
            data['request'] = 'request'
            login_json(data)
            return True
    except requests.RequestException as e:
        logger.error(f"An error occurred: {e}")
        return True


def process_urls(url, action, xss_type):
    from lib.core.scanner import scan
    if url.endswith('.txt'):
        if os.path.exists(url):
            with open(url, 'r') as f:
                urls = f.read().splitlines()
                for url in urls:
                    scan(url, action, xss_type)
        else:
            logger.error(f'File not found: {url}')
    elif url.startswith(('http://', 'https://')):
        scan(url, action, xss_type)
    else:
        logger.error(f'Invalid URL: {url}')


def set_limit(limit):
    file_path = 'settings/limits.json'

    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}
    else:
        data = {}

    data['vuln_limit'] = limit

    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

def add_payloads(payload_type, custom_file):
    # Add new payloads from a custom file to the existing payloads
    if os.path.exists(custom_file):
        logger.info('Adding new payloads to old payloads')
        Payloads('custom', payload_type, custom_file)
    else:
        logger.error(f'File not found: {custom_file}')


def inject_blind_url(blind_payload_url):
    # Inject a blind XSS payload URL into the system for testing
    if blind_payload_url.endswith('.js') or blind_payload_url.endswith('='):
        logger.info('Injecting URL into blind payloads')
        if blind_url_injection(blind_payload_url):
            logger.critical('Blind XSS URL injection to payloads complete')
        else:
            logger.error('URL injection failed or URL not found in payloads')
    else:
        logger.error(f'Invalid URL: {blind_payload_url}')


def xss911():
    parser = argparse.ArgumentParser(description="XSS911 - A Powerful XSS Scanner")
    parser.add_argument('-u', '--url', type=str, help='The URL to scan for XSS vulnerabilities (accepts file (.txt) of URL)')
    parser.add_argument('-t', '--type', type=str, choices=['reflective', 'stored', 'blind', 'dom'], help='Type of XSS to scan for')
    parser.add_argument('-a', '--action', type=str, choices=['raw', 'encoded'], default='raw', help='Payload action type (default: raw)')
    parser.add_argument('-ad', '--add-payloads', type=str, help='Path to a file with custom payloads')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-b', '--blind_payload_url', type=str, help='URL to check for blind XSS payloads (URL ends with .js or ?data=)')
    parser.add_argument('-l', '--limit', type=int, default=5, help='Number of vulnerabilities to display (default: 5)')
    parser.add_argument('--blind', action="store_true", help='Start a webserver and host it for testing blind XSS payloads')
    parser.add_argument('--login', action='store_true', help='Login to the Target Website to visit URL page')

    args = parser.parse_args()

    banner()

    if args.verbose:
        set_verbose_mode(True)

    else:
        set_verbose_mode(False)

    if args.limit:
        set_limit(args.limit)

    if args.blind:
        with open('settings/blind.json', 'r') as f:
            data = json.load(f)

        with open('settings/blind.json', 'w') as f:
            data['server'] = 'yes'
            json.dump(data, f, indent=2)
    else:
        with open('settings/blind.json', 'r') as f:
            data = json.load(f)

        with open('settings/blind.json', 'w') as f:
            data['server'] = 'no'
            json.dump(data, f, indent=2)

    if args.url and args.type:
        if args.login:
            check_url_redirect(args.url)

        process_urls(args.url, args.action, args.type)

    if args.add_payloads:
        add_payloads(args.type, args.add_payloads)

    if args.blind_payload_url:
        inject_blind_url(args.blind_payload_url)


if __name__ == "__main__":
    xss911()
