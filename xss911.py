import argparse
from colorama import Fore, Style, init
import os
from lib.core.scanner import scan
from lib.utils.logger import logger, set_verbose_mode
from lib.payloads.payload import Payloads, blind_url_injection

def banner():
    banner = f'''
    {Fore.CYAN}                                                                      
                                                                        {Fore.RED}________  ____ ____ 
                                                {Fore.YELLOW}___  ___  {Fore.CYAN}______ ______/   __   \/_   /_   |
                                                \  \/  / {Fore.GREEN}/  ___//  ___/\____    / |   ||   |
                                                 {Fore.BLUE}>    <  {Fore.MAGENTA}\___ \ \___ \    /    /  |   ||   |
                                                {Fore.RED}/__/\_ \/____  >{Fore.YELLOW}____  >  /____/   |___||___|
                                                      \/     \/     \/                      

                        
        {Style.RESET_ALL}
        '''
    print(banner)
def process_urls(url, action, xss_type):
    # Process a single URL or a file containing a list of URLs
    if url.endswith('.txt'):
        if os.path.exists(url):
            with open(url, 'r') as f:
                urls = f.read().splitlines()
                for url in urls:
                    scan(url, action, xss_type)  # Perform the scan on each URL
        else:
            logger.error(f'File not found: {url}')
    elif url.startswith(('http://', 'https://')):
        scan(url, action, xss_type)  # Perform the scan on a single URL
    else:
        logger.error(f'Invalid URL: {url}')

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
    # Define command-line arguments for the XSS911 tool
    parser = argparse.ArgumentParser(description="XSS911 - A Powerful XSS Scanner")
    parser.add_argument('-u', '--url', type=str, help='The URL to scan for XSS vulnerabilities (accepts file (.txt) of URL)')
    parser.add_argument('-t', '--type', type=str, choices=['reflective', 'stored', 'blind', 'dom'], help='Type of XSS to scan for')
    parser.add_argument('-a', '--action', type=str, choices=['raw', 'encoded'], default='raw', help='Payload action type (default: raw)')
    parser.add_argument('-ad', '--add-payloads', type=str, help='Path to a file with custom payloads')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-b', '--blind_payload_url', type=str, help='URL to check for blind XSS payloads (URL ends with .js or ?data=)')

    args = parser.parse_args()

    banner()
    if args.verbose:
        set_verbose_mode(True)
    else:
        set_verbose_mode(False)

    # Process URL(s) if provided along with the type of XSS
    if args.url and args.type:
        process_urls(args.url, args.action, args.type)

    # Add custom payloads if provided
    if args.add_payloads:
        add_payloads(args.type, args.add_payloads)

    # Inject blind XSS URL payloads if provided
    if args.blind_payload_url:
        inject_blind_url(args.blind_payload_url)

if __name__ == "__main__":
    xss911()
