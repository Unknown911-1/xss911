import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from lib.utils.logger import logger

login_path = ['/login', '/signin', '/auth', '/access', '/user/login', '/account/login', '/enter', '/session/login', '/members/login', '/welcome/login']

def find_login_page(url):
    try:
        url_parse = urlparse(url)
        url_scheme = url_parse.scheme
        url_netloc = url_parse.netloc
        url_main = f'{url_scheme}://{url_netloc}'
        response = requests.get(url)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')  # Add soup parsing

            # Check for login forms or buttons on the main page
            texts = ['Login', 'Log In', 'Sign In', 'SignIn', 'Log-In', 'Sign-In']
            for text in texts:
                login_button = soup.find('a', text=text)
                if login_button:
                    login_url = urljoin(url, login_button['href'])
                    logger.info(f"Login page found via button: {login_url}")
                    return login_url

            # If not found, check known login paths
            for path in login_path:
                log_page = f"{url_main}{path}"
                try:
                    res = requests.get(log_page)
                    if res.status_code == 200:
                        logger.info(f"Login page found via path: {log_page}")
                        return log_page
                except requests.exceptions.RequestException as e:
                    logger.error(f'Error fetching login page: {e}')
                    continue  # Continue checking other paths

            # No login page found
            logger.error("No login page found.")
            return None

        else:
            logger.error(f"Error accessing the page: {url}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f'Error fetching login page: {e}')
        return None

def find_login_form(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            form = soup.find('form')

            fields = {}
            for input_tag in form.find_all('input'):
                field_name = input_tag.get('name')
                field_type = input_tag.get('type')

                if field_type in ['text', 'password']:  # Fixed this condition
                    if field_name:
                        fields[field_name] = input_tag.get('value', '')

            return fields

        else:
            logger.error(f"Failed to fetch the login form at {url}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f'Error fetching login form: {e}')
        return None
