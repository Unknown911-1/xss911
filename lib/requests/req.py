import requests
import os
import pickle
from lib.requests.find import find_login_page, find_login_form
from lib.utils.logger import logger

SESSION_FILE = 'session.pkl'

def get_credentials(fields):
    credentials = {}
    for field_name in fields:
        if 'password' in field_name.lower():
            credentials[field_name] = input(f"Enter password for {field_name}: ")
        else:
            credentials[field_name] = input(f"Enter username for {field_name}: ")

    return credentials

def save_session(session):
    """
    Save session cookies to a file.
    """
    try:
        with open(SESSION_FILE, 'wb') as f:
            pickle.dump(session.cookies, f)
        logger.info("Session saved.")
    except Exception as e:
        logger.error(f"Error saving session: {e}")

def load_session():
    """
    Load session cookies from a file if available.
    """
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, 'rb') as f:
                cookies = pickle.load(f)
            session = requests.Session()
            session.cookies.update(cookies)
            logger.info("Session loaded.")
            return session
        except (pickle.PickleError, IOError) as e:
            logger.error(f"Error loading session: {e}")
            return None
    return None

def log_into_website(url):
    """
    Log into the website if no session is active.
    """
    try:
        # Check if there's an existing session
        session = load_session()
        if session:
            return session

        # No saved session, proceed with login

        # Find login page
        login_page = find_login_page(url)
        if login_page:
            # Find login form on the page
            login_form = find_login_form(login_page)
            if login_form:
                # Get user credentials
                credentials = get_credentials(login_form)

                # Prepare data for form submission
                login_data = {field: credentials.get(field, '') for field in login_form}

                # Create session and login
                session = requests.Session()
                res = session.post(login_page, data=login_data)

                # Check login success by response status code or URL change
                if res.status_code == 200:
                    if res.url == login_page:
                        logger.error("Login failed. Please check your credentials.")
                        return None
                    else:
                        logger.info("Login successful.")
                        save_session(session)  # Save the session after successful login
                        return session
                else:
                    logger.error(f"Failed to log into {url}. Status code: {res.status_code}")
                    return None
            else:
                logger.error("No login form found on the login page.")
                return None
        else:
            logger.error("No login page found.")
            return None

    except requests.RequestException as e:
        logger.error(f"Error during login process: {e}")
        return None

def session_get(url):
    """
    Attempt to load the saved session or log in if necessary.
    """
    session = load_session()
    if session:
        return session
    return log_into_website(url)
