import subprocess
import time
import json
import os
import platform
import requests
from lib.utils.logger import logger
from lib.payloads.blind_inject import blind_url_injection


# Function to check if ngrok is installed
def is_ngrok_installed():
    try:
        subprocess.run(['ngrok', 'version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# Function to install ngrok on Linux
def install_ngrok_linux():
    logger.info("Installing ngrok for Linux...")
    commands = [
        'curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null',
        'echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list',
        'sudo apt update',
        'sudo apt install -y ngrok'
    ]
    for command in commands:
        subprocess.run(command, shell=True, check=True)
    logger.info("ngrok installed successfully.")


# Function to install ngrok on macOS
def install_ngrok_macos():
    logger.info("Installing ngrok for macOS...")
    subprocess.run('brew install ngrok/ngrok/ngrok', shell=True, check=True)
    logger.info("ngrok installed successfully.")


# Function to install ngrok on Windows through WSL
def install_ngrok_wsl():
    logger.info("Installing ngrok for Windows Subsystem for Linux (WSL)...")
    subprocess.run('wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz', shell=True, check=True)
    subprocess.run('sudo tar -xvzf ./ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin', shell=True, check=True)
    logger.info("ngrok installed successfully.")


# Function to setup ngrok
def setup_ngrok():
    logger.info("Setting up ngrok...")

    if is_ngrok_installed():
        logger.info("ngrok is already installed.")
        return

    os_name = platform.system()
    if os_name == 'Linux':
        install_ngrok_linux()
    elif os_name == 'Darwin':  # macOS
        install_ngrok_macos()
    elif os_name == 'Windows':
        logger.critical("Windows is not directly supported. Please use WSL or manual installation.")
    else:
        logger.critical(f"Unsupported OS: {os_name}")


# Function to wait until ngrok API is ready
def wait_for_ngrok():
    logger.info("Waiting for ngrok API to become available...")
    ngrok_api_url = 'http://localhost:4040/api/tunnels'
    max_retries = 10  # retry up to 10 times
    retries = 0
    while retries < max_retries:
        try:
            response = requests.get(ngrok_api_url)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            time.sleep(1)
            retries += 1
    logger.error("Failed to connect to ngrok API.")
    return False


# Function to start ngrok and save the forwarding URL
def start_ngrok():
    port = 5000
    config_file = 'results/ngrok_url.txt'
    print(f"Starting ngrok tunnel on port {port}...")

    # Start ngrok tunnel in the background
    ngrok_process = subprocess.Popen(['ngrok', 'http', str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait for ngrok API to be ready
    if not wait_for_ngrok():
        logger.warning("Failed to get ngrok URL. Ensure ngrok is running.")
        ngrok_process.terminate()
        return

    # Fetch the forwarding URL using ngrok API
    logger.info("Fetching ngrok forwarding URL...")
    ngrok_api_url = 'http://localhost:4040/api/tunnels'
    result = requests.get(ngrok_api_url)

    # Extract the forwarding URL from the JSON response
    try:
        tunnels = result.json()
        ngrok_url = tunnels['tunnels'][0]['public_url']
    except (json.JSONDecodeError, IndexError, KeyError) as e:
        logger.error(f"Failed to parse ngrok URL: {e}")
        ngrok_process.terminate()
        return

    # Save the forwarding URL to a file
    with open(config_file, 'w') as file:
        file.write(ngrok_url)

    print(f"ngrok forwarding URL saved to {config_file}.")
    print(f"ngrok tunnel is up and running.\nForwarding URL: {ngrok_url}")

    # Keep ngrok running
    try:
        ngrok_process.wait()
    except KeyboardInterrupt:
        print("Stopping ngrok...")
        ngrok_process.terminate()

    return ngrok_url


def start_server():
    # Start the Flask server
    logger.info("Starting the Server For Blind XSS...")
    setup_ngrok()
    ngrok_url = start_ngrok()
    logger.info("Blind server started successfully.")
    blind_url_injection(ngrok_url)

