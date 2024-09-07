import json
import os
from lib.utils.logger import logger
from lib.utils.encoder import save_encoded_payloads, encode_payloads

# File paths
blind_json = "lib/payloads/blind.json"
reflective_json = "lib/payloads/reflective.json"
dom_json = "lib/payloads/dom.json"
stored_json = "lib/payloads/stored.json"

blind_encode = 'lib/payloads/encoded/blind.txt'
reflective_encode = 'lib/payloads/encoded/reflective.txt'
dom_encode = 'lib/payloads/encoded/dom.txt'
stored_encode = 'lib/payloads/encoded/stored.txt'

blind_encode_json = 'lib/payloads/encode_json/blind.json'
reflective_encode_json = 'lib/payloads/encode_json/reflective.json'
dom_encode_json = 'lib/payloads/encode_json/dom.json'
stored_encode_json = 'lib/payloads/encode_json/stored.json'

# Payload file paths for raw payloads
blind_payloads_path = 'lib/payloads/raw/blind.txt'
reflective_payloads_path = 'lib/payloads/raw/reflective.txt'
dom_payloads_path = 'lib/payloads/raw/dom.txt'
stored_payloads_path = 'lib/payloads/raw/stored.txt'

def save_to_file(payloads, file_path):
    logger.info(f"Saving payloads to {file_path}")
    with open(file_path, 'w') as f:
        f.write('\n'.join(payloads))
    return file_path

def read_file(file_path):
    if os.path.exists(file_path):
        logger.info(f"Reading payloads from {file_path}")
        with open(file_path, 'r') as f:
            payloads = f.read().splitlines()
        return payloads
    else:
        logger.error(f"File not found: {file_path}")
        return []

def load_payloads(json_file, file_path):
    if os.path.exists(json_file):
        logger.info(f'Loading JSON file: {json_file}')
        with open(json_file, 'r') as f:
            data = json.load(f)
            payloads = [item['payload'] for item in data['payloads']]
            save_to_file(payloads, file_path)
    else:
        logger.error(f'File not found: {json_file}')

    return read_file(file_path)

def raw_payloads(payload_type):
    logger.info(f"Loading raw payloads for {payload_type}")
    if payload_type == 'blind':
        payloads = load_payloads(blind_json, blind_payloads_path)
    elif payload_type == 'reflective':
        payloads = load_payloads(reflective_json, reflective_payloads_path)
    elif payload_type == 'dom':
        payloads = load_payloads(dom_json, dom_payloads_path)
    elif payload_type == 'stored':
        payloads = load_payloads(stored_json, stored_payloads_path)
    else:
        logger.error(f'Invalid payload type: {payload_type}')
        return []

    logger.debug(f'Loaded {len(payloads)} {payload_type} payloads')
    return payloads

def load_payloads_encode(json_file, file_path):
    if os.path.exists(json_file):
        logger.info(f'Loading JSON file: {json_file}')
        with open(json_file, 'r') as f:
            data = json.load(f)
            payloads = [item['payload'] for item in data['payloads']]
            save_to_file(payloads, file_path)
    else:
        logger.error(f'File not found: {json_file}')

def encoded_payloads(payload_type):
    logger.info(f"Encoding payloads for {payload_type}")

    # File paths for saving encoded payloads
    encode_files = {
        'blind': blind_encode,
        'reflective': reflective_encode,
        'dom': dom_encode,
        'stored': stored_encode
    }

    encode_files_json = {
        'blind': blind_encode_json,
        'reflective': reflective_encode_json,
        'dom': dom_encode_json,
        'stored': stored_encode_json
    }

    # Determine the raw payloads path
    raw_payloads_path = {
        'blind': blind_payloads_path,
        'reflective': reflective_payloads_path,
        'dom': dom_payloads_path,
        'stored': stored_payloads_path
    }.get(payload_type)

    if not raw_payloads_path:
        logger.error(f'Invalid payload type: {payload_type}')
        return []

    # Load raw payloads
    payloads = read_file(raw_payloads_path)

    # Encode the payloads
    encoded_payloads_list = encode_payloads(payloads)

    # Save encoded payloads to JSON file
    encode_file_json = encode_files_json.get(payload_type)
    if encode_file_json:
        save_encoded_payloads(encoded_payloads_list, encode_file_json)

        # Save encoded payloads to text file
        encode_file = encode_files.get(payload_type)
        if encode_file:
            save_to_file([item['encoded'] for item in encoded_payloads_list], encode_file)
            return read_file(encode_file)
    else:
        logger.error(f'Encoded payloads JSON file path not found for: {payload_type}')
    return []

def load_custom_payloads(json_file, payload_data):
    logger.info(f"Loading custom payload into {json_file}")
    if os.path.exists(json_file):
        with open(json_file, 'r+') as f:
            data = json.load(f)
            data['payloads'].append(payload_data)
            f.seek(0)
            json.dump(data, f, indent=2)
    else:
        logger.error(f"File not found: {json_file}")

def custom(payload_type, file):
    logger.info(f"Loading custom payloads for {payload_type} from {file}")
    if os.path.exists(file):
        with open(file, 'r') as f:
            payloads = f.read().splitlines()
    else:
        logger.error('Custom file does not exist')
        return []

    type_mapping = {
        'blind': 'basic_blind_xss',
        'reflective': 'basic_reflected_xss',
        'stored': 'basic_stored_xss',
        'dom': 'basic_dom_based_xss'
    }

    payload_type_key = type_mapping.get(payload_type)
    if not payload_type_key:
        logger.error(f'Error getting payload type key for {payload_type}')
        return []

    for payload in payloads:
        data = {'type': payload_type_key, 'payload': payload}
        load_custom_payloads(globals()[f'{payload_type}_json'], data)

def blind_url_injection(url):
    logger.info(f"Checking blind URL injection for {url}")
    if url.endswith('.js') or url.endswith('='):
        if os.path.exists(blind_json):
            with open(blind_json, 'r+') as f:
                data = json.load(f)
                updated = False
                for item in data['payloads']:
                    payload = item['payload']
                    if url in payload:
                        return True
                    if 'fetch(' in payload:
                        payload_url = payload.split('fetch(')[1].split(')')[0]
                        payload = payload.replace(url, payload_url)
                        item['payload'] = payload
                        updated = True
                if updated:
                    f.seek(0)
                    json.dump(data, f, indent=2)
    else:
        logger.error('Invalid URL format')
    return False

def Payloads(action, payload_type, custom_file=[]):
    logger.info(f"Loading payloads for {payload_type} with action: {action}")
    if action == 'encoded':
        return encoded_payloads(payload_type)
    elif action == 'raw':
        return raw_payloads(payload_type)
    elif action == 'custom' and custom_file:
        custom(payload_type, custom_file)
        return read_file(globals()[f'{payload_type}_payloads_path'])
    else:
        logger.error('Invalid action type')
        return []
