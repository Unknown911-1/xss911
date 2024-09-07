import json
import urllib.parse
import re
import os

def is_encoded(payload):
    # Check for URL, HTML, or Unicode encoding in the payload
    if re.search(r'%[0-9A-Fa-f]{2}', payload):  # URL encoding
        return True
    if re.search(r'&lt;|&gt;|&amp;', payload):  # HTML encoding
        return True
    if re.search(r'%u[0-9A-Fa-f]{4}', payload):  # Unicode encoding
        return True
    return False

def encode_payload(payload):
    if not is_encoded(payload):
        # Apply multiple encoding techniques: URL, HTML, and Unicode encoding
        payload = urllib.parse.quote(payload)  # URL Encode
        payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')  # HTML Encode
        payload = ''.join(f'%u{ord(c):04X}' for c in payload)  # Unicode Encode
    return payload

def determine_encoding_type(payload):
    # Determine the encoding type based on regex patterns
    if re.search(r'%[0-9A-Fa-f]{2}', payload):
        return 'url'
    elif re.search(r'&lt;|&gt;|&amp;', payload):
        return 'html'
    elif re.search(r'%u[0-9A-Fa-f]{4}', payload):
        return 'unicode'
    return 'none'

def determine_bypass_techniques(payload):
    # Identify encoding techniques applied in the payload
    techniques = []
    if re.search(r'%[0-9A-Fa-f]{2}', payload):
        techniques.append('URL Encoding')
    if re.search(r'&lt;|&gt;|&amp;', payload):
        techniques.append('HTML Encoding')
    if re.search(r'%u[0-9A-Fa-f]{4}', payload):
        techniques.append('Unicode Encoding')
    return techniques

def encode_payloads(payloads):
    # Encode each payload and store the original, encoded, and encoding type
    encoded_payloads = []
    for payload in payloads:
        encoding_type = determine_encoding_type(payload)
        encoded_payload = encode_payload(payload)
        techniques = determine_bypass_techniques(payload)
        encoded_payloads.append({
            'original': payload,
            'encoded': encoded_payload,
            'encoding_type': encoding_type,
            'techniques': techniques
        })
    return encoded_payloads

def save_encoded_payloads(payloads, filepath):
    # Save the encoded payloads with detailed encoding info as JSON
    with open(filepath, 'w') as f:
        json.dump(payloads, f, indent=2)

# Example usage: You can call encode_payloads with a list of payloads and save them.
# payloads = ["<script>alert(1)</script>", "javascript:alert(1)"]
# encoded_payloads = encode_payloads(payloads)
# save_encoded_payloads(encoded_payloads, "encoded_payloads.json")
