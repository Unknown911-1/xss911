import json
import os

# Define the path for the report file
file_path = 'reports/reports.json'

# Initialize report_data
report_data = []

# Ensure the directory for the report file exists
def ensure_directory_exists():
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

# Save the report data to the file
def save_report():
    ensure_directory_exists()
    try:
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=4)
    except IOError as e:
        print(f"Error saving report: {e}")

# Append a new entry to the report data and save it
def append_and_save(entry):
    report_data.append(entry)
    save_report()
    return report_data

# Convert headers to a standard dictionary if needed
def convert_headers(headers):
    if isinstance(headers, dict):
        return headers
    elif hasattr(headers, 'to_dict'):
        return headers.to_dict()  # For CaseInsensitiveDict or similar
    return dict(headers)

# Record request headers
def record_request_headers(url, headers, payload, res_status=None):
    headers_dict = convert_headers(headers)  # Ensure headers are serializable
    entry = {
        'url': url,
        'payload': payload,
        'response_status': res_status,
        'headers': headers_dict
    }
    return append_and_save(entry)

# Other functions remain unchanged

def record_request_params(url, parameter, payload, status_code=None):
    entry = {
        'url': url,
        'parameter': parameter,
        'payload': payload,
        'status_code': status_code
    }
    return append_and_save(entry)

def record_request_form(url, form_data, payload, status_code):
    entry = {
        'url': url,
        'payload': payload,
        'form_data': form_data,
        'status_code': status_code
    }
    return append_and_save(entry)

def record_dom_attacks(url, code, payload, status_code=None):
    entry = {
        'url': url,
        'payload': payload,
        'code': code,
        'status_code': status_code
    }
    return append_and_save(entry)

def blind_xss_report(url, data, payload, status_code=None):
    entry = {
        'url': url,
        'payload': payload,
        'data': data,
        'status_code': status_code
    }
    return append_and_save(entry)
