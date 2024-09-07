# XSS911 - Advanced XSS Vulnerability Scanner

![Preview](screenshots/xss911.PNG)

XSS911 is a powerful and flexible XSS (Cross-Site Scripting) vulnerability scanner designed to identify and report various types of XSS vulnerabilities. The tool covers reflected, stored, DOM-based, and blind XSS attacks with advanced detection mechanisms and reporting features.

## Features

- **Reflective XSS**: Detects vulnerabilities where user input is immediately reflected in the response.
- **Stored XSS**: Identifies issues where user input is stored and later retrieved.
- **DOM-based XSS**: Analyzes client-side JavaScript manipulations that can lead to XSS.
- **Blind XSS**: Scans for XSS vulnerabilities that require out-of-band callbacks.
- **Custom Payloads**: Supports adding custom payloads for testing.
- **Verbose Logging**: Detailed logs with color-coded outputs for better analysis.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/xss911.git
   cd xss911
   ```
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
### Usage
To run the scanner, use the following command:
```
python xss911.py -u <URL> -t <TYPE> -a <ACTION> [-ad <CUSTOM_PAYLOADS>] [-v] [-b <BLIND_PAYLOAD_URL>]
```

### Arguments

- `-u`, `--url`: The URL to scan for XSS vulnerabilities. Accepts a file containing URLs or a single URL.
- `-t`, `--type`: Type of XSS to scan for (`reflective`, `stored`, `blind`, `dom`).
- `-a`, `--action`: Payload action type (`raw` or `encoded`). Default is `raw`.
- `-ad`, `--add-payloads`: Path to a file with custom payloads.
- `-v`, `--verbose`: Enable verbose mode for detailed logging.
- `-b`, `--blind_payload_url`: URL to check for blind XSS payloads (should end with `.js` or `?data=`).

### Example

To scan a URL for reflective XSS vulnerabilities with encoded payloads:
```bash
python xss911.py -u https://example.com -t reflective -a encoded
```

To add custom payloads and enable verbose logging:
```bash
python xss911.py -u path/to/urls.txt -t blind -ad path/to/custom_payloads.json -v
```

## Testing

To run unit tests for the different modules, use:
```bash
python -m unittest discover -s xss911/tests
```

## Screenshots

![Preview](screenshots/xss911.png)![Preview](screenshots/xss911s.png)

## Contributing

Feel free to contribute to the project by submitting issues, pull requests, or suggestions. For any contributions, please adhere to the project's coding standards and guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries or support, please reach out to [honestlady1gg@gmail.com](mailto:honestlady1gg@gmail.com).

## Support This Project

If you find this script useful and would like to support further development, consider donating using cryptocurrency!

### Bitcoin
Address: `32VaadWB1EkD18hoE8t5pGqRmyD5g4CV9A`

[![Bitcoin QR Code](https://github.com/user-attachments/assets/83bbedff-f793-4797-9a50-391ab8a2a838)](https://github.com/user-attachments/assets/83bbedff-f793-4797-9a50-391ab8a2a838)

### Ethereum
Address: `0x673ffaA78F49CF7f3627178EDaf512F58160e3ED`

[![Ethereum QR Code](https://github.com/user-attachments/assets/e537afb6-cc0f-4ef6-9beb-0a9002a32014)](https://github.com/user-attachments/assets/e537afb6-cc0f-4ef6-9beb-0a9002a32014)

### USDT (TRC-20)
Address: `TMcVnY3CyqEfgqCwhunzGjJdwsR4WSZZc9`

[![USDT QR Code](https://github.com/user-attachments/assets/d4666b3a-bbca-42d5-85c0-df4e21b96203)](https://github.com/user-attachments/assets/d4666b3a-bbca-42d5-85c0-df4e21b96203)
```

