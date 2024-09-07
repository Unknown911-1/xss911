import unittest
from unittest.mock import patch, MagicMock
from xss911.lib.core.scanner import scan

class TestScanner(unittest.TestCase):

    @patch('xss911.lib.core.scanner.form_vectors')
    @patch('xss911.lib.core.scanner.url_vectors')
    @patch('xss911.lib.core.scanner.http_vectors')
    @patch('xss911.lib.core.scanner.dom_xss_attack')
    @patch('xss911.lib.utils.logger.info')
    def test_reflective_scan(self, mock_logger, mock_dom_attack, mock_http_vectors, mock_url_vectors, mock_form_vectors):
        url = "https://e08ee8271a6561faf967c953f5ac1bda.ctf.hacker101.com/page/create"
        action = "encoded"
        xss_type = "reflective"

        scan(url, action, xss_type)

        mock_form_vectors.assert_called_with(url, xss_type, action)
        mock_url_vectors.assert_called_with(url, action)
        mock_http_vectors.assert_called_with(url, action)
        mock_logger.assert_any_call(f'Scanning for reflective XSS on {url}')
        mock_logger.assert_any_call('Reflective XSS scan completed')

    @patch('xss911.lib.core.scanner.form_vector')
    @patch('xss911.lib.core.scanner.url_vector')
    @patch('xss911.lib.core.scanner.http_vector')
    @patch('xss911.lib.utils.logger.info')
    def test_blind_scan(self, mock_logger, mock_http_vector, mock_url_vector, mock_form_vector):
        url = "https://e08ee8271a6561faf967c953f5ac1bda.ctf.hacker101.com/page/create"
        action = "encoded"
        xss_type = "blind"

        scan(url, action, xss_type)

        mock_form_vector.assert_called_with(url, xss_type, action)
        mock_url_vector.assert_called_with(url, action)
        mock_http_vector.assert_called_with(url, action)
        mock_logger.assert_any_call(f'Scanning for blind XSS on {url}')
        mock_logger.assert_any_call('Blind XSS scan completed')

    @patch('xss911.lib.core.scanner.form_vector')
    @patch('xss911.lib.core.scanner.url_vector')
    @patch('xss911.lib.core.scanner.http_vector')
    @patch('xss911.lib.utils.logger.info')
    def test_stored_scan(self, mock_logger, mock_http_vector, mock_url_vector, mock_form_vector):
        url = "https://e08ee8271a6561faf967c953f5ac1bda.ctf.hacker101.com/page/create"
        action = "encoded"
        xss_type = "stored"

        scan(url, action, xss_type)

        mock_form_vector.assert_called_with(url, xss_type, action)
        mock_url_vector.assert_called_with(url, action)
        mock_http_vector.assert_called_with(url, action)
        mock_logger.assert_any_call(f'Scanning for stored XSS on {url}')
        mock_logger.assert_any_call('Stored XSS scan completed')

    @patch('xss911.lib.core.scanner.dom_xss_attack')
    @patch('xss911.lib.utils.logger.info')
    def test_dom_scan(self, mock_logger, mock_dom_attack):
        url = "https://e08ee8271a6561faf967c953f5ac1bda.ctf.hacker101.com/page/create"
        action = "encoded"
        xss_type = "dom"

        scan(url, action, xss_type)

        mock_dom_attack.assert_called_with(url, action)
        mock_logger.assert_any_call(f'Scanning for DOM-Based XSS on {url}')
        mock_logger.assert_any_call('DOM-Based XSS scan completed')

if __name__ == '__main__':
    unittest.main()
