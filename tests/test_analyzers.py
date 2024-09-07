import unittest
from unittest.mock import patch, MagicMock
from xss911.lib.analyzers.response_analyzer import res_analyzer

class TestResponseAnalyzer(unittest.TestCase):

    @patch('xss911.lib.analyzers.response_analyzer.logger.info')
    def test_res_analyzer_script_detection(self, mock_logger):
        response = MagicMock()
        response.text = '<script>alert(1)</script>'
        response.status_code = 200

        payload = "<script>alert(1)</script>"
        res_analyzer(response, payload)

        mock_logger.assert_any_call('Detected XSS in response with payload <script>alert(1)</script>')
        mock_logger.assert_any_call('Script execution detected')

    @patch('xss911.lib.analyzers.response_analyzer.logger.info')
    def test_res_analyzer_other_payloads(self, mock_logger):
        response = MagicMock()
        response.text = '<img src=x onerror=alert(1)>'
        response.status_code = 200

        payload = '<img src=x onerror=alert(1)>'
        res_analyzer(response, payload)

        mock_logger.assert_any_call('Detected XSS in response with payload <img src=x onerror=alert(1)>')
        mock_logger.assert_any_call('Image XSS detected')

    # Add more tests for other types of responses and payloads

if __name__ == '__main__':
    unittest.main()
