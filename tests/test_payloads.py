import unittest
from unittest.mock import patch, MagicMock, mock_open
import json
import os
from xss911.lib.payloads.payload import raw_payloads, encoded_payloads, custom, Payloads, load_custom_payloads

class TestPayloads(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open, read_data='{"payloads":[{"payload":"<script>alert(1)</script>"}]}')
    def test_load_payloads(self, mock_open):
        payload_list = raw_payloads('blind')
        self.assertEqual(len(payload_list), 1)
        self.assertEqual(payload_list[0], '<script>alert(1)</script>')

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='<script>alert(1)</script>')
    def test_encoded_payloads(self, mock_open, mock_exists):
        encoded_list = encoded_payloads('blind')
        self.assertEqual(len(encoded_list), 1)
        self.assertEqual(encoded_list[0], '<script>alert(1)</script>')

    @patch('builtins.open', new_callable=mock_open, read_data='<script>alert(1)</script>')
    @patch('xss911.lib.payloads.payload.load_custom_payloads')
    def test_custom_payloads(self, mock_load_custom, mock_open):
        custom('blind', 'custom_file.txt')
        mock_load_custom.assert_called_once()

    @patch('xss911.lib.payloads.payload.load_custom_payloads')
    def test_load_custom_payloads(self, mock_load_custom):
        mock_load_custom.return_value = None
        Payloads('custom', 'blind', 'custom_file.txt')
        mock_load_custom.assert_called_once()

    # Add similar tests for stored, reflective, and dom payloads

if __name__ == '__main__':
    unittest.main()
