import unittest
from unittest.mock import patch, mock_open, MagicMock
from pathlib import Path
import json
import normalizer

class TestNormalizer(unittest.TestCase):

    def setUp(self):
        self.sample_csv_data = ("id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
                                "3571718,2025-06-30,http://malicious.com,online,2025-06-30,malware_download,,https://urlhaus.abuse.ch/url/3571718/,c2hunter")

        self.sample_json_data = json.dumps({
            "results": [
                {"ioc_string": "1.2.3.4", "ioc_type": "ipv4-addr"},
                {"ioc_string": "http://bad.com/mal", "ioc_type": "url"}
            ]
        })

        self.sample_txt_data = "1.1.1.1\n2.2.2.2\n#comment\n"

        self.sample_otx_data = json.dumps({
            "indicators": [
                {"indicator": "badhash", "type": "file-md5"}
            ]
        })

    @patch("builtins.open", new_callable=mock_open, read_data="1.2.3.4\n")
    def test_normalize_txt_list(self, mock_file):
        path = Path("dummy.txt")
        result = normalizer.normalize_txt_list(path, "test_source")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'ipv4-addr')
        self.assertEqual(result[0]['source'], 'test_source')

    @patch("normalizer.load_json")
    def test_normalize_threatfox(self, mock_json):
        mock_json.return_value = json.loads(self.sample_json_data)
        path = Path("dummy.json")
        result = normalizer.normalize_threatfox(path)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['type'], 'ipv4-addr')

    @patch("normalizer.load_json")
    def test_normalize_otx(self, mock_json):
        mock_json.return_value = json.loads(self.sample_otx_data)
        path = Path("dummy.json")
        result = normalizer.normalize_otx(path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'file-md5')

    @patch("normalizer.parse_csv")
    def test_normalize_urlhaus(self, mock_parse_csv):
        mock_parse_csv.return_value = [
            {"url": "http://malicious.com"}
        ]
        path = Path("dummy.csv")
        result = normalizer.normalize_urlhaus(path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['indicator'], "http://malicious.com")

    @patch("normalizer.load_json")
    def test_normalize_json_list(self, mock_json):
        mock_json.return_value = [{"url": "http://test.com"}]
        path = Path("dummy.json")
        result = normalizer.normalize_json_list(path, "testsource", "url", "url")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['indicator'], "http://test.com")

    @patch("pathlib.Path.read_text")
    def test_normalize_generic(self, mock_read):
        mock_read.return_value = "http://abc.com 1.2.3.4 deadbeefdeadbeefdeadbeefdeadbeef"
        path = Path("dummy.txt")
        result = normalizer.normalize_generic(path)
        types = {r['type'] for r in result}
        self.assertIn('ipv4-addr', types)
        self.assertIn('url', types)

if __name__ == '__main__':
    unittest.main()