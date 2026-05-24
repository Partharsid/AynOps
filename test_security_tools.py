import os
import unittest
from unittest.mock import Mock, patch

from main import cve_lookup, ip_reputation


class SecurityToolTests(unittest.TestCase):
    @patch("main.requests.get")
    def test_cve_lookup_returns_nvd_results(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "published": "2021-10-05T12:15:07.000",
                        "lastModified": "2024-11-21T05:31:44.123",
                        "descriptions": [{"lang": "en", "value": "Path traversal vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "baseSeverity": "CRITICAL",
                                    "cvssData": {"baseScore": 9.8},
                                }
                            ]
                        },
                    }
                }
            ],
        }
        mock_get.return_value = response

        result = cve_lookup("apache", "2.4.49")

        self.assertTrue(result["success"])
        self.assertEqual(result["software"], "apache")
        self.assertEqual(result["version"], "2.4.49")
        self.assertEqual(result["cves"][0]["cve_id"], "CVE-2021-41773")
        self.assertEqual(result["cves"][0]["severity"], "CRITICAL")
        self.assertEqual(result["cves"][0]["score"], 9.8)
        mock_get.assert_called_once()

    def test_ip_reputation_requires_valid_ip_and_api_key(self):
        self.assertFalse(ip_reputation("not-an-ip")["success"])

        with patch.dict(os.environ, {}, clear=True):
            result = ip_reputation("1.2.3.4")

        self.assertFalse(result["success"])
        self.assertIn("ABUSEIPDB_API_KEY", result["error"])

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("main.requests.get")
    def test_ip_reputation_maps_abuseipdb_response(self, mock_get):
        response = Mock()
        response.json.return_value = {
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 95,
                "totalReports": 342,
                "countryCode": "CN",
                "isp": "Example ISP",
                "domain": "example.net",
                "usageType": "Data Center/Web Hosting/Transit",
                "lastReportedAt": "2026-05-01T00:00:00+00:00",
            }
        }
        mock_get.return_value = response

        result = ip_reputation("1.2.3.4")

        self.assertTrue(result["success"])
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["abuse_confidence_score"], 95)
        self.assertEqual(result["total_reports"], 342)
        self.assertEqual(result["country"], "CN")
        self.assertEqual(result["isp"], "Example ISP")
        mock_get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
