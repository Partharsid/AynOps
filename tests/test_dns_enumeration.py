from unittest.mock import MagicMock, Mock, patch
import unittest
from tools.dns_tool import dns_enumeration

class TestDnsEnumeration(unittest.TestCase):

    def _make_resolver_answer(self, values):
        """Return a mock dns.resolver answer iterable."""
        records = []
        for v in values:
            r = MagicMock()
            r.__str__ = lambda self, _v=v: _v
            records.append(r)
        return records

    def _make_txt_answer(self, chunks):
        record = Mock()
        record.strings = chunks
        return [record]

    def _make_soa_answer(self):
        record = Mock()
        record.mname = "ns1.example.com."
        record.rname = "hostmaster.example.com."
        record.serial = 1
        record.refresh = 2
        record.retry = 3
        record.expire = 4
        record.minimum = 5
        return [record]

    def test_invalid_domain(self):
        result = dns_enumeration("bad_domain")
        self.assertFalse(result["success"])

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_dns_success_returns_records(self, mock_resolver_class):
        resolver = Mock()
        mock_resolver_class.return_value = resolver

        def side_effect(domain, rtype, lifetime=5, tcp=False):
            import dns.resolver as real_dns

            if domain != "example.com":
                raise real_dns.NoAnswer
            if rtype == "A":
                return self._make_resolver_answer(["93.184.216.34"])
            if rtype == "MX":
                record = Mock()
                record.preference = 10
                record.exchange = "mail.example.com."
                return [record]
            if rtype == "NS":
                return self._make_resolver_answer(["ns1.example.com."])
            if rtype == "TXT":
                return self._make_txt_answer((b"v=spf1 ", b"include:example.com"))
            if rtype == "CNAME":
                return self._make_resolver_answer(["alias.example.com."])
            if rtype == "SOA":
                return self._make_soa_answer()
            raise Exception("no record")

        resolver.resolve.side_effect = side_effect
        result = dns_enumeration("example.com")

        self.assertTrue(result["success"])
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["records"]["MX"][0]["exchange"], "mail.example.com")
        self.assertEqual(result["records"]["NS"], ["ns1.example.com"])
        self.assertEqual(result["records"]["TXT"], ["v=spf1 include:example.com"])
        self.assertEqual(result["records"]["CNAME"], ["alias.example.com"])
        self.assertEqual(result["records"]["SOA"]["mname"], "ns1.example.com")
        self.assertEqual(result["records"]["SOA"]["rname"], "hostmaster.example.com")
        self.assertIn("subdomains_found", result)
        self.assertEqual(resolver.nameservers, ["1.1.1.1", "8.8.8.8"])
        resolver.resolve.assert_any_call("example.com", "TXT", lifetime=5, tcp=True)
        resolver.resolve.assert_any_call("www.example.com", "A", lifetime=3, tcp=True)

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_dns_nxdomain_returns_failure(self, mock_resolver_class):
        import dns.resolver as real_dns

        resolver = Mock()
        resolver.resolve.side_effect = real_dns.NXDOMAIN
        mock_resolver_class.return_value = resolver
        result = dns_enumeration("thisdoesnotexistatall12345.com")
        self.assertFalse(result["success"])
        self.assertIn("does not exist", result["error"])

    @patch("tools.dns_tool.dns.resolver.Resolver")
    def test_dns_no_answer_returns_empty_list(self, mock_resolver_class):
        import dns.resolver as real_dns

        resolver = Mock()
        resolver.resolve.side_effect = real_dns.NoAnswer
        mock_resolver_class.return_value = resolver
        result = dns_enumeration("example.com")
        # NoAnswer means success but empty records
        self.assertTrue(result["success"])
        for rtype_records in result["records"].values():
            self.assertEqual(rtype_records, [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
