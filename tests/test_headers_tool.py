import unittest
from unittest.mock import patch, Mock
from curl_cffi.requests.errors import RequestsError
from curl_cffi.requests.headers import Headers
from tools.headers_tool import headers_analyzer


def _resp(status_code: int, headers: dict):
    """Build a mock curl_cffi response for a single hop.

    Wraps headers in curl_cffi's real Headers class (not a plain dict)
    -- Headers does case-insensitive lookups (e.g. .get("location")
    matches a "Location" key), matching real response behavior. A plain
    dict would silently fail that lookup and give false test failures
    that look like a production bug but are actually just an inaccurate
    mock.

    headers is a plain dict on input, curl_cffi (like `requests`)
    already combines a repeated header into one comma-joined value
    during its own parsing, so by the time this tool sees resp.headers,
    a duplicate-header scenario is already a single combined string,
    not separate entries.
    """
    m = Mock()
    m.status_code = status_code
    m.headers = Headers(headers)
    return m


class TestHeadersAnalyzer(unittest.TestCase):

    # ------------------------------------------------------------------
    # Domain validation
    # ------------------------------------------------------------------

    def test_invalid_domain_rejected(self):
        result = headers_analyzer("not-a-domain")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid domain format")

    def test_ip_address_rejected(self):
        result = headers_analyzer("192.168.1.1")
        self.assertFalse(result["success"])

    # ------------------------------------------------------------------
    # Successful response (single hop, no redirect)
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get")
    def test_success_returns_correct_structure(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        })
        result = headers_analyzer("example.com")
        self.assertTrue(result["success"])
        self.assertIn("domain", result)
        self.assertIn("headers", result)
        self.assertIn("redirect_chain", result)

    @patch("tools.headers_tool.requests.get")
    def test_hsts_present_and_valid(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertEqual(hsts["issue"], "None")
        self.assertEqual(hsts["severity"], "low")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_missing_flagged_as_high(self, mock_get):
        mock_get.return_value = _resp(200, {})
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertFalse(hsts["present"])
        self.assertEqual(hsts["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_low_max_age_flagged_medium(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=3600",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("max-age", hsts["issue"])
        self.assertEqual(hsts["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_max_age_zero_flagged_high(self, mock_get):
        """Fix: max-age=0 actively disables HSTS (a real rollback
        technique), so it must be flagged as high severity, not lumped
        in with merely-short-but-nonzero durations as medium."""
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=0",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertEqual(hsts["severity"], "high")
        self.assertIn("disables", hsts["issue"])

    @patch("tools.headers_tool.requests.get")
    def test_hsts_negative_max_age_flagged_high(self, mock_get):
        """Fix: a negative max-age is invalid per spec, not just "weak", so it
        must be flagged distinctly from a low-but-valid value."""
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=-1",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertEqual(hsts["severity"], "high")
        self.assertIn("invalid", hsts["issue"])

    @patch("tools.headers_tool.requests.get")
    def test_hsts_malformed_max_age_value_caught(self, mock_get):
        """A non-numeric max-age (e.g. a malformed or hand-edited header)
        must be caught by the except clause, not raise an uncaught
        exception."""
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=notanumber",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("Could not parse", hsts["issue"])
        self.assertEqual(hsts["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_present_without_max_age_directive(self, mock_get):
        """HSTS header present but with no max-age= substring at all
        (e.g. just "includeSubDomains"), distinct from HSTS being
        completely absent."""
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "includeSubDomains",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("max-age directive is missing", hsts["issue"])
        self.assertEqual(hsts["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_hsts_missing_includesubdomains_upgrades_severity(self, mock_get):
        """A valid, long max-age without includeSubDomains should still
        be flagged (and the severity upgraded from the default "low"
        to "medium" for the missing directive), not silently accepted
        as fully clean."""
        mock_get.return_value = _resp(200, {
            "Strict-Transport-Security": "max-age=31536000",
        })
        result = headers_analyzer("example.com")
        hsts = result["headers"]["strict-transport-security"]
        self.assertTrue(hsts["present"])
        self.assertIn("includeSubDomains", hsts["issue"])
        self.assertEqual(hsts["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_csp_missing_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {})
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertFalse(csp["present"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_csp_unsafe_inline_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertTrue(csp["present"])
        self.assertIn("unsafe-inline", csp["issue"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_csp_unsafe_eval_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertIn("unsafe-eval", csp["issue"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_csp_wildcard_source_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "default-src *",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertIn("Wildcard", csp["issue"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_csp_missing_default_src_flagged_once(self, mock_get):
        """Regression test for the redundant-check cleanup: a CSP with
        neither default-src 'self' nor 'none' should be flagged exactly
        once (the old code had two nested checks for the exact same
        condition -- this verifies behavior is unchanged after removing
        the dead duplicate, not just that it doesn't crash)."""
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "script-src 'self'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        issue_count = csp["issue"].count("No restrictive default-src")
        self.assertEqual(issue_count, 1)
        self.assertEqual(csp["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_csp_report_only_mode_detected(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy-Report-Only": "default-src 'self'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertTrue(csp["present"])
        self.assertIn("report-only mode", csp["issue"])
        self.assertEqual(csp["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_combined_duplicate_csp_directives_are_analyzed_correctly(self, mock_get):
        """curl_cffi (like `requests` and like DevTools) already combines
        a header that appears more than once in a real response into one
        comma-joined value during parsing, verify the analysis logic
        correctly flags an unsafe directive even when it's not first in
        an already-combined value."""
        mock_get.return_value = _resp(200, {
            "Content-Security-Policy": "default-src 'self', script-src 'unsafe-inline'",
        })
        result = headers_analyzer("example.com")
        csp = result["headers"]["content-security-policy"]
        self.assertIn("default-src 'self'", csp["value"])
        self.assertIn("script-src 'unsafe-inline'", csp["value"])
        self.assertEqual(csp["severity"], "high")

    @patch("tools.headers_tool.requests.get")
    def test_x_frame_options_deny_accepted(self, mock_get):
        mock_get.return_value = _resp(200, {"X-Frame-Options": "DENY"})
        result = headers_analyzer("example.com")
        xfo = result["headers"]["x-frame-options"]
        self.assertTrue(xfo["present"])
        self.assertEqual(xfo["issue"], "None")

    @patch("tools.headers_tool.requests.get")
    def test_x_frame_options_unrecognized_value_flagged(self, mock_get):
        """A value that's neither DENY nor SAMEORIGIN (e.g. a malformed
        or non-standard directive) must be flagged, not silently treated
        as acceptable just because the header is present."""
        mock_get.return_value = _resp(200, {"X-Frame-Options": "ALLOW-FROM https://example.com"})
        result = headers_analyzer("example.com")
        xfo = result["headers"]["x-frame-options"]
        self.assertTrue(xfo["present"])
        self.assertIn("Unexpected value", xfo["issue"])
        self.assertEqual(xfo["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_x_content_type_options_nosniff_accepted(self, mock_get):
        mock_get.return_value = _resp(200, {"X-Content-Type-Options": "nosniff"})
        result = headers_analyzer("example.com")
        xcto = result["headers"]["x-content-type-options"]
        self.assertTrue(xcto["present"])
        self.assertEqual(xcto["issue"], "None")

    @patch("tools.headers_tool.requests.get")
    def test_server_header_flagged_as_disclosure(self, mock_get):
        mock_get.return_value = _resp(200, {"Server": "Apache/2.4.41"})
        result = headers_analyzer("example.com")
        self.assertIn("server", result["headers"])
        self.assertIn("exposes technology", result["headers"]["server"]["issue"])

    @patch("tools.headers_tool.requests.get")
    def test_referrer_policy_good_value_accepted(self, mock_get):
        mock_get.return_value = _resp(200, {"Referrer-Policy": "strict-origin-when-cross-origin"})
        result = headers_analyzer("example.com")
        rp = result["headers"]["referrer-policy"]
        self.assertTrue(rp["present"])
        self.assertEqual(rp["issue"], "None")
        self.assertEqual(rp["severity"], "low")

    @patch("tools.headers_tool.requests.get")
    def test_referrer_policy_weak_value_flagged(self, mock_get):
        """A Referrer-Policy value that's present but not in the
        recognized "good" list (e.g. "unsafe-url", which leaks the full
        URL including path and query string cross-origin) must be
        flagged as leaking more than necessary, not silently accepted
        just because the header exists."""
        mock_get.return_value = _resp(200, {"Referrer-Policy": "unsafe-url"})
        result = headers_analyzer("example.com")
        rp = result["headers"]["referrer-policy"]
        self.assertTrue(rp["present"])
        self.assertIn("may leak", rp["issue"])
        self.assertEqual(rp["severity"], "medium")

    # ------------------------------------------------------------------
    # Permissions-Policy content analysis (fix: presence-only -> low was
    # treated as automatically "fine" regardless of content)
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get")
    def test_permissions_policy_restrictive_clean(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Permissions-Policy": "camera=(), microphone=()",
        })
        result = headers_analyzer("example.com")
        pp = result["headers"]["permissions-policy"]
        self.assertTrue(pp["present"])
        self.assertEqual(pp["issue"], "None")
        self.assertEqual(pp["severity"], "low")

    @patch("tools.headers_tool.requests.get")
    def test_permissions_policy_wildcard_sensitive_feature_flagged(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Permissions-Policy": "camera=*, geolocation=()",
        })
        result = headers_analyzer("example.com")
        pp = result["headers"]["permissions-policy"]
        self.assertTrue(pp["present"])
        self.assertIn("camera", pp["issue"])
        self.assertEqual(pp["severity"], "medium")

    @patch("tools.headers_tool.requests.get")
    def test_permissions_policy_missing_flagged_low(self, mock_get):
        mock_get.return_value = _resp(200, {})
        result = headers_analyzer("example.com")
        pp = result["headers"]["permissions-policy"]
        self.assertFalse(pp["present"])
        self.assertEqual(pp["severity"], "low")

    # ------------------------------------------------------------------
    # WAF / bot-challenge detection (#62: "differences between browser
    # and non-browser requests") -- confirmed via live testing that a
    # site behind Cloudflare can serve a JS challenge page instead of
    # the real site to a non-browser-fingerprinted client.
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get")
    def test_cloudflare_challenge_page_is_rejected_not_analyzed(self, mock_get):
        mock_get.return_value = _resp(200, {
            "Server": "cloudflare",
            "cf-mitigated": "challenge",
            "X-Frame-Options": "SAMEORIGIN",
        })
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("challenge", result["error"].lower())

    @patch("tools.headers_tool.requests.get")
    def test_normal_cloudflare_site_without_challenge_is_analyzed_normally(self, mock_get):
        """Server: cloudflare alone must not trigger the challenge
        rejection, only the explicit cf-mitigated: challenge signal
        should. Plenty of legitimate sites run behind Cloudflare without
        ever serving a challenge."""
        mock_get.return_value = _resp(200, {
            "Server": "cloudflare",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        result = headers_analyzer("example.com")
        self.assertTrue(result["success"])
        self.assertTrue(result["headers"]["x-frame-options"]["present"])

    # ------------------------------------------------------------------
    # Full redirect-chain recovery (#62: "Redirect handling" / "Response
    # selection"), each hop is fetched individually (allow_redirects=
    # False) so its own headers are captured, not just the final
    # destination's. A header present on an intermediate hop but absent
    # (or different) on the final destination is now fully visible.
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get")
    def test_no_redirect_single_hop_chain(self, mock_get):
        mock_get.return_value = _resp(200, {"X-Frame-Options": "DENY"})
        result = headers_analyzer("example.com")
        self.assertFalse(result["redirected"])
        self.assertEqual(len(result["redirect_chain"]), 1)
        self.assertEqual(result["final_url"], "https://example.com")
        self.assertEqual(result["requested_url"], "https://example.com")

    @patch("tools.headers_tool.requests.get")
    def test_redirect_captures_each_hops_distinct_headers(self, mock_get):
        """Root-cause fix: the redirect hop and the final hop
        have DIFFERENT X-Frame-Options values, and both must be visible
        in redirect_chain, not just the final one."""
        mock_get.side_effect = [
            _resp(301, {
                "Location": "https://www.example.com/home",
                "X-Frame-Options": "SAMEORIGIN",
            }),
            _resp(200, {
                "X-Frame-Options": "DENY",
            }),
        ]
        result = headers_analyzer("example.com")

        self.assertTrue(result["redirected"])
        self.assertEqual(len(result["redirect_chain"]), 2)
        self.assertEqual(result["redirect_chain"][0]["status_code"], 301)
        self.assertEqual(
            result["redirect_chain"][0]["headers"]["x-frame-options"], "SAMEORIGIN"
        )
        self.assertEqual(result["redirect_chain"][1]["status_code"], 200)
        self.assertEqual(
            result["redirect_chain"][1]["headers"]["x-frame-options"], "DENY"
        )
        # The final analysis must reflect the DESTINATION's header, not
        # the redirect's.
        self.assertEqual(result["headers"]["x-frame-options"]["value"], "DENY")
        self.assertEqual(result["final_url"], "https://www.example.com/home")

    @patch("tools.headers_tool.requests.get")
    def test_relative_location_header_is_resolved(self, mock_get):
        """A redirect's Location header is often a relative path, not a
        full URL. It must be resolved against the current URL, not
        treated as a literal (broken) next destination."""
        mock_get.side_effect = [
            _resp(301, {"Location": "/new-path"}),
            _resp(200, {"X-Frame-Options": "DENY"}),
        ]
        result = headers_analyzer("example.com")
        self.assertEqual(result["final_url"], "https://example.com/new-path")

    @patch("tools.headers_tool.requests.get")
    def test_self_redirecting_url_fails_explicitly(self, mock_get):
        """Regression test for a bug found during final audit: a server
        misconfigured to 301-redirect a URL to itself (a real pattern,
        e.g. broken nginx/Apache redirect rules) would previously be
        silently analyzed as if its 301 response were the real page,
        reporting redirected=False (technically true by the old len(hops)
        > 1 check, since the loop guard stopped the chain at 1 hop) while
        actually surfacing the REDIRECT's own headers as the site's
        configuration. Must now fail explicitly instead."""
        mock_get.return_value = _resp(301, {
            "Location": "https://example.com",
            "X-Frame-Options": "SAMEORIGIN",
        })
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        # Must not contain a "headers" analysis key at all, there is no
        # successful analysis to report.
        self.assertNotIn("headers", result)

    @patch("tools.headers_tool.requests.get")
    def test_redirect_loop_does_not_hang(self, mock_get):
        """A redirect pointing back to an already-visited URL must stop
        (not loop forever). And since it never resolves to real page
        content, it must fail explicitly rather than silently analyzing
        whichever redirect response it stopped on."""
        mock_get.side_effect = [
            _resp(301, {"Location": "https://example.com/b"}),
            _resp(301, {"Location": "https://example.com"}),  # loops back
        ]
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("loop", result["error"].lower())

    @patch("tools.headers_tool.requests.get")
    def test_redirect_chain_caps_at_max_hops(self, mock_get):
        """A long chain of redirects that never resolves to real content
        must stop at a reasonable cap (bounded request count) and fail
        explicitly, not silently analyze whichever redirect response
        it happened to stop on as if it were the real page."""
        def make_redirect(i):
            return _resp(301, {"Location": f"https://example.com/{i}"})
        mock_get.side_effect = [make_redirect(i) for i in range(20)]
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertLessEqual(mock_get.call_count, 8)
        self.assertIn("hop", result["error"].lower())

    @patch("tools.headers_tool.requests.get")
    def test_redirect_missing_location_header_stops_cleanly(self, mock_get):
        """A 301/302 with no Location header is malformed and has no
        real destination to analyze, must stop gracefully (not crash
        on a None location) and fail explicitly rather than analyzing
        the broken redirect response itself as if it were the page."""
        mock_get.return_value = _resp(301, {})
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("tools.headers_tool.requests.get")
    def test_domain_in_result_reflects_final_destination(self, mock_get):
        mock_get.side_effect = [
            _resp(301, {"Location": "https://www.example.com/"}),
            _resp(200, {}),
        ]
        result = headers_analyzer("example.com")
        self.assertEqual(result["domain"], "www.example.com")

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    @patch("tools.headers_tool.requests.get",
           side_effect=RequestsError("Failed to connect"))
    def test_connection_error_returns_failure(self, _):
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("Connection failed", result["error"])

    @patch("tools.headers_tool._walk_redirect_chain", return_value=[])
    def test_empty_hop_list_returns_failure(self, _):
        """_walk_redirect_chain always appends at least one hop before
        it can return via the real requests.get() call site (max_hops
        defaults to 8, and `seen` always starts empty), so this branch
        is unreachable through the public API today. It's kept as a
        defensive guard in case _walk_redirect_chain's contract changes
        later (e.g. max_hops becomes caller-configurable down to 0).
        Tested here by patching the internal function directly, since
        there's no way to trigger it through headers_analyzer()."""
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("tools.headers_tool.requests.get",
           side_effect=Exception("Unexpected error"))
    def test_unexpected_exception_returns_failure(self, _):
        result = headers_analyzer("example.com")
        self.assertFalse(result["success"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)