import unittest
from scanners.vuln_analyzer import analyze_vulnerabilities


class AnalysisTests(unittest.TestCase):
    def test_fetch_failure_does_not_imply_missing_headers(self):
        findings = analyze_vulnerabilities('example.com', {'error': 'timeout', 'missing': ['Content-Security-Policy']}, {'valid': True}, [])
        self.assertEqual(findings, [])

    def test_connection_failure_does_not_imply_bad_certificate(self):
        for error in ['Connection timeout', 'Name resolution failed', 'SSL Error: handshake failed']:
            with self.subTest(error=error):
                self.assertEqual(analyze_vulnerabilities('example.com', {}, {'valid': False, 'error': error}, []), [])

    def test_confirmed_certificate_failure_is_reported(self):
        findings = analyze_vulnerabilities('example.com', {}, {'valid': False, 'certificate_error': True, 'error': 'expired'}, [])
        self.assertEqual([v['title'] for v in findings], ['Invalid SSL Certificate'])

    def test_missing_hsts_is_reported_once(self):
        findings = analyze_vulnerabilities('example.com', {'missing': ['Strict-Transport-Security'], 'hsts_issues': ['HSTS header missing']}, {'valid': True}, [])
        self.assertEqual(len(findings), 1)

    def test_zero_days_expiry_is_reported(self):
        findings = analyze_vulnerabilities('example.com', {}, {'valid': True, 'expiry_days': 0}, [])
        self.assertEqual([v['title'] for v in findings], ['SSL Certificate Expiring Soon'])

    def test_missing_csp_is_hardening_not_critical(self):
        findings = analyze_vulnerabilities('example.com', {'missing': ['Content-Security-Policy'], 'status_code': 200}, {'valid': True}, [])
        self.assertEqual(findings[0]['severity'], 'medium')
        self.assertEqual(findings[0]['category'], 'hardening')
        self.assertEqual(findings[0]['evidence']['missing_header'], 'Content-Security-Policy')
        self.assertTrue(findings[0]['solution'])
        self.assertTrue(findings[0]['impact'])

    def test_technology_alone_is_informational(self):
        findings = analyze_vulnerabilities('example.com', {}, {'valid': True}, ['WordPress', 'jQuery 3.0', 'Powered-By: PHP/5.6'])
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(v['severity'] == 'info' and v['confidence'] == 'low' for v in findings))
        self.assertTrue(all(v['cve_id'] is None for v in findings))

    def test_technology_errors_are_not_detections(self):
        self.assertEqual(analyze_vulnerabilities('example.com', {}, {}, ['Error: WordPress timeout']), [])

    def test_csp_frame_ancestors_avoids_duplicate_framing_finding(self):
        findings = analyze_vulnerabilities('example.com', {'missing': ['X-Frame-Options'], 'raw': {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'"}}, {'valid': True}, [])
        self.assertEqual(findings, [])

    def test_legacy_xss_header_not_required(self):
        self.assertEqual(analyze_vulnerabilities('example.com', {'missing': ['X-XSS-Protection']}, {}, []), [])

    def test_failed_headers_do_not_generate_banner_or_hsts_findings(self):
        self.assertEqual(analyze_vulnerabilities('example.com', {'error': 'timeout', 'hsts_issues': ['missing'], 'info_leaks': ['Server: x']}, {}, []), [])

    def test_expired_certificate_is_distinct_from_expiring(self):
        findings = analyze_vulnerabilities('example.com', {}, {'expiry_days': -1}, [])
        self.assertEqual(findings[0]['title'], 'SSL Certificate Expired')
        self.assertEqual(findings[0]['severity'], 'high')
