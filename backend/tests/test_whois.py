import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from scanners.whois_scanner import run_whois_scan
from scanners.assessment import collection_checks


class RegistrationLookupTests(unittest.TestCase):
    @patch('scanners.whois_scanner.httpx.get')
    @patch('scanners.whois_scanner.whois.whois')
    def test_whois_success_does_not_need_fallback(self, lookup, get):
        lookup.return_value = SimpleNamespace(registrar='Registrar', domain_name='example.com')
        self.assertEqual(run_whois_scan('example.com')['source'], 'WHOIS')
        get.assert_not_called()

    @patch('scanners.whois_scanner.httpx.get')
    @patch('scanners.whois_scanner.whois.whois')
    def test_empty_whois_uses_https_fallback(self, lookup, get):
        lookup.return_value = SimpleNamespace(domain_name='example.com')
        get.return_value = httpx.Response(200, request=httpx.Request('GET', 'https://rdap.org/domain/example.com'), json={
            'objectClassName': 'domain', 'ldhName': 'EXAMPLE.COM',
            'events': [{'eventAction': 'registration', 'eventDate': '2000-01-01T00:00:00Z'}],
            'nameservers': [{'ldhName': 'ns.example.com'}],
            'entities': [{'roles': ['registrar'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Example Registrar']]]}],
        })
        result = run_whois_scan('www.example.com')
        self.assertEqual(get.call_args.args[0], 'https://rdap.org/domain/example.com')
        self.assertEqual(result['source'], 'RDAP')
        self.assertEqual(result['registrar'], 'Example Registrar')
        self.assertEqual(result['creation_date'], '2000-01-01T00:00:00Z')
        self.assertEqual(result['name_servers'], ['ns.example.com'])
        self.assertEqual(collection_checks({'whois': result})[0]['status'], 'completed')

    @patch('scanners.whois_scanner.httpx.get', side_effect=httpx.ReadTimeout('timeout'))
    @patch('scanners.whois_scanner.whois.whois', side_effect=TimeoutError())
    def test_both_services_fail_without_failing_scan(self, lookup, get):
        result = run_whois_scan('example.com')
        self.assertIn('RDAP fallback failed', result['error'])
        self.assertEqual(collection_checks({'whois': result})[0]['status'], 'failed')

    @patch('scanners.whois_scanner.httpx.get')
    @patch('scanners.whois_scanner.whois.whois')
    def test_ip_does_not_lookup_reverse_dns_domain(self, lookup, get):
        self.assertIn('not applicable', run_whois_scan('1.1.1.1')['error'])
        lookup.assert_not_called()
        get.assert_not_called()

    @patch('scanners.whois_scanner.httpx.get')
    @patch('scanners.whois_scanner.whois.whois', return_value=SimpleNamespace())
    def test_invalid_rdap_response_is_not_success(self, lookup, get):
        get.return_value = httpx.Response(200, request=httpx.Request('GET', 'https://rdap.org/domain/example.com'), json={})
        self.assertIn('error', run_whois_scan('example.com'))
