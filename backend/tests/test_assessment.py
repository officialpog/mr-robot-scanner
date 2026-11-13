import unittest
from scanners.assessment import collection_checks, collection_status


class CollectionTests(unittest.TestCase):
    def test_all_failures(self):
        data = {key: {'error': 'timeout'} for key in ('whois', 'dns', 'ssl', 'headers')}
        data['technologies'] = ['Error: timeout']
        self.assertEqual(collection_status(collection_checks(data)), 'failed')

    def test_unknown_is_partial_not_clean(self):
        self.assertEqual(collection_status(collection_checks({})), 'partial')
        self.assertTrue(all(c['status'] == 'inconclusive' for c in collection_checks({})))

    def test_confirmed_bad_certificate_is_completed_collection(self):
        data = {'ssl': {'certificate_error': True, 'error': 'expired'}}
        check = next(c for c in collection_checks(data) if c['key'] == 'ssl')
        self.assertEqual(check['status'], 'completed')

    def test_complete_collection(self):
        data = {'whois': {'registrar': 'Example'}, 'dns': {'a': ['1.1.1.1']}, 'ssl': {'valid': True}, 'headers': {'status_code': 200}, 'technologies': ['React']}
        self.assertEqual(collection_status(collection_checks(data)), 'completed')

    def test_dns_partial_data_retains_failure(self):
        data = {'dns': {'a': ['1.1.1.1'], 'error': 'TXT query timed out'}}
        self.assertEqual(next(c for c in collection_checks(data) if c['key'] == 'dns')['status'], 'failed')
