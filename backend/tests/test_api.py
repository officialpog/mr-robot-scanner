import os
import tempfile
import unittest
from unittest.mock import patch

# Never touch the application's database or contact scan targets.
_temp = tempfile.TemporaryDirectory()
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_temp.name, 'test.db')
os.environ['SECRET_KEY'] = 'test-only-key-that-is-longer-than-32-characters'

try:
    from fastapi.testclient import TestClient
    from main import app
    from database.database import SessionLocal, engine
    from models.models import Scan
except ModuleNotFoundError:
    app = None


@unittest.skipIf(app is None, 'Install backend requirements to run API integration tests')
class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()
        response = cls.client.post('/api/auth/register', json={'username': 'tester', 'email': 'tester@example.com', 'password': 'strong-password'})
        assert response.status_code == 200, response.text
        cls.headers = {'Authorization': 'Bearer ' + response.json()['access_token']}

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)
        engine.dispose()
        _temp.cleanup()

    def test_authentication_required(self):
        self.assertEqual(self.client.get('/api/scan/history').status_code, 401)
        self.assertEqual(self.client.post('/api/auth/login', json={'username': 'tester', 'password': 'wrong'}).status_code, 401)

    def test_registered_account_can_log_back_in(self):
        response = self.client.post('/api/auth/login', json={'username': 'tester', 'password': 'strong-password'})
        self.assertEqual(response.status_code, 200, response.text)
        headers = {'Authorization': 'Bearer ' + response.json()['access_token']}
        self.assertEqual(self.client.get('/api/auth/me', headers=headers).json()['username'], 'tester')
        self.assertEqual(self.client.post('/api/auth/login', json={'username': 'not-registered', 'password': 'strong-password'}).status_code, 401)

    def test_registration_validation(self):
        for updates in [{'email': 'bad'}, {'username': ''}, {'password': 'short'}, {'password': 'é' * 37}]:
            data = {'username': 'other', 'email': 'other@example.com', 'password': 'strong-password', **updates}
            self.assertEqual(self.client.post('/api/auth/register', json=data).status_code, 422)

    def test_invalid_targets(self):
        for target in ['', 'https://example.com/path', 'example.com:443', 'bad domain', '-bad.example']:
            with self.subTest(target=target):
                self.assertEqual(self.client.post('/api/scan/light', headers=self.headers, json={'target': target}).status_code, 422)

    def test_local_tools_not_implemented(self):
        response = self.client.post('/api/scan/local', headers=self.headers, json={'target': 'example.com'})
        self.assertEqual(response.status_code, 501)

    def test_scan_persistence_and_user_isolation(self):
        values = {'run_whois_scan': {'domain_name': 'example.com', 'registrar': 'Example', 'name_servers': ['ns.example.com']}, 'run_dns_scan': {'a': ['93.184.216.34']}, 'run_ssl_scan': {'valid': True}, 'run_headers_scan': {'status_code': 200, 'present': [], 'missing': ['Content-Security-Policy']}, 'run_tech_scan': ['React']}
        from contextlib import ExitStack
        with ExitStack() as stack:
            for name, result in values.items():
                stack.enter_context(patch('api.scan.' + name, return_value=result))
            response = self.client.post('/api/scan/light', headers=self.headers, json={'target': ' EXAMPLE.COM. '})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['target'], 'example.com')
        with SessionLocal() as db:
            scan = db.query(Scan).order_by(Scan.id.desc()).first()
            self.assertEqual(scan.status, 'completed')
            self.assertIsNotNone(scan.completed_at)
        saved = self.client.get('/api/scan/' + str(response.json()['scan_id']), headers=self.headers)
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.json()['completed_at'], response.json()['completed_at'])
        self.assertEqual(saved.json()['vulnerabilities'], response.json()['vulnerabilities'])
        self.assertTrue(saved.json()['vulnerabilities'][0]['evidence'])
        self.assertEqual(self.client.get('/api/auth/me', headers=self.headers).json()['username'], 'tester')
        other = self.client.post('/api/auth/register', json={'username': 'isolated', 'email': 'isolated@example.com', 'password': 'strong-password'}).json()
        history = self.client.get('/api/scan/history', headers={'Authorization': 'Bearer ' + other['access_token']})
        self.assertEqual(history.json(), [])
        foreign_headers = {'Authorization': 'Bearer ' + other['access_token']}
        self.assertEqual(self.client.get('/api/scan/' + str(response.json()['scan_id']), headers=foreign_headers).status_code, 404)
        self.assertEqual(self.client.get('/api/scan/999999', headers=foreign_headers).status_code, 404)
