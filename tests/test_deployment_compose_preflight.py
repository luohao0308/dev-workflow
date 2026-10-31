import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'packs/deployment/scripts/deployment_compose_preflight.py'
sys.path.insert(0, str(SCRIPT.parent))
import deployment_compose_preflight as preflight


def model():
    return {'name': 'fixture', 'services': {
        'web': {'image': 'registry.example/web@sha256:' + 'a' * 64,
                'read_only': True, 'user': '10001:10001', 'cap_drop': ['ALL'],
                'security_opt': ['no-new-privileges:true'], 'restart': 'no',
                'environment': {'PRIVATE_TEST_SECRET': 'do-not-print'},
                'networks': {'default': None}},
        'db': {'image': 'mysql:8', 'volumes': ['database:/var/lib/mysql']}}}


class ComposePreflightTests(unittest.TestCase):
    def test_candidate_is_only_untrusted_structural_screening(self):
        result = preflight.assess(model(), 'web')
        self.assertEqual(result['structuralStatus'], 'candidate-unverified')
        self.assertEqual(result['runtimeVerification'], 'unknown')
        self.assertFalse(result['authorityGranted'])
        self.assertFalse(result['executionAvailable'])
        self.assertFalse(result['productionReady'])
        self.assertNotIn('do-not-print', json.dumps(result))

    def test_unsupported_selected_service_and_mutable_image_are_blocked(self):
        value = model()
        value['services']['web'].update(image='registry.example/web:latest', volumes=['uploads:/data'], restart='always')
        result = preflight.assess(value, 'web')
        self.assertEqual(result['structuralStatus'], 'blocked')
        self.assertEqual(result['reasons'], sorted(('immutable-image-required', 'unsupported-service-fields',
                                                     'restart-policy-unsupported')))
        self.assertNotIn('uploads:/data', json.dumps(result))

    def test_url_shaped_image_is_not_a_registry_digest(self):
        value = model()
        value['services']['web']['image'] = 'http://evil.example/web@sha256:' + 'a' * 64
        self.assertIn('immutable-image-required', preflight.assess(value, 'web')['reasons'])

    def test_explicit_command_override_is_blocked_but_normalized_null_is_allowed(self):
        value = model()
        value['services']['web'].update(command=None, entrypoint=None)
        self.assertEqual(preflight.assess(value, 'web')['structuralStatus'], 'candidate-unverified')
        value['services']['web']['command'] = ['sh', '-c', 'echo custom']
        self.assertIn('command-override-unsupported', preflight.assess(value, 'web')['reasons'])

    def test_missing_hardening_controls_are_blocked(self):
        value = model()
        for key in ('read_only', 'user', 'cap_drop', 'security_opt'):
            value['services']['web'].pop(key)
        self.assertEqual(set(preflight.assess(value, 'web')['reasons']), {
            'read-only-root-required', 'numeric-nonroot-user-required',
            'drop-all-capabilities-required', 'no-new-privileges-required'})

    def test_duplicate_json_or_missing_service_is_rejected(self):
        with self.assertRaisesRegex(preflight.PreflightError, 'duplicate-json-field'):
            preflight.parse_model(b'{"services":{},"services":{}}')
        with self.assertRaisesRegex(preflight.PreflightError, 'duplicate-json-field'):
            preflight.parse_model(b'{"services":{"web":{"image":"first","image":"second"}}}')
        with self.assertRaisesRegex(preflight.PreflightError, 'missing-compose-service'):
            preflight.assess(model(), 'missing')

    def test_malformed_and_oversized_models_are_rejected(self):
        for raw in (b' ' * (preflight.MAX_MODEL + 1), b'{"services":{},"number":NaN}',
                    b'{"services":{},"name":"\xff"}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(preflight.PreflightError):
                preflight.parse_model(raw)

    def test_other_services_and_top_level_volumes_do_not_claim_runtime_safety(self):
        value = model()
        value['volumes'] = {'database': {}}
        result = preflight.assess(value, 'web')
        self.assertEqual(result['structuralStatus'], 'candidate-unverified')
        self.assertEqual(result['runtimeVerification'], 'unknown')
        self.assertFalse(result['productionReady'])

    def test_cli_does_not_echo_model_or_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'model.json'
            path.write_text(json.dumps(model()), encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--model', str(path), '--service', 'web'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['structuralStatus'], 'candidate-unverified')
            self.assertNotIn('do-not-print', result.stdout + result.stderr)
            link = Path(directory) / 'linked.json'
            link.symlink_to(path)
            rejected = subprocess.run([sys.executable, '-B', str(SCRIPT), '--model', str(link), '--service', 'web'],
                                      capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(json.loads(rejected.stderr)['error'], 'invalid-model-file')


if __name__ == '__main__':
    unittest.main()
