import copy
import json
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from deployment_compose_collect import collect, image_catalog_digest
from deployment_compose_reader import ComposeDockerReader, ComposeReadError, ComposeNotFound, ComposeReadPolicy
from test_deployment_compose_observation import fixture


def harness(mutate=None, *, gateway=None, private=None, bind=None):
    if bind is not None and private is None:
        private = lambda cid, round_number: 'a' * 64
    records, policy = fixture()
    image = 'sha256:' + 'a' * 64
    read_policy = ComposeReadPolicy('https://docker.example', 'a' * 64, policy['daemonId'],
                                    policy['project'], tuple(policy['volumes']),
                                    gateway_policy_hash='b' * 64 if gateway is not None else None,
                                    private_key_id='host-key-1' if private is not None or bind is not None else None,
                                    bind_count=1 if bind is not None else 0)
    calls = []
    reader = ComposeDockerReader(read_policy, ca_file=Path('/unused'), cert_file=Path('/unused'),
                                 key_file=Path('/unused'), transport=lambda path: transport(path))

    def transport(path):
        calls.append(path)
        pass_number = (calls.count('/v1.45/info') - 1) // 2
        snapshot = copy.deepcopy(records)
        if mutate:
            mutate(snapshot, pass_number)
        if path == '/v1.45/workflow/reader-info':
            value = gateway(calls.count(path))
        elif path.startswith('/v1.45/workflow/private/'):
            value = {'schemaVersion': 1, 'keyId': 'host-key-1',
                     'configHmac': private(path.split('/')[-1], pass_number),
                     'authorityGranted': False}
        elif path == '/v1.45/workflow/binds/0':
            value = {'schemaVersion': 1, 'bindDigest': bind(pass_number),
                     'authorityGranted': False}
        elif path == '/v1.45/info':
            value = {'ID': policy['daemonId']}
        elif path == reader.list_path:
            value = [{'Id': c['id'], 'Labels': c['labels']} for c in snapshot['containers']]
        elif path.startswith('/v1.45/containers/'):
            cid = path.split('/')[3]
            c = next(c for c in snapshot['containers'] if c['id'] == cid)
            value = {'Id': cid, 'Name': '/' + c['name'], 'Image': c['imageId'],
                     'Config': {'Labels': c['labels'], 'Env': ['TOKEN=private-value']},
                     'NetworkSettings': {'Networks': {n['name']: {'NetworkID': n['id'],
                                                                'Aliases': n['aliases']} for n in c['networks']}},
                     'Mounts': [{'Type': m['type'], 'Name': m['source'],
                                 'Source': m['source'], 'Destination': m['target'],
                                 'RW': not m['readOnly']} for m in c['mounts']],
                     'RestartCount': c.get('restartCount', 0),
                     'State': {'Running': c['running'], 'Pid': c.get('pid', 100),
                               'StartedAt': c.get('startedAt', '2026-10-25T00:00:00Z'),
                               'Health': {'Status': c['health'],
                                'Log': ['private-value']}}}
        elif path.startswith('/v1.45/networks/'):
            n = snapshot['networks'][0]
            value = {'Id': n['id'], 'Name': n['name'], 'Labels': {'com.docker.compose.project': n['project']}}
        elif path.startswith('/v1.45/volumes/'):
            v = snapshot['volumes'][0]
            value = {'Name': v['name'], 'Driver': v['driver'], 'Options': v['options'],
                     'Labels': {'com.docker.compose.project': v['project']}}
        elif path.startswith('/v1.45/images/'):
            value = {'Id': image, 'Os': 'linux', 'Architecture': 'amd64',
                     'RepoDigests': ['registry.example/blog@sha256:' + 'b' * 64],
                     'Config': {'Env': ['TOKEN=private-value']}}
        else:
            raise AssertionError('unexpected read')
        return json.dumps(value).encode()
    return reader, policy, calls


class CollectTests(unittest.TestCase):
    def test_image_catalog_digest_rejects_malformed_projection(self):
        image = 'sha256:' + 'a' * 64
        good = {image: {'os': 'linux', 'architecture': 'amd64',
                        'repoDigests': ['registry.example/blog@sha256:' + 'b' * 64]}}
        self.assertEqual(len(image_catalog_digest(good)), 64)
        bad = copy.deepcopy(good)
        bad[image]['repoDigests'] = [{}]
        with self.assertRaisesRegex(ValueError, '^invalid-image-catalog$'):
            image_catalog_digest(bad)

    def test_complete_six_service_scope_two_passes_and_no_secrets(self):
        reader, policy, calls = harness()
        result = collect(reader, policy)
        self.assertEqual(result['structuralStatus'], 'candidate-unverified')
        self.assertEqual(calls.count('/v1.45/info'), 4)
        self.assertEqual(sum(c.startswith('/v1.45/containers/') and c.endswith('/json') for c in calls), 12)
        self.assertFalse(result['executionAvailable'])
        self.assertFalse(result['authorityGranted'])
        self.assertFalse(result['productionReady'])
        self.assertEqual(result['runtimeVerification'], 'unknown')
        self.assertEqual(len(result['instanceDigest']), 64)
        self.assertEqual(len(result['imageCatalogDigest']), 64)
        self.assertEqual(set(result['serviceImages']),
                         set(policy['selectedServices'] + policy['protectedServices']))
        self.assertNotIn('private-value', json.dumps(result))

    def test_missing_extra_and_drift_fail_closed(self):
        for mutation in (
            lambda r, p: r['containers'].pop(),
            lambda r, p: r['containers'].append({**copy.deepcopy(r['containers'][0]), 'id': 'f' * 64}),
            lambda r, p: r['networks'][0].update(id='c' * 64) if p else None,
            lambda r, p: r['volumes'][0].update(driver='other') if p else None,
        ):
            with self.subTest(mutation=mutation):
                reader, policy, _ = harness(mutation)
                self.assertEqual(collect(reader, policy)['structuralStatus'], 'blocked')

    def test_health_log_change_is_not_structural(self):
        def change(records, pass_number):
            if pass_number:
                records['containers'][0]['health'] = 'starting'
        reader, policy, _ = harness(change)
        self.assertEqual(collect(reader, policy)['structuralStatus'], 'candidate-unverified')

    def test_restart_between_rounds_is_not_a_stable_instance(self):
        def restarted(records, pass_number):
            if pass_number:
                records['containers'][0]['pid'] = 101
                records['containers'][0]['startedAt'] = '2026-10-25T00:01:00Z'
                records['containers'][0]['restartCount'] = 1
        reader, policy, _ = harness(restarted)
        self.assertEqual(collect(reader, policy)['reasons'], ['instance-drift'])

        stable_reader, stable_policy, _ = harness()
        baseline = collect(stable_reader, stable_policy)['instanceDigest']
        changed_reader, changed_policy, _ = harness(
            lambda records, _: records['containers'][0].update(pid=101))
        self.assertNotEqual(baseline, collect(changed_reader, changed_policy)['instanceDigest'])

    def test_image_catalog_drift_is_blocked_without_disclosing_registry(self):
        reader, policy, calls = harness()
        original = reader._transport
        def changed(path):
            raw = original(path)
            if path.startswith('/v1.45/images/') and calls.count('/v1.45/info') > 2:
                value = json.loads(raw)
                value['RepoDigests'] = ['registry.example/blog@sha256:' + 'c' * 64]
                return json.dumps(value).encode()
            return raw
        reader._transport = changed
        result = collect(reader, policy)
        self.assertEqual(result['reasons'], ['image-catalog-drift'])
        self.assertNotIn('registry.example', json.dumps(result))

    def test_unknown_response_and_secret_are_sanitized(self):
        reader, policy, _ = harness()
        original = reader._transport
        reader._transport = lambda path: b'{"Env":"private-value"}' if path == reader.list_path else original(path)
        result = collect(reader, policy)
        self.assertEqual(result['structuralStatus'], 'blocked')
        self.assertNotIn('private-value', json.dumps(result))

    def test_finite_reader_errors_preserve_safe_category(self):
        for error, code in ((ComposeReadError('pin-mismatch'), 'pin-mismatch'),
                            (ComposeReadError('deadline-exceeded'), 'deadline-exceeded'),
                            (ComposeNotFound(), 'exact-not-found')):
            with self.subTest(code=code):
                reader, policy, _ = harness()
                reader.get = lambda path, *, deadline=None: (_ for _ in ()).throw(error)
                result = collect(reader, policy)
                self.assertEqual(result['reasons'], ['docker-read-' + code])
                self.assertEqual(result['structuralStatus'], 'blocked')
                self.assertFalse(result['executionAvailable'])

        reader, policy, _ = harness()
        reader.get = lambda path, *, deadline=None: (_ for _ in ()).throw(RuntimeError('TOKEN=private-value'))
        result = collect(reader, policy)
        self.assertEqual(result['reasons'], ['read-unverified'])
        self.assertNotIn('private-value', json.dumps(result))

    def test_invalid_policy_is_blocked(self):
        reader, policy, _ = harness()
        policy['volumes'] = ['unexpected']
        result = collect(reader, policy)
        self.assertEqual(result['structuralStatus'], 'blocked')
        self.assertFalse(result['authorityGranted'])

    def test_total_collection_deadline_is_shared_across_reads(self):
        reader, policy, _ = harness()
        original = reader._transport
        def slow(path):
            time.sleep(0.02)
            return original(path)
        reader._transport = slow
        result = collect(reader, policy, max_seconds=0.005)
        self.assertEqual(result['reasons'], ['docker-read-deadline-exceeded'])
        self.assertFalse(result['authorityGranted'])
        self.assertEqual(collect(reader, policy, max_seconds=0)['reasons'], ['invalid-input'])

    def test_gateway_boot_is_checked_at_both_ends_without_granting_authority(self):
        stable = lambda number: {'bootId': 'c' * 32, 'policyHash': 'b' * 64}
        reader, policy, calls = harness(gateway=stable)
        result = collect(reader, policy)
        self.assertEqual(result['structuralStatus'], 'candidate-unverified')
        self.assertEqual(calls.count('/v1.45/workflow/reader-info'), 2)
        self.assertEqual(result['runtimeVerification'], 'unknown')
        self.assertFalse(result['authorityGranted'])
        self.assertFalse(result['executionAvailable'])
        self.assertFalse(result['productionReady'])

        reader, policy, _ = harness(gateway=lambda number: {
            'bootId': ('c' if number == 1 else 'd') * 32, 'policyHash': 'b' * 64})
        self.assertEqual(collect(reader, policy)['reasons'], ['gateway-boot-drift'])

        reader, policy, _ = harness(gateway=lambda number: {'bootId': 'c' * 32,
                                                             'policyHash': 'd' * 64})
        self.assertEqual(collect(reader, policy)['reasons'], ['docker-read-gateway-mismatch'])

    def test_host_private_commitments_detect_drift_without_granting_authority(self):
        gateway = lambda _: {'bootId': 'c' * 32, 'policyHash': 'b' * 64}
        reader, policy, calls = harness(gateway=gateway,
                                        private=lambda cid, round_number: 'a' * 64)
        result = collect(reader, policy)
        self.assertEqual(result['structuralStatus'], 'candidate-unverified')
        self.assertEqual(sum('/workflow/private/' in path for path in calls), 12)
        self.assertEqual(len(result['privateDigest']), 64)
        self.assertEqual(result['serviceConfigHmacs'],
                         {service: 'a' * 64 for service in policy['selectedServices'] + policy['protectedServices']})
        self.assertFalse(result['authorityGranted'])
        self.assertFalse(result['executionAvailable'])

        reader, policy, _ = harness(gateway=gateway,
                                    private=lambda cid, round_number: ('a' if round_number == 0
                                                                        else 'b') * 64)
        self.assertEqual(collect(reader, policy)['reasons'], ['private-config-drift'])

    def test_bind_content_drift_is_blocked_without_path_disclosure(self):
        gateway = lambda _: {'bootId': 'c' * 32, 'policyHash': 'b' * 64}
        reader, policy, calls = harness(gateway=gateway, bind=lambda _: 'a' * 64)
        result = collect(reader, policy)
        self.assertEqual(len(result['bindDigest']), 64)
        self.assertEqual(calls.count('/v1.45/workflow/binds/0'), 2)
        self.assertFalse(result['authorityGranted'])
        reader, policy, _ = harness(gateway=gateway,
                                    bind=lambda round_number: ('a' if round_number == 0 else 'b') * 64)
        self.assertEqual(collect(reader, policy)['reasons'], ['bind-content-drift'])

        reader, policy, _ = harness(gateway=lambda number: {'policyHash': 'b' * 64})
        self.assertEqual(collect(reader, policy)['reasons'], ['docker-read-gateway-mismatch'])


if __name__ == '__main__':
    unittest.main()
