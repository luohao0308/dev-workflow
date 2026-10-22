"""Durable history authority and kernel-lock contracts (stdlib only)."""
from copy import copy, deepcopy
from dataclasses import asdict, replace, FrozenInstanceError
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
import deployment_store as store
from tests import test_deployment_runtime as fixtures
from tests.test_deployment_runtime import SECRET
from tests.test_deployment_spec import SECRET as SPEC_SECRET

runtime = store.runtime
KEY = b'host-test-key-material-32-bytes!!!'


def fixture():
    original, docker, containers, specs = fixtures.SpecificationRuntimeTests().fixture()
    policy = runtime.RuntimePolicy(**asdict(original.policy))
    return make_collector(policy, original.client._transport), docker, containers, specs


def make_collector(policy, transport):
    client = runtime.DockerTLSClient(policy, ca_file=Path('unused'), cert_file=Path('unused'),
                                     key_file=Path('unused'), transport=transport)
    return runtime.TrustedDockerCollector(policy, client)


# Fresh interpreter: real persisted file verification and live collector issuance.
CHILD = r'''
import json, sys
from pathlib import Path
from tests.test_deployment_store import fixture, store, KEY
c, _, _, _ = fixture()
s = store.HostStore(store.StorePolicy(42, 'host', 'key-v1', c.policy), Path(sys.argv[2]), key=KEY)
if sys.argv[1] == 'load':
    h = s.load_history(sys.argv[3], collector=c, before=c.collect())
    print(json.dumps(dict(evidence=h.evidence_hash, producer=h.policy_hash)), flush=True)
else:
    print('ready', flush=True)
    with s.target_lock():
        print('acquired', flush=True)
        sys.stdin.readline()
    print('released', flush=True)
'''


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'host'
        self.c, self.docker, self.containers, self.specs = fixture()
        self.policy = store.StorePolicy(42, 'host', 'key-v1', self.c.policy)
        self.s = store.HostStore(self.policy, self.root, key=KEY)

    def capture(self):
        old = self.c.collect()
        ref = self.s.capture_history(self.c, old)
        before = self.c.collect()
        return old, ref, before

    def load(self, ref, before, collector=None, backend=None):
        return (backend or self.s).load_history(ref, collector=collector or self.c, before=before)

    def child(self, mode, ref=''):
        process = subprocess.Popen([sys.executable, '-B', '-c', CHILD, mode, str(self.root), ref],
                                   cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.addCleanup(self.cleanup_child, process)
        return process

    @staticmethod
    def cleanup_child(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)

    def test_roundtrip_distinct_frozen_and_no_secrets(self):
        old, ref, before = self.capture()
        h = self.load(ref, before)
        self.assertIs(type(h), store.HistoricalSnapshot)
        self.assertIs(store.HostStore.validate_history(h, collector=self.c, before=before), h)
        self.assertEqual(h.snapshot(), old.snapshot())
        self.assertEqual(h.to_dict(), old.to_dict())
        self.assertEqual(h.evidence_hash, old.evidence_hash)
        self.assertEqual(h.policy_hash, old.policy_hash)
        self.assertEqual(h.current_policy_hash, self.c.policy.identity_hash())
        self.assertEqual(h.store_policy_hash, self.policy.identity_hash())
        self.assertRegex(h.proof_hash, r'^[0-9a-f]{64}$')
        self.assertLess(store._utc(h.captured_at), store._utc(before.captured_at))
        with self.assertRaises(FrozenInstanceError):
            h._ref = 'fake'
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.c.validate(h)
        exported = (self.root / ref).read_text()
        for private in (SECRET, SPEC_SECRET, 'HostConfig', 'Env', 'TOKEN=', 'hostConfig', 'config_json'):
            self.assertNotIn(private, exported)
        # Exported dicts have no mutable connection to authority.
        h.to_dict()['snapshot']['components'].clear()
        self.assertEqual(h.snapshot(), old.snapshot())

    def test_policy_identity_stable_target_not_mutable_catalog_or_transport(self):
        p = self.c.policy
        data = json.loads(p.catalog_json)
        data['images'].append(dict(data['images'][0], imageId='sha256:' + 'f' * 64,
                                   artifact={'kind': 'registry', 'ref': 'registry.invalid/web@sha256:' + 'f' * 64}))
        changed = replace(p, catalog_json=json.dumps(data), endpoint='https://new.invalid:1234',
                          server_certificate_sha256='e' * 64, maximum_age=120)
        self.assertEqual(self.policy.identity_hash(), replace(self.policy, runtime_policy=changed).identity_hash())
        for values in (dict(repository_id=43), dict(store_id='other'), dict(key_id='other')):
            self.assertNotEqual(self.policy.identity_hash(), replace(self.policy, **values).identity_hash())
        for values in (dict(repository='other/repo', catalog_json=json.dumps({'schemaVersion': 1, 'images': []})),
                       dict(environment='prod'), dict(target='other'), dict(production=True),
                       dict(daemon_id='other'), dict(project='other'), dict(components=('web', 'api'))):
            self.assertNotEqual(self.policy.identity_hash(), replace(self.policy, runtime_policy=replace(p, **values)).identity_hash())
        for values in (dict(repository_id=True), dict(repository_id=0), dict(store_id='../host'), dict(key_id='')):
            with self.assertRaises(store.StoreError):
                replace(self.policy, **values)
        with self.assertRaises(store.StoreError):
            store.HostStore(self.policy, self.root, key=b'short')
        with self.assertRaises(store.StoreError):
            store.HostStore(self.policy, ROOT / 'candidate-history', key=KEY)

    def test_forged_copied_other_collector_or_baseline_rejected(self):
        old, ref, before = self.capture()
        h = self.load(ref, before)
        for forged in (object.__new__(store.HistoricalSnapshot), copy(h), deepcopy(h), replace(h),
                       store.HistoricalSnapshot(self.s, ref, self.c, before), old, h.to_dict()):
            with self.subTest(kind=type(forged)), self.assertRaises(store.StoreError):
                store.HostStore.validate_history(forged, collector=self.c, before=before)
        other = make_collector(self.c.policy, self.c.client._transport)
        for collector, baseline in ((other, other.collect()), (self.c, self.c.collect())):
            with self.assertRaises(store.StoreError):
                store.HostStore.validate_history(h, collector=collector, before=baseline)
        for forged in (deepcopy(old), replace(old), old.to_dict(), h):
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.s.capture_history(self.c, forged)

    def test_live_drift_stale_incomplete_and_equal_time_fail_closed(self):
        old, ref, before = self.capture()
        # Loading rechecks live state. Issued history stays historical evidence
        # through replacement stages; the execution guard checks each live stage.
        h = self.load(ref, before)
        self.docker.files['hosts'] += b'changed'
        self.assertEqual(h.snapshot(), old.snapshot())
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.load(ref, before)
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.s.capture_history(self.c, old)
        with mock.patch.object(runtime.time, 'monotonic', return_value=10**15):
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.load(ref, before)
        fresh, _, _, _ = fixture()
        with mock.patch.object(runtime, 'utcnow', return_value=store._utc(h._store._read(ref)['capturedAt'])):
            equal = fresh.collect()
            with self.assertRaises(store.StoreError):
                self.load(ref, equal, fresh)
        container = next(iter(self.containers.values()))
        container['Config']['Env'].append('DRIFT=1')
        incomplete = self.c.collect()
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.s.capture_history(self.c, incomplete)

    def test_capture_requires_spec_and_final_recheck_before_sign(self):
        legacy_policy = replace(self.c.policy, specifications_json=None)
        legacy = make_collector(legacy_policy, self.c.client._transport)
        backend = store.HostStore(replace(self.policy, runtime_policy=legacy_policy), self.root, key=KEY)
        with self.assertRaises(store.StoreError):
            backend.capture_history(legacy, legacy.collect())
        observation = self.c.collect()
        with mock.patch.object(self.c, 'recheck', side_effect=runtime.RuntimeCollectionError('drift')):
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.s.capture_history(self.c, observation)
        self.assertEqual(list(self.root.glob('history-*')), [])

    def test_reload_in_fresh_process_and_new_store(self):
        old, ref, before = self.capture()
        backend = store.HostStore(self.policy, self.root, key=KEY)
        self.assertEqual(self.load(ref, before, backend=backend).evidence_hash, old.evidence_hash)
        child = self.child('load', ref)
        stdout, stderr = child.communicate(timeout=20)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(json.loads(stdout), dict(evidence=old.evidence_hash, producer=old.policy_hash))

    def test_catalog_additions_pin_rotation_allowed_original_producer_retained(self):
        old, ref, _ = self.capture()
        data = json.loads(self.c.policy.catalog_json)
        new_image = 'sha256:' + 'f' * 64
        data['images'].append(dict(data['images'][0], imageId=new_image,
                                   artifact={'kind': 'local-build', 'imageId': new_image, 'buildSourceSha': 'c' * 40}))
        spec = replace(self.specs[0], image_id=new_image)
        p = replace(self.c.policy, catalog_json=json.dumps(data),
                    specifications_json=runtime.deployment_spec.specifications_json((*self.specs, spec)),
                    endpoint='https://rotated.invalid', server_certificate_sha256='e' * 64)
        current = make_collector(p, self.c.client._transport)
        backend = store.HostStore(replace(self.policy, runtime_policy=p), self.root, key=KEY)
        h = self.load(ref, current.collect(), current, backend)
        self.assertEqual(h.policy_hash, old.policy_hash)
        self.assertEqual(h.current_policy_hash, p.identity_hash())
        self.assertNotEqual(h.policy_hash, h.current_policy_hash)
        self.assertEqual(h.store_policy_hash, self.policy.identity_hash())

    def test_current_old_catalog_or_spec_removal_and_changes_rejected(self):
        _, ref, _ = self.capture()
        p = self.c.policy
        # _entries checks historical recipes independently of current live image.
        payload = self.s._read(ref)['observation']
        variants = [replace(p, catalog_json=json.dumps({'schemaVersion': 1, 'images': []})),
                    replace(p, specifications_json=runtime.deployment_spec.specifications_json(()))]
        for field, value in (('sourceSha', 'e' * 40), ('version', '9.0.0'),
                             ('artifact', {'kind': 'registry', 'ref': 'registry.invalid/web@sha256:' + 'f' * 64})):
            data = json.loads(p.catalog_json)
            data['images'][0][field] = value
            if field == 'sourceSha':
                data['images'][0]['artifact']['buildSourceSha'] = value
            variants.append(replace(p, catalog_json=json.dumps(data)))
        recipe = self.specs[0].to_dict()
        recipe['config']['Env'].append('CHANGED=yes')
        changed_spec = runtime.deployment_spec.ContainerSpec('web', self.specs[0].image_id,
                      runtime.canonical(recipe['config']), runtime.canonical(recipe['hostConfig']))
        variants.append(replace(p, specifications_json=runtime.deployment_spec.specifications_json((changed_spec,))))
        for variant in variants:
            with self.subTest(policy=variant), self.assertRaises(store.StoreError):
                self.s._entries(variant, payload)
        other = make_collector(replace(p, daemon_id='foreign-daemon'), self.c.client._transport)
        with self.assertRaises(store.StoreError):
            self.load(ref, self.c.collect(), other)
        for values in (dict(repository_id=43), dict(key_id='key-v2'), dict(store_id='other')):
            backend = store.HostStore(replace(self.policy, **values), self.root, key=KEY)
            with self.assertRaises(store.StoreError):
                self.load(ref, self.c.collect(), backend=backend)

    def test_load_rejects_removed_old_recipe_with_valid_new_live_version(self):
        _, ref, _ = self.capture()
        new_image = 'sha256:' + 'f' * 64
        old_entry = json.loads(self.c.policy.catalog_json)['images'][0]
        new_entry = dict(old_entry, imageId=new_image, version='2.0.0',
                         artifact={'kind': 'local-build', 'imageId': new_image, 'buildSourceSha': 'c' * 40})
        new_spec = replace(self.specs[0], image_id=new_image)
        for container in self.containers.values():
            container['Image'] = new_image
            container['Config']['Image'] = new_image
        self.docker.image['Id'] = new_image
        original = self.c.client._transport
        def transport(path):
            if path == '/v1.45/images/' + new_image + '/json':
                return deepcopy(self.docker.image)
            return original(path)
        changed_entry = dict(old_entry, version='9.0.0')
        old_recipe = self.specs[0].to_dict()
        old_recipe['config']['Env'].append('CHANGED=yes')
        changed_spec = runtime.deployment_spec.ContainerSpec('web', self.specs[0].image_id,
                          runtime.canonical(old_recipe['config']), runtime.canonical(old_recipe['hostConfig']))
        variants = [([new_entry], (*self.specs, new_spec)),
                    ([old_entry, new_entry], (new_spec,)),
                    ([changed_entry, new_entry], (*self.specs, new_spec)),
                    ([old_entry, new_entry], (changed_spec, new_spec))]
        for entries, specs in variants:
            p = replace(self.c.policy, catalog_json=json.dumps(dict(schemaVersion=1, images=entries)),
                        specifications_json=runtime.deployment_spec.specifications_json(specs))
            current = make_collector(p, transport)
            before = current.collect()
            current.validate(before)  # New live version is complete and trusted.
            backend = store.HostStore(replace(self.policy, runtime_policy=p), self.root, key=KEY)
            with self.subTest(entries=entries, specs=len(specs)), self.assertRaises(store.StoreError):
                backend.load_history(ref, collector=current, before=before)

    def test_same_collector_history_must_precede_baseline_issuance(self):
        baseline = self.c.collect()
        later = self.c.collect()
        ref = self.s.capture_history(self.c, later)
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.load(ref, baseline)

    def test_tamper_wrong_key_corrupt_unknown_and_signature_on_every_use(self):
        _, ref, before = self.capture()
        h = self.load(ref, before)
        backend = store.HostStore(self.policy, self.root, key=secrets.token_bytes(32))
        with self.assertRaises(store.StoreError):
            self.load(ref, before, backend=backend)
        path = self.root / ref
        raw = path.read_bytes()
        copied_ref = 'history-' + 'e' * 64 + '.json'
        copied_path = self.root / copied_ref
        copied_path.write_bytes(raw)
        copied_path.chmod(0o600)
        with self.assertRaises(store.StoreError):
            self.load(copied_ref, before)
        for corrupt in (b'{}', b'{broken', raw.replace(b'fixture/example', b'foreign/example'),
                        raw + b' ', b'{"record":{},"record":{},"signature":"x"}'):
            path.write_bytes(corrupt)
            with self.subTest(corrupt=corrupt[:20]), self.assertRaises(store.StoreError):
                h.to_dict()
        path.write_bytes(raw)
        for unknown in ('../' + ref, '/etc/passwd', 'history-' + '0' * 64 + '.json', {}, ''):
            with self.assertRaises(store.StoreError):
                self.load(unknown, before)
        with self.assertRaises(store.StoreError):
            self.load(ref, self.c.collect(), backend=store.HostStore(
                replace(self.policy, repository_id=99), self.root, key=KEY))

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode and link contract')
    def test_private_modes_and_symlink_hardlink_root_replacement_rejected(self):
        _, ref, before = self.capture()
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.root.chmod(0o755)
        with self.assertRaises(store.StoreError):
            self.load(ref, before)
        self.root.chmod(0o700)
        path = self.root / ref
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        os.chmod(path, 0o644)
        with self.assertRaises(store.StoreError):
            self.load(ref, before)
        os.chmod(path, 0o600)
        link = self.root / 'hardlink'
        os.link(path, link)
        with self.assertRaises(store.StoreError):
            self.load(ref, before)
        link.unlink()
        saved = self.root / 'saved'
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaises(store.StoreError):
            self.load(ref, before)
        path.unlink()
        saved.rename(path)
        alias = self.root.parent / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(store.StoreError):
            store.HostStore(self.policy, alias, key=KEY)
        (self.root / 'target.lock').symlink_to(path)
        with self.assertRaises(store.StoreError):
            with self.s.target_lock():
                self.fail('symlink mutex admitted')
        self.root.rename(self.root.with_name('original'))
        self.root.mkdir(mode=0o700)
        with self.assertRaises(store.StoreError):
            self.load(ref, before)

    def test_exclusive_immutable_create_never_overwrites(self):
        old, ref, _ = self.capture()
        original = (self.root / ref).read_bytes()
        with mock.patch.object(store.secrets, 'token_hex', return_value=ref[8:-5]):
            with self.assertRaises(store.StoreError):
                self.s.capture_history(self.c, old)
        self.assertEqual((self.root / ref).read_bytes(), original)

    def test_crossprocess_mutex_never_steals_live_owner_and_releases_on_exit(self):
        import queue
        import threading
        events = queue.Queue()
        with self.s.target_lock():
            child = self.child('lock')
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            reader = threading.Thread(target=lambda: events.put(child.stdout.readline().strip()), daemon=True)
            reader.start()
            with self.assertRaises(queue.Empty):
                events.get(timeout=0.25)
            self.assertIsNone(child.poll())
        self.assertEqual(events.get(timeout=10), 'acquired')
        child.stdin.write('\n')
        child.stdin.flush()
        stdout, stderr = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertIn('released', stdout)
        # A dead process releases the kernel lock without deleting any file.
        owner = self.child('lock')
        self.assertEqual(owner.stdout.readline().strip(), 'ready')
        self.assertEqual(owner.stdout.readline().strip(), 'acquired')
        owner.kill()
        owner.communicate(timeout=10)
        with self.s.target_lock():
            self.assertTrue((self.root / 'target.lock').is_file())


if __name__ == '__main__':
    unittest.main()
