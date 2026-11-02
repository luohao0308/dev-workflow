"""Resource handoff and private artifact tests; Engine preparation is doubled."""
import base64
from copy import copy,deepcopy
import hashlib
import json
import os
from pathlib import Path
import pickle
import secrets
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts','tests/support')]
from tests import test_deployment_compose_recovery_daemon_v3_host as fixture
import deployment_compose_recovery_daemon_v3_host as daemon
import deployment_compose_scene_preparation_v3_host as preparation


@unittest.skipUnless(os.name=='posix','POSIX private files required')
class PreparationTests(unittest.TestCase):
    identity=fixture.DaemonTests.identity
    ticks=fixture.DaemonTests.ticks
    command=fixture.DaemonTests.command
    def setUp(self):
        fixture.DaemonTests.setUp(self);self.patches[-1].stop()
        for item in (patch.object(daemon,'subprocess',SimpleNamespace(run=self.command)),):
            item.start();self.addCleanup(item.stop)
        self.observer=fixture.DaemonTests.observe(self)
        self.subject=preparation.PreparationOwnerV3(self.observer,'b'*40,'c'*64)
        self.keys={k:secrets.token_bytes(32) for k in ('config','image','declaration','archive','target')}
        self.private={'fullConfig':['PRIVATE=body'],'marker':'capsule','artifactServices':('native-dataclass-tuple',)};self.sessions=[]
        def prepare(root,info,**kwargs):
            self.assertEqual(info['DockerRootDir'],str(self.root/'data'))
            target=SimpleNamespace(socket=str(root/'docker.sock'),daemon_id=info['ID'])
            session=preparation.PreparationSession(target,'dw-fixture');self.sessions.append(session)
            kwargs['on_session_created'](session)
            self.assertEqual(session.created_ids,[])
            session.prepared=dict(request=SimpleNamespace(digest=lambda:'d'*64,expires_at='2030-01-01T00:00:00Z'))
            return session
        def facts(channel,*args):channel.emit('observer-facts',bootId='e'*32,bindDigest=None)
        real_directory=preparation.directory
        for item in (patch.object(preparation,'prepare_profile3',side_effect=prepare),
                patch.object(preparation.live,'writer_tls',return_value=('server-private-context','client-private-context','a'*64,'b'*64)),
                patch.object(preparation.live,'private_capsule',side_effect=lambda *a:self.private),
                patch.object(preparation.live,'emit_observer_facts',side_effect=facts),
                patch.object(preparation,'directory',side_effect=lambda p:real_directory(p.resolve()))):
            item.start();self.addCleanup(item.stop)

    def test_identity_and_capsule_survive_reconnect_without_new_preparation(self):
        hello=self.subject.identity('host-one');self.assertEqual(self.subject.identity('host-one'),hello)
        self.assertEqual(self.subject.status()['preparationIdentity'],hello)
        meta=self.subject.prepare('f'*64,self.keys)
        with self.assertRaises(ValueError):self.subject.prepare('f'*64,self.keys)
        raw=bytearray();offset=0
        while offset<meta['totalBytes']:
            chunk=self.subject.chunk(meta['preparationId'],meta['capsuleDigest'],offset,7)
            self.assertEqual(chunk['offset'],offset);self.assertEqual(chunk['totalBytes'],meta['totalBytes'])
            part=base64.b64decode(chunk['dataBase64']);raw.extend(part);offset+=len(part)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),meta['capsuleDigest']);self.assertEqual(json.loads(raw),preparation.live.private_json(self.private))
        self.assertNotIn('PRIVATE',json.dumps(meta));self.assertFalse(meta['approvalReady']);self.assertEqual(len(self.sessions),1)
        self.assertTrue(self.subject.cleanup()['preparationCleaned'])

    def test_chunk_substitution_corruption_and_copy_reject(self):
        self.subject.identity('host-one');meta=self.subject.prepare('f'*64,self.keys)
        for clone in (copy,deepcopy,pickle.dumps):
            with self.assertRaises(ValueError):clone(self.subject)
        with self.assertRaises(ValueError):self.subject.chunk('x',meta['capsuleDigest'],0,10)
        with self.assertRaises(ValueError):self.subject.chunk(meta['preparationId'],meta['capsuleDigest'],True,10)
        file=self.root/'scene-preparation/capsule.private.json';file.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.subject.chunk(meta['preparationId'],meta['capsuleDigest'],0,10)
        self.subject.cleanup()

    def test_system_exit_retains_session_and_unknown_write_cleanup_never_guesses(self):
        self.subject.identity('host-one')
        def interrupted(root,info,**kwargs):
            target=unittest.mock.Mock(socket=str(root/'docker.sock'),daemon_id=info['ID'])
            session=preparation.PreparationSession(target,'dw-fixture');self.sessions.append(session)
            kwargs['on_session_created'](session);session.unknown_write_result=True
            raise SystemExit('interrupted')
        with patch.object(preparation,'prepare_profile3',side_effect=interrupted):
            with self.assertRaises(SystemExit):self.subject.prepare('f'*64,self.keys)
        self.assertEqual(len(self.sessions),1)
        with self.assertRaises(ValueError):self.subject.cleanup()
        self.sessions[0].target.stop.assert_not_called()
        with self.assertRaises(ValueError):self.subject.prepare('f'*64,self.keys)

    def test_known_cleanup_rechecks_original_endpoint_before_resource_deletion(self):
        self.subject.identity('host-one');self.subject.prepare('f'*64,self.keys)
        with patch.object(self.sessions[0],'cleanup') as cleanup,patch.object(preparation,'_fresh',side_effect=ValueError('endpoint-changed')):
            with self.assertRaises(ValueError):self.subject.cleanup()
            cleanup.assert_not_called()
