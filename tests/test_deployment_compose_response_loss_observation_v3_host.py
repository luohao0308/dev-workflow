"""Strict positive observations contain no response body, CID or authority."""
import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts')]
import deployment_compose_response_loss_observation_v3_host as observation


def fact():
    return dict(schemaVersion=1,diagnosticProfile='response-unobserved-v3',sourceSha='a'*40,
        archiveDigest='b'*64,hostId='host-one',root='/var/tmp/dw-engine-'+'c'*16,daemonId='opaque-daemon',
        requestHash='d'*64,method='POST',pathSha256='e'*64,bodySha256='f'*64,attempts=1,
        requestReturned=True,responseSuppressed=True,originalResponseRead=False,engineOutcome='unknown',
        authorityGranted=False,runtimePermit=False,productionReady=False)


class SchemaTests(unittest.TestCase):
    def test_canonical_copy_and_digest_do_not_mutate_input(self):
        value=fact();copied=observation.validate_observation(value)
        self.assertEqual(copied,value);copied['requestHash']='0'*64
        self.assertEqual(value['requestHash'],'d'*64)
        self.assertEqual(observation.observation_digest(value),hashlib.sha256(observation.encode(value)).hexdigest())

    def test_no_missing_or_additional_body_commit_or_authority_claims(self):
        for key in fact():
            value=fact();del value[key]
            with self.subTest(missing=key),self.assertRaises(ValueError):observation.validate_observation(value)
        for key in ('body','cid','engineCommitted','recoveryAuthorized'):
            with self.subTest(extra=key),self.assertRaises(ValueError):observation.validate_observation(dict(fact(),**{key:True}))

    def test_types_and_context_are_strict(self):
        changes=dict(schemaVersion=True,attempts=True,requestReturned=1,responseSuppressed='true',
            originalResponseRead=0,engineOutcome='committed',authorityGranted=True,runtimePermit=True,
            productionReady=True,method='DELETE',diagnosticProfile='normal',sourceSha='A'*40,
            archiveDigest='bad',requestHash=None,pathSha256='a'*63,bodySha256='b'*65,
            hostId='-oProxyCommand=x',root='/var/tmp/../run/docker.sock',daemonId='')
        for key,value in changes.items():
            with self.subTest(key=key),self.assertRaises(ValueError):observation.validate_observation(dict(fact(),**{key:value}))
