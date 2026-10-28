"""Live-reader fixture scope and drift checks; not production TLS acceptance."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[1]
for directory in ('scripts','packs/deployment/scripts','core/scripts','tests/support'):
    sys.path.insert(0,str(ROOT/directory))
from tests.test_deployment_compose_restore_body_host import fixture
from deployment_compose_image_defaults import commit_image_config
import compose_restore_observer_fixture as helper


def setup():
    args=fixture();raw=args['raw'];identity=args['identity'];artifact=args['artifact']
    reference='python@sha256:'+'c'*64
    artifact=replace(artifact,registry_digest='docker.io/library/'+reference)
    image=deepcopy(args['image']);image['RepoDigests']=[reference]
    key=args['image_key'];proof=commit_image_config(image,'image-key',key)
    row=deepcopy(raw);row.update(State={'Running':True,'StartedAt':'fixed-start','Health':{'Status':'healthy','Log':[]}},RestartCount=0)
    target=Mock()
    def run(*values):
        if values[:2]==('image','inspect'):return json.dumps([image])
        if values[:2]==('container','inspect'):return json.dumps([row])
        raise AssertionError('fixture attempted a non-read operation')
    target.run.side_effect=run
    observer,observation=helper.archive_observer(target,identity,artifact,args['private_key'],image,proof,key,
        expected_image_key_id='image-key',expected_observed_reference=reference)
    return observer,observation,row,target


class ArchiveObserverFixtureTests(unittest.TestCase):
    def test_archive_representation_has_complete_mount_fields_without_mutating_raw(self):
        from deployment_compose_private import MOUNT
        raw=fixture()['raw'];before=deepcopy(raw)
        normalized=helper.archive_snapshot(raw)
        self.assertEqual(raw,before)
        self.assertTrue(all(set(m)==MOUNT for m in normalized['Mounts']))
        self.assertEqual(normalized['Config'],raw['Config'])
        self.assertEqual(normalized['HostConfig'],raw['HostConfig'])

    def test_live_reads_recheck_and_health_log_noise_is_ignored(self):
        observer,observation,row,target=setup()
        self.assertTrue(observer._test_only)
        before=observer.commitment(observation)
        row['State']['Health']['Log'].append({'Start':'later','Output':'noise'})
        self.assertEqual(observer.commitment(observation),before)
        self.assertTrue(all(call.args[:2] in (('image','inspect'),('container','inspect')) for call in target.run.call_args_list))

    def test_private_configuration_or_lifecycle_drift_invalidates_observation(self):
        for mutate in (lambda r:r['Config']['Env'].append('CHANGED=value'),
                       lambda r:r.update(RestartCount=1),
                       lambda r:r['State'].update(StartedAt='another-start'),
                       lambda r:r['State'].update(Running=False),
                       lambda r:r['State']['Health'].update(Status='unhealthy')):
            observer,observation,row,_=setup();mutate(row)
            with self.assertRaises(ValueError):observer.commitment(observation)


if __name__=='__main__':unittest.main()
