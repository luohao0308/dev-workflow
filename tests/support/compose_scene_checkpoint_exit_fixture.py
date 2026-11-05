"""Scene checkpoint across exited processes; Engine/provider/kernel are doubles."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'core/scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]


def produce(parent):
    from tests.support.compose_scene_create_integration_fixture import run_case
    from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase
    original_temp = tempfile.TemporaryDirectory
    original_init = LocalAcceptanceCase.__init__

    def temporary(*args, **kwargs):
        if kwargs.get('prefix') == 'live-controller-':
            kwargs['dir'] = str(parent)
        return original_temp(*args, **kwargs)

    def initialize(subject, *args, **kwargs):
        original_init(subject, *args, **kwargs)
        assert subject.root.is_relative_to(parent)
        # Keep the original private witness/material for the independent reader.
        # case.close still cleans the Engine fixture and closes the witness store.
        # The parent test owns deletion of this entire private directory.
        subject.temp._finalizer.detach()
        subject.temp.cleanup = lambda: None

    notices = []
    with patch.object(tempfile, 'TemporaryDirectory', temporary), \
            patch.object(LocalAcceptanceCase, '__init__', initialize):
        result = run_case(unittest.TestCase(), scene_controller=True,
                          checkpoint_callback=notices.append)
    assert len(notices) == 1 and result['postCount'] == 1
    return dict(descriptor=notices[0], producerPid=os.getpid(), postCount=1)


def consume(descriptor):
    from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3
    from deployment_compose_checkpoint_archive_v3_host import read_source_archive
    case = Path(descriptor['casePath'])
    before = (case / 'witness/state.json').read_bytes()
    options = dict(expected_material_digest=descriptor['materialDigest'],
                   expected_custody_digest=descriptor['custodyDigest'],
                   expected_context=descriptor['context'],
                   expected_witness_key_hash=descriptor['witnessKeyHash'])
    test = unittest.TestCase()
    with RestartCheckpointReaderV3(case, **options) as reader:
        test.assertIsNone(reader.writer_origin)
        test.assertEqual(reader.context.snapshot.snapshot['chainStatus']['activeSeq'], 6)
        test.assertEqual(reader.context.snapshot.digest, descriptor['context']['historyDigest'])
        summary = reader.context.public_summary()
        for flag in ('phaseFreshnessVerified', 'linuxQuiescenceVerified',
                     'executionAvailable', 'recoveryAuthorized', 'productionReady'):
            test.assertFalse(summary[flag])
        with test.assertRaises(ValueError):
            read_source_archive(reader)
    with test.assertRaises(ValueError):
        RestartCheckpointReaderV3(case, **dict(options, expected_material_digest='0' * 64))
    test.assertEqual(before, (case / 'witness/state.json').read_bytes())
    return dict(consumerPid=os.getpid(), historyAuthenticated=True,
                writerOriginBound=False, sourceArchiveBound=False,
                executionRecovered=False, witnessUnchanged=True)


if __name__ == '__main__':
    if sys.argv[1] == 'produce':
        result = produce(Path(sys.argv[2]).resolve(strict=True))
    elif sys.argv[1] == 'consume':
        result = consume(json.load(sys.stdin))
    else:
        raise ValueError('fixture action rejected')
    print(json.dumps(result), flush=True)
