"""Native signatures/Git/custody across exited processes; SSH/Engine are doubles."""
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'core/scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]


def produce(parent, repository, sha, archive):
    from tests.support import compose_scene_create_integration_fixture as integration
    from tests.support.compose_scene_checkpoint_exit_fixture import produce as material_producer
    original = integration.run_case
    measurements = {}

    def run(testcase, *, scene_controller, checkpoint_callback):
        result = original(testcase, scene_controller=scene_controller, scene_callback=checkpoint_callback,
                          published_source=(sha, archive.read_bytes(), repository))
        measurements.update({key: result[key] for key in ('unixFrameBytes', 'sshFrameBytes')})
        return result

    with patch.object(integration, 'run_case', run):
        result = material_producer(parent)
    result['sourceRepository'] = str(repository)
    result.update(measurements)
    return result


def consume(value):
    import os
    from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3, _arguments
    from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3
    descriptor = value['descriptor']; case = Path(descriptor['casePath'])
    before = (case / 'witness/state.json').read_bytes()
    with SceneCheckpointReaderV3(case, **_arguments(descriptor)) as reader:
        proof = reader.verify_published_source(repository=Path(value['sourceRepository']))
        assert reader.writer_origin is not None
        assert proof.gitObjectContentsVerified and proof.publishedSourceArchiveVerified
        assert not proof.sourceRevalidated and not proof.currentPublicationVerified
        summary = reader.context.public_summary()
        assert summary['historyAuthenticated'] and summary['completedWriteCount'] == 1
        assert all(summary[key] is False for key in
                   ('phaseFreshnessVerified', 'linuxQuiescenceVerified', 'executionAvailable',
                    'recoveryAuthorized', 'runtimePermit', 'productionReady'))
    common = _arguments(descriptor)
    del common['expected_scene_binding_digest'], common['expected_intent_key_hash']
    with RestartCheckpointReaderV3(case, **common) as legacy:
        assert legacy.writer_origin is None
    assert (case / 'witness/state.json').read_bytes() == before
    return dict(consumerPid=os.getpid(), historyAuthenticated=True, sourceArchiveBound=True,
                writerOriginBound=True, gitObjectContentsVerified=True, witnessUnchanged=True,
                executionRecovered=False, productionReady=False)


if __name__ == '__main__':
    if sys.argv[1] == 'produce':
        result = produce(Path(sys.argv[2]).resolve(strict=True), Path(sys.argv[3]).resolve(strict=True),
                         sys.argv[4], Path(sys.argv[5]))
    elif sys.argv[1] == 'consume':
        result = consume(json.load(sys.stdin))
    else:
        raise ValueError('fixture action rejected')
    print(json.dumps(result), flush=True)
