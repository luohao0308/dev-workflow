"""Original managed controller capture, exited producer and cold reader.

Engine/provider/SSH/systemd are explicit doubles; admission, history, pipe
ownership, HMAC, SSHSIG, private storage and process exit are actual.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts', 'tests/support'))]

from tests.test_deployment_compose_owned_recovery_session_v3_host import SessionTests
from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase
import deployment_compose_owned_recovery_controller_v3_host as controller


def produce(directory, *, fail_callback=False):
    harness = SessionTests('test_full_managed_flow_checks_independent_history_and_manager_completion')
    session = harness.open(verify_daemon=True, verify_resources=True, verify_host=True)
    owner = SimpleNamespace(reviewed=[])
    base = LocalAcceptanceCase.review_adapter(owner)
    captured = []
    second_reviews = []
    closed = []
    def checkpoint(value):
        if captured:
            raise AssertionError('checkpoint delivered twice')
        captured.append(deepcopy(value))
        if fail_callback:
            raise RuntimeError('checkpoint-callback-refused')
    class Review:
        def consume_prepared(self, bundle, request, notice):
            if request.operation == 'recovery':
                second_reviews.append(True)
                raise RuntimeError('second-review-refused')
            return base.consume_prepared(bundle, request, notice)
        def close(self):
            closed.append(True)
    expected_error = 'checkpoint-callback-refused' if fail_callback else 'second-review-refused'
    try:
        try:
            controller._drive_managed_recovery_protocol(directory, session=session,
                review=Review(), on_review=lambda value: None,
                on_restart_checkpoint=checkpoint, timeout=100)
        except RuntimeError as error:
            if str(error) != expected_error or getattr(error, 'owned_recovery_cleanup_failed', False):
                raise
        else:
            raise AssertionError('producer must stop before second consumption')
        assert len(captured) == 1
        assert [request.operation for request in owner.reviewed] == ['deploy']
        assert len(second_reviews) == (0 if fail_callback else 1)
        assert closed == [True]
        report = session.cleanup_report()
        assert not report['cleanupErrors']
        assert all(report[key] is True for key in ('closed', 'managerReceiptVerified',
            'localProcessReaped', 'localStreamsClosed', 'stderrReaderStopped',
            'daemonStoppedVerified', 'hostSnapshotUnchangedVerified'))
        assert report['completionPathSucceeded'] is False
        case = Path(captured[0]['casePath'])
        assert case.is_relative_to(directory)
        assert not list(case.glob('history-terminal-certificate.private.json'))
        # Pins are returned via the native callback, never reconstructed from
        # an adjacent manifest or by patching the save implementation.
        return dict(descriptor=captured[0], producerPid=os.getpid(),
            reviewedOperations=['deploy'], secondReviewCalls=len(second_reviews),
            secondConsumptionCount=0, controllerCleanupVerified=True,
            callbackFailed=fail_callback, executionRecovered=False)
    finally:
        if not harness.doCleanups():
            raise AssertionError('producer fixture cleanup failed')


def consume(descriptor):
    from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3
    case = Path(descriptor['casePath'])
    before = (case / 'witness/state.json').read_bytes()
    with RestartCheckpointReaderV3(case,
            expected_material_digest=descriptor['materialDigest'],
            expected_custody_digest=descriptor['custodyDigest'],
            expected_context=descriptor['context'],
            expected_witness_key_hash=descriptor['witnessKeyHash']) as reader:
        context = reader.context
        assert context.snapshot.digest == descriptor['context']['historyDigest']
        summary = context.public_summary()
    try:
        context.history.capture()
    except ValueError:
        pass
    else:
        raise AssertionError('closed reader left a usable transport')
    assert (case / 'witness/state.json').read_bytes() == before
    return dict(consumerPid=os.getpid(), summary=summary, witnessUnchanged=True,
        historicalTransportClosed=True, newApprovalConsumptions=0, engineRequests=0,
        executionRecovered=False)


if __name__ == '__main__':
    action = sys.argv[1]
    if action == 'produce':
        result = produce(Path(sys.argv[2]).resolve(strict=True))
    elif action == 'consume':
        result = consume(json.load(sys.stdin))
    else:
        raise ValueError('fixture action rejected')
    print(json.dumps(result), flush=True)
