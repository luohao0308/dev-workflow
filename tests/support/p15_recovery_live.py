#!/usr/bin/env python3
"""Disposable Linux Actions crash/recovery proof, never a consumer entry point.

A trusted child is killed after the gateway has completed a real Docker write,
before its response is persisted in the observer journal. The parent gateway
survives; a new observer proves quiescence and requires independent recovery
approval. Original deployment authority is explicitly synthetic in this fixture.
"""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(1, str(ROOT / 'packs/deployment/scripts'))
sys.path.insert(2, str(Path(__file__).resolve().parent))
import p14_execution_live as provision
import deployment_gateway as gateway
import deployment_gateway_host as gateway_host
import deployment_recover as recovery
import deployment_recovery_host as authority
import deployment_store as history
import deployment_verify as verification
import release_host_runner
from release_host import bundle_digest

sdk, runtime, execution = provision.sdk, provision.runtime, provision.execution


def embedding(config):
    p = dict(config['runtime'])
    p['components'] = tuple(p['components'])
    p = runtime.RuntimePolicy(**p)
    directory = Path(config['directory'])
    reader = runtime.DockerTLSClient(p, ca_file=directory / 'ca.pem', cert_file=directory / 'reader.pem',
                                    key_file=directory / 'reader.key')
    collector = runtime.TrustedDockerCollector(p, reader)
    store = history.HostStore(history.StorePolicy(config['metadata']['targetRepositoryId'], 'p15-host', 'key-one', p),
        directory / 'store', key=bytes.fromhex(config['storeKey']))
    gate = gateway.FileWriterGate(gateway.GatePolicy('p15-host', 'key-one', runtime.digest(store.policy._scope()),
        config['writerPin']), directory / 'gate', key=bytes.fromhex(config['gateKey']))
    probe = verification.ProbePolicy(**config['probe'])
    verifier = verification.TrustedProbeVerifier(probe, p)
    epolicy = execution.ExecutionPolicy(p, config['writerPin'], verification_policy_hash=probe.identity_hash(),
        history_policy_hash=store.policy.identity_hash(), gateway_policy_hash=gate.policy.identity_hash())
    if epolicy.identity_hash() != config['executionPolicyHash']:
        raise ValueError('Fixture execution policy changed')
    client = execution.DockerMutationClient(epolicy, ca_file=directory / 'ca.pem',
        cert_file=directory / 'writer.pem', key_file=directory / 'writer.key')
    coordinator = recovery.HostCoordinator(store, gate, collector, epolicy)
    executor = execution.DockerExecutor(epolicy, client, collector, verifier=verifier, coordinator=coordinator)
    coordinator.executor = executor
    return collector, coordinator, executor


def child(config_path, crash_after):
    config = json.loads(Path(config_path).read_text())
    collector, coordinator, executor = embedding(config)
    root = Path(config['candidate'])
    observation = collector.collect()
    collector.validate(observation)
    records = root / sdk.RECORDS
    records.mkdir(parents=True, exist_ok=True)
    provision.save(records / 'current.json', observation.snapshot())
    catalog = runtime._catalog(collector.policy)
    entry = next(item for item in catalog.values() if item['component'] == 'web' and item['version'] == '2.0.0')
    spec = execution._specifications(collector.policy)[('web', entry['imageId'])]
    desired = dict(name='web', sourceSha=entry['sourceSha'], artifact=entry['artifact'],
                   configurationDigest=spec.configuration_digest(), migrationVersion=None)
    provision.save(records / 'target.json', dict(schemaVersion=1, kind='deployment-target', environment='staging',
        target='p1-isolated', version='v2', components=[desired]))
    provision.save(records / 'conditions.json', dict(schemaVersion=1, kind='deployment-conditions', environment='staging',
        target='p1-isolated', backup=dict(required=False, reference=None, restoreEvidence=None),
        migration=dict(mode='none', evidence=None)))
    plan = sdk.planner.prepare(root, 'staging', sdk.RECORDS + 'target.json', sdk.RECORDS + 'current.json',
                               sdk.RECORDS + 'conditions.json')
    assert plan['result'] == 'prepared', plan['blockers']
    intent = executor.prepare(root, plan, 'deployment-deploy', observation=observation)
    request = sdk.build_request(root, plan, 'deployment-deploy', collector=collector, observation=observation,
        repository_slug=config['metadata']['targetRepository'], repository_id=config['metadata']['targetRepositoryId'],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(), execution_intent=intent)
    # Deliberate fault injection in the trusted fixture, never a product loader.
    original = recovery.HostOperation.after_write
    completed = 0
    def crash(operation, session, digest):
        nonlocal completed
        completed += 1
        if completed == crash_after:
            os._exit(77)  # Bypass finally: leave actual Core owner and observer journal.
        return original(operation, session, digest)
    recovery.HostOperation.after_write = crash
    with coordinator.operation(root, plan, intent) as operation:
        permit = sdk.authorize(root, plan, request, collector=collector, observation=observation,
            approval=provision.TestApproval(), execution_intent=intent, host_operation=operation)
        executor.execute(root, permit, intent, host_operation=operation)
    raise AssertionError('Crash point was not reached')


class RecoveryTestApproval:
    """Independent synthetic recovery authority, never described as GitHub review."""
    def __init__(self):
        self.used = set()
    def validate(self, request):
        return recovery.RecoveryGrant('fixture:recovery', request.digest(), request.expires_at, 1)
    def consume(self, grant, request, *, before_consume):
        before_consume()
        if request.digest() in self.used:
            raise ValueError('Recovery already consumed')
        self.used.add(request.digest())
        return recovery.RecoveryReceipt(grant.grant_id, request.digest(), 1, sdk.clock().isoformat())
    def guard(self, request):
        if request.digest() not in self.used:
            raise ValueError('Recovery not consumed')


def recovery_child(config_path, crash_after):
    """Crash a separately authorized recovery after its real gateway write."""
    if os.environ.get('P15_REAL_AUTHORITY') != 'false':
        raise ValueError('Recovery crash fixture requires explicit synthetic authority')
    config = json.loads(Path(config_path).read_text())
    _, coordinator, _ = embedding(config)
    pending = coordinator._ids()
    assert len(pending) == 1
    request = coordinator.prepare_recovery(Path(config['candidate']), pending[0],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat())
    output = ROOT / 'p15-results'
    provision.save(output / 'recovery-child-request.json', dict(requestId=request.request_id,
        requestHash=request.digest(), producerPID=os.getpid(), actions=json.loads(request.actions_json),
        authority='synthetic-test-double'))
    original = recovery.HostOperation.after_write
    completed = 0
    def crash(operation, session, digest):
        nonlocal completed
        completed += 1
        if completed == crash_after:
            os._exit(78)  # Gateway completed; observer has not journaled its response.
        return original(operation, session, digest)
    recovery.HostOperation.after_write = crash
    coordinator.recover(request, RecoveryTestApproval())
    raise AssertionError('Recovery crash point was not reached')


def actual_approval(config, request, output):
    metadata = config['metadata']
    expires = request.expires_at
    policy = authority.RecoveryHostPolicy(host_repository=metadata['hostRepository'],
        host_repository_id=metadata['hostRepositoryId'], workflow_ref=os.environ['GITHUB_WORKFLOW_REF'],
        workflow_sha=os.environ['GITHUB_SHA'], run_id=int(os.environ['GITHUB_RUN_ID']), environment='p15-observer',
        reviewer_ids=tuple(metadata['reviewerIds']), target_repository=metadata['targetRepository'],
        target_repository_id=metadata['targetRepositoryId'], ledger_repository=metadata['hostRepository'],
        ledger_repository_id=metadata['hostRepositoryId'], ledger_sha=os.environ['GITHUB_SHA'], expires_at=expires,
        prevent_self_review=False, deployment_environment='staging', deployment_target='p1-isolated', production=False,
        runtime_policy_hash=request.runtime_policy_hash, allowed_components=('web', 'api'),
        approval_environment='p15-recovery-approval', execution_policy_hash=request.execution_policy_hash,
        store_policy_hash=request.store_policy_hash, gate_policy_hash=request.gate_policy_hash)
    digest = bundle_digest([request], expires, policy.bundle_context())
    provision.save(output / 'recovery-preview.json', dict(bundleHash=digest, request=asdict(request),
        hostPolicy=asdict(policy), originalDeployAuthority='synthetic-test-double',
        realDocker=True, productionReady=False))
    gh = provision.GitHubClient(os.environ['P1_GITHUB_TOKEN'])
    run_path = '/repos/' + metadata['hostRepository'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID']
    until = time.monotonic() + 2100
    while time.monotonic() < until:
        reviews, _ = gh.request('GET', run_path + '/approvals')
        if any(review.get('state') == 'approved' and review.get('comment') == 'dev-workflow approve ' + digest
               and any(item.get('name') == 'p15-recovery-approval' for item in review.get('environments', []))
               for review in reviews):
            break
        time.sleep(5)
    else:
        raise ValueError('Exact recovery review timed out')
    for _ in range(15):
        state, _ = gh.request('GET', run_path)
        if state.get('status') == 'in_progress':
            break
        time.sleep(2)
    previous = release_host_runner.AUDIENCE
    try:
        release_host_runner.AUDIENCE = authority.AUDIENCE
        token = release_host_runner.oidc_token()
    finally:
        release_host_runner.AUDIENCE = previous
    return authority.GitHubRecoveryApproval(gh, token, [request], policy)


def exercise(state, after_recovery=None):
    import ssl
    directory, metadata = state['directory'], state['metadata']
    if (metadata['targetRepository'] != 'luohao0308/dev-workflow-p0-target-20261022'
            or metadata['targetRepositoryId'] != 1428943581
            or metadata['hostRepository'] != 'luohao0308/dev-workflow-p0-host-public-20261022'):
        raise ValueError('Only the explicit independent synthetic repositories are allowed')
    recovery_crash_after = int(os.environ.get('P15_RECOVERY_CRASH_AFTER', '0'))
    real = os.environ.get('P15_REAL_AUTHORITY') == 'true'
    if (recovery_crash_after not in (0, 1, 2, 3)
            or (recovery_crash_after and os.environ.get('P15_REAL_AUTHORITY') != 'false')):
        raise ValueError('Recovery crash requires synthetic authority and write 1/2/3')
    output = ROOT / 'p15-results'
    output.mkdir()
    before = state['collector'].collect()
    before_api = next(item for item in before.to_dict()['instances'] if item['component'] == 'api')
    state['server'].shutdown()
    state['server'].server_close()
    stub = state['policy']
    store_key, gate_key = secrets.token_bytes(32), secrets.token_bytes(32)
    temporary_policy = history.StorePolicy(metadata['targetRepositoryId'], 'p15-host', 'key-one', stub)
    gp = gateway.GatePolicy('p15-host', 'key-one', runtime.digest(temporary_policy._scope()), state['certificate_hash']('writer'))
    parent_gate = gateway.FileWriterGate(gp, directory / 'gate', key=gate_key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory / 'server.pem'), str(directory / 'server.key'))
    context.load_verify_locations(str(directory / 'ca.pem'))
    context.verify_mode = ssl.CERT_REQUIRED
    server = gateway_host.create_gateway(stub, parent_gate, tls_context=context,
        reader_certificate_sha256=state['certificate_hash']('reader'), docker_socket=Path('/var/run/docker.sock'))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        p = replace(stub, endpoint='https://localhost:' + str(server.server_port))
        store_policy = history.StorePolicy(metadata['targetRepositoryId'], 'p15-host', 'key-one', p)
        probe = replace(state['executor'].verifier.policy, runtime_policy_hash=p.identity_hash())
        epolicy = execution.ExecutionPolicy(p, gp.writer_certificate_sha256,
            verification_policy_hash=probe.identity_hash(), history_policy_hash=store_policy.identity_hash(),
            gateway_policy_hash=gp.identity_hash())
        config = dict(runtime=asdict(p), directory=str(directory), metadata=metadata, storeKey=store_key.hex(),
            gateKey=gate_key.hex(), writerPin=gp.writer_certificate_sha256, probe=asdict(probe),
            executionPolicyHash=epolicy.identity_hash(), candidate=str(state['candidate']))
        config_path = directory / 'private-fixture.json'
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(config, stream)
        crash_after = int(os.environ.get('P15_CRASH_AFTER', '3'))
        assert crash_after in (1, 3)
        child_process = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
            '--child', str(config_path), str(crash_after)], capture_output=True, timeout=180)
        (output / 'child.log').write_bytes(child_process.stdout + child_process.stderr)
        assert child_process.returncode == 77, 'Trusted crash injection did not reach the requested completed write'
        collector, coordinator, executor = embedding(config)
        pending = coordinator._ids()
        assert len(pending) == 1
        oid = pending[0]
        events = coordinator._load(oid)
        assert events[0]['data']['producerPID'] != os.getpid()
        from workflow_lock import process_alive
        assert process_alive(events[0]['data']['producerPID']) is False
        inspected = coordinator.inspect(state['candidate'], oid)
        provision.save(output / 'partial-state.json', inspected)
        request = coordinator.prepare_recovery(state['candidate'], oid,
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat())
        crashed_recovery = None
        if recovery_crash_after:
            assert crash_after == 3, 'Recovery crash matrix starts after deployment write 3'
            recovery_process = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                '--recovery-child', str(config_path), str(recovery_crash_after)],
                capture_output=True, timeout=180)
            (output / 'recovery-child.log').write_bytes(recovery_process.stdout + recovery_process.stderr)
            assert recovery_process.returncode == 78, 'Recovery child did not reach its completed gateway write'
            crashed_recovery = json.loads((output / 'recovery-child-request.json').read_text())
            assert process_alive(crashed_recovery['producerPID']) is False
            collector, coordinator, executor = embedding(config)
            assert coordinator._ids() == [oid]
            interrupted_events = coordinator._load(oid)
            assert interrupted_events[-1]['kind'] == 'attempt'
            current_inventory = execution.DockerExecutor._inventory(executor,
                time.monotonic() + executor.policy.execution_deadline)
            old_id = interrupted_events[0]['data']['binding']['beforeContainerId']
            for cid, before_hash in interrupted_events[0]['data']['baseline'].items():
                if cid != old_id:
                    assert runtime.digest(current_inventory[cid]) == before_hash, 'Unselected instance changed'
            inspected = coordinator.inspect(state['candidate'], oid)
            provision.save(output / 'recovery-partial-state.json', inspected)
            request = coordinator.prepare_recovery(state['candidate'], oid,
                expires_at=(datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat())
            assert request.request_id != crashed_recovery['requestId']
            assert request.digest() != crashed_recovery['requestHash']
        approval = actual_approval(config, request, output) if real else RecoveryTestApproval()
        original_inventory = execution.DockerExecutor._inventory
        prior_inventory = {}
        def diagnostic_inventory(executor_instance, deadline):
            nonlocal prior_inventory
            current = original_inventory(executor_instance, deadline)
            for cid in set(current).intersection(prior_inventory):
                previous, actual = prior_inventory[cid], current[cid]
                if (not previous.get('State', {}).get('Running')
                        and actual.get('State', {}).get('Running')):
                    # Keys only: never export raw configuration or private Env.
                    provision.save(output / 'start-transition-diagnostics.json', dict(
                        previousStatus=previous.get('State', {}).get('Status'),
                        oomBefore=previous.get('HostConfig', {}).get('OomKillDisable'),
                        oomAfter=actual.get('HostConfig', {}).get('OomKillDisable'),
                        managed=[dict(name=name, beforeEmpty=previous.get(key) in ('', None),
                            afterMatchesId=type(actual.get(key)) is str and actual[key].endswith('/' + cid + '/' + name),
                            unchanged=previous.get(key)==actual.get(key))
                            for name,key in runtime.MANAGED_FILES.items()],
                        changedFields=sorted(k for k in set(previous) | set(actual)
                            if previous.get(k) != actual.get(k)),
                        changedConfigFields=sorted(k for k in set(previous.get('Config', {})) | set(actual.get('Config', {}))
                            if previous.get('Config', {}).get(k) != actual.get('Config', {}).get(k)),
                        changedHostConfigFields=sorted(k for k in set(previous.get('HostConfig', {})) | set(actual.get('HostConfig', {}))
                            if previous.get('HostConfig', {}).get(k) != actual.get('HostConfig', {}).get(k))))
            prior_inventory = current
            return current
        execution.DockerExecutor._inventory = diagnostic_inventory
        try:
            result = coordinator.recover(request, approval)
        finally:
            execution.DockerExecutor._inventory = original_inventory
        observation = result.pop('observation')
        provision.save(output / 'recovery-result.json', result)
        assert result['status'] == 'recovered-runtime-verified', result
        assert result['health'] == result['smoke'] == 'passed', result
        collector.validate(observation)
        assert observation.snapshot()['components'] == before.snapshot()['components']
        after_api = next(item for item in observation.to_dict()['instances'] if item['component'] == 'api')
        assert after_api == before_api
        assert coordinator._load(oid)[-1]['kind'] == 'terminal'
        assert len(result['actions']) == len(json.loads(request.actions_json))
        if not recovery_crash_after:
            assert len(result['actions']) == (1 if crash_after == 1 else 3)
        try:
            coordinator.recover(request, approval)
        except Exception:
            pass
        else:
            raise AssertionError('Recovery request replay succeeded')
        if after_recovery is not None:
            after_recovery(coordinator, collector, executor, config, state)
        provision.save(output / 'summary.json', dict(result='passed', realDocker=True, realMTLS=True,
            actualChildCrash=True, crashAfterCompletedWrite=crash_after, staleCoreOwnerReclaimed=True,
            actualRecoveryChildCrash=bool(recovery_crash_after),
            recoveryCrashAfterCompletedWrite=recovery_crash_after,
            independentRecoveryRequest=crashed_recovery is not None,
            recoveryCrashAuthority='synthetic-test-double' if recovery_crash_after else None,
            originalDeployAuthority='synthetic-test-double',
            recoveryAuthority='github-oidc-exact-review-cas' if real else 'synthetic-test-double',
            realRecoveryGitHubOIDC=real, restoredBefore=True, preservedApiInstance=True,
            health='passed', smoke='passed', recoveryReplayDenied=True, productionReady=False))
    finally:
        server.shutdown()
        server.server_close()


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--child':
        return child(sys.argv[2], int(sys.argv[3]))
    if len(sys.argv) == 4 and sys.argv[1] == '--recovery-child':
        return recovery_child(sys.argv[2], int(sys.argv[3]))
    if sys.platform != 'linux' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Disposable Linux Actions fixture only')
    os.environ['P14_MODE'] = 'smoke'
    provision.main(exercise=exercise)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        output = ROOT / 'p15-results'
        output.mkdir(exist_ok=True)
        provision.save(output / 'failure.json', dict(result='failed', errorType=type(error).__name__,
            locations=[Path(item.filename).name + ':' + str(item.lineno) for item in traceback.extract_tb(error.__traceback__)]))
        raise SystemExit('P15 fixture failed: ' + type(error).__name__)
