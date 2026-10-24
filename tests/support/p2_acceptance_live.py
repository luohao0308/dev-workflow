#!/usr/bin/env python3
"""Isolated P2 exercise: real recovery, then separately reviewed deploy/rollback."""
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(1, str(ROOT / 'packs/deployment/scripts'))
sys.path.insert(2, str(Path(__file__).resolve().parent))
import p15_recovery_live as live
import deployment_acceptance as acceptance
import deployment_acceptance_host as acceptance_host
import deployment_host as host
from release_github import GitHubClient
from release_host import bundle_digest


def _profile(coordinator, executor, config, state):
    policy = executor.policy
    return acceptance.AcceptanceProfile.from_mapping(dict(
        schemaVersion=1, kind='deployment-acceptance-profile', profileName='p2-isolated',
        repositoryId=config['metadata']['targetRepositoryId'], environment=policy.runtime_policy.environment,
        target=policy.runtime_policy.target, component='web', runtimePolicyHash=policy.runtime_policy.identity_hash(),
        executionPolicyHash=policy.identity_hash(), verificationPolicyHash=executor.verifier.policy.identity_hash(),
        storePolicyHash=coordinator.store.policy.identity_hash(), gatePolicyHash=coordinator.gate.policy.identity_hash(),
        allowInterruption=True, requireHealth=True, requireSmoke=True,
        rollbackRef=config['metadata']['oldSha'], platform='linux', adapter='docker',
        state='stateless', readOnly=True, mounts=[]))


def _review(gh, request, policy, profile, output, name):
    digest = bundle_digest([request], policy.expires_at, policy.bundle_context())
    live.provision.save(output / (name + '-preview.json'), dict(bundleHash=digest,
        request=asdict(request), profileHash=profile.identity_hash(),
        approvalEnvironment=policy.approval_environment, productionReady=False))
    path = '/repos/' + policy.host_repository + '/actions/runs/' + str(policy.run_id)
    until = time.monotonic() + 2100
    while time.monotonic() < until:
        reviews, _ = gh.request('GET', path + '/approvals')
        if any(item.get('state') == 'approved' and item.get('comment') == 'dev-workflow approve ' + digest
               and any(env.get('name') == policy.approval_environment for env in item.get('environments', []))
               for item in reviews):
            break
        time.sleep(5)
    else:
        raise ValueError('Exact P2 approval timed out')
    for _ in range(15):
        run, _ = gh.request('GET', path)
        if run.get('status') == 'in_progress':
            return
        time.sleep(2)
    raise ValueError('P2 observer is not active')


def after_recovery(coordinator, collector, executor, config, state):
    output = ROOT / 'p15-results'
    profile = _profile(coordinator, executor, config, state)
    live.provision.save(output / 'p2-profile.json', profile.to_mapping())
    if os.environ.get('P15_REAL_AUTHORITY') != 'true':
        supplied = acceptance.assess_supplied(profile, dict(status='accepted', stages=['all-passed']))
        assert supplied['status'] == 'unknown'
        live.provision.save(output / 'p2-acceptance.json', supplied)
        return
    gh_token = os.environ['P1_GITHUB_TOKEN']
    gh = GitHubClient(gh_token)
    candidate = state['candidate']
    metadata = config['metadata']
    records = candidate / live.sdk.RECORDS
    records.mkdir(parents=True, exist_ok=True)
    live.provision.save(records / 'conditions.json', dict(schemaVersion=1,kind='deployment-conditions',
        environment='staging',target='p1-isolated',backup=dict(required=False,reference=None,restoreEvidence=None),
        migration=dict(mode='none',evidence=None)))
    baseline = collector.collect()
    history_ref = coordinator.store.capture_history(collector, baseline)
    before_deploy = collector.collect()
    old = next(item for item in baseline.snapshot()['components'] if item['name'] == 'web')
    catalog = live.runtime._catalog(collector.policy)
    entry = next(item for item in catalog.values() if item['component'] == 'web' and item['version'] == '2.0.0')
    spec = live.execution._specifications(collector.policy)[('web', entry['imageId'])]
    desired = dict(old, sourceSha=entry['sourceSha'], artifact=entry['artifact'],
                   configurationDigest=spec.configuration_digest())

    def stage(operation, before, target, history=None):
        expiration = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        live.provision.save(records / 'current.json', before.snapshot())
        live.provision.save(records / 'target.json', dict(schemaVersion=1,kind='deployment-target',
            environment='staging',target='p1-isolated',version='v2' if history is None else 'v1',
            components=[target]))
        plan = live.sdk.planner.prepare(candidate,'staging',live.sdk.RECORDS+'target.json',
            live.sdk.RECORDS+'current.json',live.sdk.RECORDS+'conditions.json')
        assert plan['result'] == 'prepared', plan['blockers']
        intent = executor.prepare(candidate, plan, operation, observation=before, rollback_target=history)
        request = live.sdk.build_request(candidate, plan, operation, collector=collector, observation=before,
            repository_slug=metadata['targetRepository'], repository_id=metadata['targetRepositoryId'],
            expires_at=expiration, rollback_target=history, execution_intent=intent)
        environment = 'p14-deploy-approval' if history is None else 'p14-rollback-approval'
        host_policy = host.DeploymentHostPolicy(host_repository=metadata['hostRepository'],
            host_repository_id=metadata['hostRepositoryId'], workflow_ref=os.environ['GITHUB_WORKFLOW_REF'],
            workflow_sha=os.environ['GITHUB_SHA'], run_id=int(os.environ['GITHUB_RUN_ID']),
            environment='p15-observer', reviewer_ids=tuple(metadata['reviewerIds']),
            target_repository=metadata['targetRepository'], target_repository_id=metadata['targetRepositoryId'],
            ledger_repository=metadata['hostRepository'],ledger_repository_id=metadata['hostRepositoryId'],
            ledger_sha=os.environ['GITHUB_SHA'],expires_at=expiration,prevent_self_review=False,
            deployment_environment='staging',deployment_target='p1-isolated',production=False,
            runtime_policy_hash=collector.policy.identity_hash(),allowed_components=('web','api'),
            approval_environment=environment,execution_policy_hash=executor.policy.identity_hash())
        _review(gh,request,host_policy,profile,output,'p2-'+('deploy' if history is None else 'rollback'))
        with coordinator.operation(candidate,plan,intent) as operation_guard:
            result, observed = acceptance_host.run_stage(profile,root=candidate,plan=plan,request=request,
                collector=collector,observation=before,executor=executor,intent=intent,rollback_target=history,
                host_policy=host_policy,github_token=gh_token,oidc_token=live.provision.oidc(),
                host_operation=operation_guard)
        return result, observed

    deploy_result, deploy_stage = stage('deployment-deploy',before_deploy,desired)
    after = deploy_result['observation']
    old_history = coordinator.store.load_history(history_ref, collector=collector, before=after)
    rollback_result, rollback_stage = stage('deployment-rollback',after,old,old_history)
    report = acceptance_host.assess_run(profile,deploy_stage,rollback_stage,
        recovery_stage=state['recovery_evidence'])
    live.provision.save(output / 'p2-acceptance.json', report)
    assert report['status'] == 'accepted', report['reason']
    assert rollback_result['observation'].snapshot()['components'] == baseline.snapshot()['components']


def exercise(state):
    def run_recovery(coordinator, collector, executor, config, current_state, request, approval):
        profile = _profile(coordinator, executor, config, current_state)
        return acceptance_host.run_recovery(profile, coordinator=coordinator, request=request, approval=approval)
    return live.exercise(state, after_recovery=after_recovery,
        recovery_runner=run_recovery if os.environ.get('P15_REAL_AUTHORITY') == 'true' else None)


def main():
    if sys.platform != 'linux' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Disposable Linux Actions fixture only')
    os.environ['P14_MODE'] = 'smoke'
    os.environ.setdefault('P15_CRASH_AFTER','3')
    os.environ.setdefault('P15_RECOVERY_CRASH_AFTER','0')
    live.provision.main(exercise=exercise)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        output = ROOT / 'p15-results'
        output.mkdir(exist_ok=True)
        live.provision.save(output / 'failure.json', dict(result='failed',
            errorType=type(error).__name__,
            locations=[Path(frame.filename).name + ':' + str(frame.lineno)
                       for frame in traceback.extract_tb(error.__traceback__)]))
        raise SystemExit('P2 isolated fixture failed: ' + type(error).__name__)
