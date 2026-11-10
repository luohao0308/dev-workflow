"""Closed production frontend intent review; no Docker writes or runtime permit."""
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import argparse
import os
from pathlib import Path
import re
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
import deployment_compose_full_body_review_contract as common
import deployment_compose_production_frontend_approval_v1_host as host
from release_host import bundle_digest
canonical=common.canonical


def identities(env):
    if (env.get('GITHUB_REPOSITORY')!=host.RUNTIME or env.get('GITHUB_REPOSITORY_ID')!='1327491026'
            or env.get('GITHUB_REF')!='refs/heads/main' or env.get('GITHUB_EVENT_NAME')!='workflow_dispatch'
            or env.get('GITHUB_RUN_ATTEMPT')!='1' or env.get('GITHUB_WORKFLOW_REF')!=host.WORKFLOW
            or env.get('GITHUB_WORKFLOW_SHA')!=env.get('GITHUB_SHA')
            or not re.fullmatch('[0-9a-f]{40}',env.get('GITHUB_SHA',''))
            or env.get('DW_AUTH_LEDGER_REPOSITORY')!=host.LEDGER or env.get('DW_AUTH_LEDGER_ID')!='1436718662'
            or not re.fullmatch('[0-9a-f]{64}',env.get('DW_PROD_FRONTEND_POLICY_HASH',''))):
        raise ValueError('Unsupported production workflow identity')
    return dict(host_repository=host.RUNTIME,host_repository_id=1327491026,workflow_ref=host.WORKFLOW,
        workflow_sha=env['GITHUB_SHA'],run_id=int(env['GITHUB_RUN_ID']),environment='compose-review',
        reviewer_ids=(int(env['DW_AUTH_REVIEWER_ID']),),target_repository=host.BLOG,target_repository_id=1395689651,
        ledger_repository=host.LEDGER,ledger_repository_id=1436718662,ledger_sha=env['DW_AUTH_LEDGER_SHA'])


def _values(payload,env,now):
    identity=identities(env);common._closed(payload,{'request','review'})
    request=host.RequestV2.from_json(canonical(payload['request']))
    expected=host.prepare_production_frontend_request(payload['review'],policy_hash=env['DW_PROD_FRONTEND_POLICY_HASH'],expires_at=request.expires_at,operation=request.operation)
    if request!=expected:raise ValueError('Production request differs from review')
    request.ensure_fresh(now,maximum_seconds=1800)
    policy=host.ProductionFrontendApprovalPolicyV1(**identity,expires_at=request.expires_at,
        source_sha=request.source.source_sha,host_id=request.host_id,daemon_id=request.daemon_id,
        current_image_id='sha256:'+request.artifact_digest,snapshot_hash=request.observation_hash,
        body_hash=request.after_hash,plan_hash=request.plan_hash,
        protected_inventory_hash=host._digest(list(request.protected_components)),request_hash=request.digest(),policy_hash=request.policy_hash)
    return request,policy


def prepare(raw,env,now=None):
    now=common.parse_stamp(common.stamp(now or datetime.now(timezone.utc)))
    payload=common._parse(raw,32768);request,policy=_values(payload,env,now)
    return dict(schema=1,issuedAt=common.stamp(now),request=asdict(request),policy=asdict(policy),review=payload['review'],
        requestHash=request.digest(),policyHash=common.digest(asdict(policy)),reviewHash=common.digest(payload['review']),
        bundleHash=bundle_digest([request],policy.expires_at,policy.bundle_context()))


def verify(raw,env,now=None):
    value=common._parse(raw,65536);common._closed(value,common.FIELDS)
    if type(value['schema']) is not int or value['schema']!=1:raise ValueError('Invalid schema')
    now=now or datetime.now(timezone.utc);issued=common.parse_stamp(value['issuedAt'])
    if not issued<=now<issued+timedelta(minutes=30):raise ValueError('Expired artifact')
    payload=canonical(dict(request=value['request'],review=value['review']))
    if canonical(prepare(payload,env,issued))!=raw:raise ValueError('Artifact scope drift')
    request,policy=_values(common._parse(payload,32768),env,now)
    return request,policy,value['bundleHash']


def verify_prepared_review(raw,env,expected_request,expected_review,now=None):
    request,policy,digest=verify(raw,env,now)
    if (type(expected_request) is not host.RequestV2 or request!=expected_request
            or canonical(common._parse(raw,65536)['review'])!=canonical(expected_review)):
        raise ValueError('Private prepared scope differs')
    return request,policy,digest


def summary(raw,env):
    request,_,digest=verify(raw,env);review=common._parse(raw,65536)['review']
    return ('PRODUCTION frontend intent consent; production=true; deploy only.\n\n'
        +'Repository: `'+host.BLOG+'`; business SHA: `'+request.source.source_sha+'`; runtime SHA: `'+env['GITHUB_SHA']+'`.\n\n'
        +'Host: `'+request.host_id+'`; daemon: `'+request.daemon_id+'`; project: `luohao-blog-prod`; container: `blog-frontend` (`'+review['identity']['containerId']+'`).\n\n'
        +'Same immutable image: `'+review['identity']['imageId']+'`; protected IDs (inventory only): `'+', '.join(request.protected_components)+'`.\n\n'
        +'Snapshot: `'+request.observation_hash+'`; body: `'+request.after_hash+'`; plan: `'+request.plan_hash+'`.\n\n'
        +'Expiry: `'+request.expires_at+'`; maximum uses: 1.\n\n'
        +'Limits: '+', '.join(review['executionBlockedReasons'])+'. No runtime permit, native enrollment, freshness, Engine reconstruction or production readiness is established. Rollback/recovery denied. Host must verify private prepared scope before consumption.\n\n'
        +'Exact approval comment: `dev-workflow approve '+digest+'`\n\nThis workflow performs no Docker, SSH, ledger consumption or deployment.\n')


def seal(raw,env,recipient,output):
    output=Path(output)
    # Never replace or remove a caller's prior artifact, including symlinks.
    if os.path.lexists(output):raise FileExistsError('Evidence output exists')
    verify(raw,env);token=common.fetch_token(env,audience=host.AUDIENCE);verify(raw,env)
    fd,name=tempfile.mkstemp(prefix='.production-evidence-',dir=output.parent)
    os.close(fd)
    temporary=Path(name)
    try:
        common.encrypt_token(token,recipient,temporary)
        verify(raw,env)
        # Hard-link publication is atomic and refuses an existing destination.
        os.link(temporary,output,follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('prepare','verify','summary','seal'))
    parser.add_argument('--bundle',required=True,type=Path);parser.add_argument('--recipient',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        if args.command=='prepare':
            value=prepare(os.environ['PUBLIC_PAYLOAD'],os.environ);args.bundle.write_text(canonical(value),encoding='ascii');print(value['bundleHash'])
        elif args.command=='verify':print(verify(args.bundle.read_text(encoding='ascii'),os.environ)[2])
        elif args.command=='summary':print(summary(args.bundle.read_text(encoding='ascii'),os.environ),end='')
        else:
            if not args.recipient or not args.output:raise ValueError()
            seal(args.bundle.read_text(encoding='ascii'),os.environ,args.recipient,args.output)
            print('Encrypted production intent evidence saved')
    except Exception:
        print('Production review contract failed closed',file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
