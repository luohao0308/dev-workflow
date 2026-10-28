#!/usr/bin/env python3
"""Public v3 review entrance; private prepared bodies stay exclusively on host.

Workflow validation proves public shape and workflow scope only. The host MUST
call verify_prepared_review against its private prepared intent before consuming
approval; a caller's self-declared bundle/review hash or historical source SHA
is not host authentication. Rollback/recovery history must also be authenticated
by the trusted host fence before admission.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import urllib.request

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from deployment_compose_approval_v3_host import AUDIENCE, PROFILE, FullBodyApprovalPolicyV3
from deployment_contract_v2 import RequestV2
from release_host import bundle_digest
from deployment_compose_bundle_v3 import ExecutionBundleV3

REPOSITORY='luohao0308/dev-workflow'
REPOSITORY_ID=1327491026
REF='refs/heads/feat/compose-validation-20261028'
WORKFLOW='.github/workflows/compose-full-body-review.yml'
MAX_PAYLOAD=32768
FIELDS={'schema','issuedAt','request','policy','review','requestHash','policyHash','reviewHash','bundleHash'}
REVIEW_FIELDS={'bundleDigest','profile','profileVersion','identity','expiresAt','services',
               'protectedContainers','operations','blockers'}
HASH=re.compile(r'[0-9a-f]{64}\Z')
NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('ascii')).hexdigest()


def stamp(now):
    return now.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_stamp(value):
    return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def _closed(value, fields):
    if type(value) is not dict or set(value)!=fields:raise ValueError('Invalid closed public shape')


def _hex(value):
    if type(value) is not str or not HASH.fullmatch(value):raise ValueError('Invalid public digest')


def _name(value):
    if type(value) is not str or not NAME.fullmatch(value):raise ValueError('Invalid public name')


def _parse(raw,limit):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('Duplicate public key')
            value[key]=item
        return value
    if type(raw) is not str or not raw.isascii() or len(raw)>limit:raise ValueError('Oversized public payload')
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if canonical(value)!=raw:raise ValueError('Noncanonical public payload')
    return value


def identities(env):
    workflow_ref=REPOSITORY+'/'+WORKFLOW+'@'+REF
    if (env.get('GITHUB_REPOSITORY')!=REPOSITORY or env.get('GITHUB_REPOSITORY_ID')!=str(REPOSITORY_ID)
            or env.get('GITHUB_REF')!=REF or env.get('GITHUB_RUN_ATTEMPT')!='1'
            or env.get('GITHUB_EVENT_NAME')!='workflow_dispatch'
            or env.get('GITHUB_WORKFLOW_REF')!=workflow_ref
            or env.get('GITHUB_WORKFLOW_SHA')!=env.get('GITHUB_SHA')
            or not re.fullmatch(r'[0-9a-f]{40}',env.get('GITHUB_SHA',''))):
        raise ValueError('Unsupported full-body workflow identity')
    return dict(host_repository=REPOSITORY,host_repository_id=REPOSITORY_ID,workflow_ref=workflow_ref,
        workflow_sha=env['GITHUB_SHA'],run_id=int(env['GITHUB_RUN_ID']),environment='compose-review',
        reviewer_ids=(int(env['DW_AUTH_REVIEWER_ID']),),target_repository=REPOSITORY,
        target_repository_id=REPOSITORY_ID,ledger_repository=env['DW_AUTH_LEDGER_REPOSITORY'],
        ledger_repository_id=int(env['DW_AUTH_LEDGER_ID']),ledger_sha=env['DW_AUTH_LEDGER_SHA'])


def _validate_review(review,request):
    _closed(review,REVIEW_FIELDS)
    if (review['bundleDigest']!=request.plan_hash or review['profile']!=PROFILE or review['profileVersion']!='3'
            or type(review['expiresAt']) is not int or not 0<review['expiresAt']<2**53
            or review['identity']!=dict(hostId=request.host_id,daemonId=request.daemon_id,
                project=request.target.namespace,sourceIdentity=canonical(asdict(request.source)))
            or review['blockers']!=['trusted-host-authentication-required','coordinator-admission-and-recovery-required']):
        raise ValueError('Public review differs from request')
    services=review['services'];protected=review['protectedContainers']
    if type(services) is not list or not 1<=len(services)<=16 or type(protected) is not list:
        raise ValueError('Invalid public container scope')
    names=[];ids=[];finals=[];dependencies={}
    for service in services:
        _closed(service,{'name','finalName','baselineContainerId','baselineImageId','targetImageId',
                         'dependsOn','baselineBodyDigest','targetBodyDigest'})
        for field in ('name','finalName'):_name(service[field])
        for field in ('baselineContainerId','baselineBodyDigest','targetBodyDigest'):_hex(service[field])
        for field in ('baselineImageId','targetImageId'):
            if type(service[field]) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',service[field]):
                raise ValueError('Invalid image identity')
        deps=service['dependsOn']
        if type(deps) is not list or any(type(v) is not str for v in deps) or deps!=sorted(set(deps)):
            raise ValueError('Invalid dependency shape')
        names.append(service['name']);ids.append(service['baselineContainerId']);finals.append(service['finalName'])
        dependencies[service['name']]=deps
    if (tuple(sorted(names))!=request.components or len(set(names))!=len(names)
            or len(set(ids))!=len(ids) or len(set(finals))!=len(finals)
            or names!=sorted(names) or len(protected)>32
            or len(protected)!=len(request.protected_components)):
        raise ValueError('Public service scope differs from request')
    for pin in protected:
        _closed(pin,{'containerId','staticConfigDigest'})
        _hex(pin['containerId']);_hex(pin['staticConfigDigest'])
        ids.append(pin['containerId'])
    if len(set(ids))!=len(ids):raise ValueError('Overlapping protected container identity')
    if [p['containerId'] for p in protected]!=sorted(p['containerId'] for p in protected):
        raise ValueError('Unordered protected scope')
    order=[]
    while len(order)<len(names):
        ready=sorted(n for n in names if n not in order and set(dependencies[n]).issubset(order))
        if not ready:raise ValueError('Invalid public dependency graph')
        order.extend(ready)
    operations=([dict(phase='create',service=n) for n in order]+
        [dict(phase=phase,service=n) for phase in ('stop','delete') for n in reversed(order)]+
        [dict(phase='rename',service=n) for n in order]+
        [dict(phase=phase,service=n) for n in order for phase in ('start','readiness')])
    if canonical(review['operations'])!=canonical(operations):raise ValueError('Invalid public operation order')


def _values(payload,env,now):
    identity=identities(env)
    _closed(payload,{'request','review'})
    request=RequestV2.from_json(canonical(payload['request']))
    if (request.profile_id!=PROFILE or request.profile_version!='3' or request.production is not False
            or request.target.runtime!='compose' or not re.fullmatch(r'dw-[A-Za-z0-9][A-Za-z0-9._-]{0,124}',request.target.namespace)
            or request.environment!='staging' or request.max_uses!=1
            or request.source.provider_id!='github.com' or request.source.project_path!=REPOSITORY
            or request.source.origin!='https://github.com/'+REPOSITORY+'.git'
            or request.source.project_id!=REPOSITORY_ID
            or (request.operation=='deploy' and request.source.source_sha!=env['GITHUB_SHA'])):
        raise ValueError('Unsupported public request scope')
    request.ensure_fresh(now,maximum_seconds=1800)
    _validate_review(payload['review'],request)
    policy=FullBodyApprovalPolicyV3(**identity,expires_at=request.expires_at,approval_environment='compose-review',
        operation=request.operation,profile_version='3',source_sha=request.source.source_sha,target=request.target,
        deployment_environment='staging',production=False,daemon_id=request.daemon_id,host_id=request.host_id,
        components=request.components,protected_components=request.protected_components,policy_hash=request.policy_hash,
        bundle_hash=request.plan_hash,expected_history_hash=request.history_hash)
    return request,policy


def prepare(raw,env,now=None):
    now=parse_stamp(stamp(now or datetime.now(timezone.utc)))
    payload=_parse(raw,MAX_PAYLOAD);request,policy=_values(payload,env,now)
    return dict(schema=1,issuedAt=stamp(now),request=asdict(request),policy=asdict(policy),review=payload['review'],
        requestHash=request.digest(),policyHash=digest(asdict(policy)),reviewHash=digest(payload['review']),
        bundleHash=bundle_digest([request],policy.expires_at,policy.bundle_context()))


def verify(raw,env,now=None):
    value=_parse(raw,65536);_closed(value,FIELDS)
    if type(value['schema']) is not int or value['schema']!=1:raise ValueError('Invalid public artifact schema')
    now=now or datetime.now(timezone.utc);issued=parse_stamp(value['issuedAt'])
    if not issued<=now<issued+timedelta(minutes=30):
        raise ValueError('Public artifact expired or issued in future')
    payload=canonical(dict(request=value['request'],review=value['review']))
    expected=prepare(payload,env,issued)
    if canonical(expected)!=raw:raise ValueError('Public artifact differs from workflow scope')
    request,policy=_values(_parse(payload,MAX_PAYLOAD),env,now)
    return request,policy,value['bundleHash']


def verify_prepared_review(raw,env,expected_bundle,expected_request,now=None):
    """Required host boundary before approval consumption; self hashes prove nothing."""
    request,policy,approval_hash=verify(raw,env,now)
    if (type(expected_bundle) is not ExecutionBundleV3 or type(expected_request) is not RequestV2
            or expected_request.plan_hash!=expected_bundle.digest
            or request!=expected_request
            or canonical(_parse(raw,65536)['review'])!=canonical(expected_bundle.public_review())):
        raise ValueError('Public review differs from trusted private preparation')
    return request,policy,approval_hash


def summary(raw,env):
    request,_,approval_hash=verify(raw,env)
    review=_parse(raw,65536)['review']
    images='\n'.join('- '+s['name']+' ('+s['finalName']+', original '+s['baselineContainerId']+'): '
        +s['baselineImageId']+' -> '+s['targetImageId'] for s in review['services'])
    counts={phase:sum(op['phase']==phase for op in review['operations'])
            for phase in ('create','stop','delete','rename','start','readiness')}
    order=', '.join(op['phase']+':'+op['service'] for op in review['operations'])
    return ('Full-body v3 public review. Workflow checks public shape only; host must verify against its private prepared intent.\n\n'
        +'Physical scope: host '+request.host_id+'; daemon '+request.daemon_id+'; project '+request.target.namespace+'; staging; production=false.\n\n'
        +'Services: '+', '.join(request.components)+'; protected services: '+(', '.join(request.protected_components) or '(none)')+'.\n\n'
        +'Protected container IDs: '+(', '.join(p['containerId'] for p in review['protectedContainers']) or '(none)')+'.\n\n'
        +'Immutable image changes (original -> target):\n\n'+images+'\n\n'
        +'Phase counts: '+', '.join(phase+'='+str(count) for phase,count in counts.items())+'.\n\n'
        +'Phase order: '+order+'.\n\n'
        +'Application source SHA: '+request.source.source_sha+'; review workflow SHA: '+env['GITHUB_SHA']+'; operation: '+request.operation+'; request expiry: '+request.expires_at+'; maximum uses: 1.\n\n'
        +'Approving grants intent consent for the trusted host to perform this listed staging operation. Fresh runtime guards, phase checks, and host admission remain required.\n\n'
        +'Exact new human approval comment: `dev-workflow approve '+approval_hash+'`\n\n'
        +'This workflow itself does not execute Docker or SSH. Private prepared bodies remain on the trusted host.\n')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('OIDC endpoint redirected')


def fetch_token(env):
    url = env['ACTIONS_ID_TOKEN_REQUEST_URL']
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ''
    if (parsed.scheme != 'https' or not host.endswith('.actions.githubusercontent.com')
            or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.fragment):
        raise ValueError('Unsupported OIDC endpoint')
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if any(key == 'audience' for key, _ in query):
        raise ValueError('Unexpected OIDC audience parameter')
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query + [('audience', AUDIENCE)])))
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + env['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('Oversized response')
        token = json.loads(raw)['value']
        if not isinstance(token, str) or len(token) > 32768 or token.count('.') != 2 or not token.isascii():
            raise ValueError('Invalid token')
        return token.encode('ascii')
    except Exception:
        raise ValueError('OIDC request failed') from None


def seal(raw, env, recipient, output):
    verify(raw, env)
    token = fetch_token(env)
    # Plaintext exists only in memory and the subprocess pipe, never a file or log.
    result = subprocess.run(['/usr/bin/openssl', 'cms', '-encrypt', '-binary', '-aes256',
                             '-outform', 'DER', str(recipient)], input=token, capture_output=True,
                            timeout=15, env={'PATH': '/usr/bin:/bin'})
    if result.returncode or not result.stdout:
        raise ValueError('OIDC encryption failed')
    Path(output).write_bytes(result.stdout)
    os.chmod(output, 0o600)



def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('prepare','verify','summary','seal'))
    parser.add_argument('--bundle',required=True,type=Path)
    parser.add_argument('--recipient',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        if args.command=='prepare':
            value=prepare(os.environ['PUBLIC_PAYLOAD'],os.environ)
            args.bundle.write_text(canonical(value),encoding='ascii');print(value['bundleHash'])
        elif args.command=='verify':
            print(verify(args.bundle.read_text(encoding='ascii'),os.environ)[2])
        elif args.command=='summary':
            print(summary(args.bundle.read_text(encoding='ascii'),os.environ),end='')
        else:
            if not args.recipient or not args.output:raise ValueError()
            seal(args.bundle.read_text(encoding='ascii'),os.environ,args.recipient,args.output)
            print('Encrypted full-body authorization evidence saved')
    except Exception:
        print('Full-body review contract failed closed',file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
