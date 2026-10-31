"""GitLab.com native user-review intent authority; no provider mutation.

Pinned 19.5.1 shape, non-MR protected branch, running deployment, explicit users
only. Different manual job executors and pipeline creators are unsupported.
Premium/Ultimate account behavior needs separate real-project acceptance.
Ledger path pins registration scope; it does not resist rollback of its host.
"""
import base64
from copy import deepcopy
from dataclasses import dataclass,asdict
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.request
from urllib.parse import quote

from release_gitlab_prepare_v2_host import GitLabRequestPreparationV2,PROFILE
from release_gitlab_ledger_v2_host import GitLabReleaseLedgerV2
from release_contract_v2 import ProviderIdentity,RequestV2
from release_host import _decode,_json,_der,_integer,_NoRedirect

ISSUER='https://gitlab.com'
JWKS='https://gitlab.com/oauth/discovery/keys'
AUDIENCE='dev-workflow-gitlab-native-release-v2-host'
DOMAIN=b'dev-workflow:gitlab-native-approval:v2\0'


def reject():raise ValueError('gitlab-native-approval-v2-rejected')
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
def digest(value):return hashlib.sha256(DOMAIN+encoded(value)).hexdigest()
def positive(value):return type(value) is int and value>0


def verify_oidc(token):
    """RS256 with fixed GitLab issuer/JWKS; no candidate key discovery."""
    try:
        if type(token) is not str or len(token)>32768 or token.count('.')!=2:reject()
        h,c,s=token.split('.');header=_json(_decode(h));claims=_json(_decode(c))
        if (header.get('alg')!='RS256' or type(header.get('kid')) is not str
                or any(k in header for k in ('jku','jwk','x5u','crit')) or claims.get('iss')!=ISSUER):reject()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),_NoRedirect())
        with opener.open(JWKS,timeout=15) as response:raw=response.read(262145)
        if len(raw)>262144:reject()
        keys=_json(raw).get('keys')
        if type(keys) is not list:reject()
        matched=[k for k in keys if type(k) is dict and k.get('kid')==header['kid']]
        if len(matched)!=1:reject()
        key=matched[0]
        if key.get('kty')!='RSA' or key.get('alg','RS256')!='RS256' or key.get('use','sig')!='sig':reject()
        if not 256<=len(_decode(key['n']))<=1024 or not 1<=len(_decode(key['e']))<=8:reject()
        rsa=_der(48,_integer(key['n'])+_integer(key['e']))
        spki=_der(48,bytes.fromhex('300d06092a864886f70d0101010500')+_der(3,b'\0'+rsa))
        with tempfile.TemporaryDirectory(prefix='gitlab-oidc-v2-') as directory:
            root=Path(directory);public=root/'key.pem';signature=root/'sig'
            public.write_bytes(b'-----BEGIN PUBLIC KEY-----\n'+base64.encodebytes(spki)+b'-----END PUBLIC KEY-----\n')
            signature.write_bytes(_decode(s))
            result=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-verify',str(public),'-signature',str(signature)],
                input=(h+'.'+c).encode('ascii'),capture_output=True,timeout=15,env={'PATH':'/usr/bin:/bin'})
            if result.returncode:reject()
        return claims
    except Exception:reject()


@dataclass(frozen=True)
class UserRuleV2:
    id:int
    user_id:int
    required_approvals:int=1
    group_id:None=None
    access_level:None=None
    group_inheritance_type:int=0
    def __post_init__(self):
        if (not positive(self.id) or not positive(self.user_id) or type(self.required_approvals) is not int
                or self.required_approvals!=1 or self.group_id is not None or self.access_level is not None
                or type(self.group_inheritance_type) is not int or self.group_inheritance_type!=0):reject()


@dataclass(frozen=True)
class NativeApprovalPolicyV2:
    identity:ProviderIdentity
    host_id:str
    tag:str
    ref:str
    environment:str
    environment_id:int
    job_id:int
    pipeline_id:int
    deployment_id:int
    trigger_user_id:int
    rules:tuple
    ledger_root:str
    expires_at:str
    profile:str=PROFILE
    def __post_init__(self):
        if (type(self.identity) is not ProviderIdentity or self.identity.provider_id!='gitlab.com'
                or self.profile!=PROFILE or any(type(v) is not str or not v or len(v)>255 for v in
                    (self.host_id,self.tag,self.ref,self.environment))
                or any(not positive(v) for v in (self.environment_id,self.job_id,self.pipeline_id,self.deployment_id,self.trigger_user_id))
                or type(self.rules) is not tuple or not self.rules or len(self.rules)>32
                or any(type(r) is not UserRuleV2 or r.user_id==self.trigger_user_id for r in self.rules)
                or len({r.id for r in self.rules})!=len(self.rules)
                or len({r.user_id for r in self.rules})!=len(self.rules)
                or type(self.ledger_root) is not str or not Path(self.ledger_root).is_absolute()):reject()
        datetime.strptime(self.expires_at,'%Y-%m-%dT%H:%M:%SZ')
    def digest(self):return digest(asdict(self))


class NativeGrantV2:pass
class NativeReceiptV2:pass


class GitLabNativeApprovalV2:
    def __init__(self, *, token, policy, preparer, intent, request, ledger, verifier=None):
        if (type(policy) is not NativeApprovalPolicyV2 or type(preparer) is not GitLabRequestPreparationV2
                or type(request) is not RequestV2 or type(ledger) is not GitLabReleaseLedgerV2
                or ledger._host_id!=policy.host_id or ledger._policy_hash!=policy.digest()
                or str(ledger.root)!=policy.ledger_root or preparer._policy_hash!=policy.digest()
                or preparer._host_id!=policy.host_id or preparer._identity!=policy.identity
                or Path(policy.ledger_root).resolve().is_relative_to(preparer._preflight.repository.resolve())):reject()
        self.policy=policy;self._policy_digest=policy.digest();self._preparer=preparer
        self._request=RequestV2.from_json(request.canonical_json());self._intent=json.loads(encoded(intent))
        self._ledger=ledger;self._token=token;self._verifier=verify_oidc if verifier is None else verifier
        self._owner=self;self._grants={};self._receipts={};self._spent=set();self._lock=threading.RLock()
        self.bundle_hash=digest({'requestHash':request.digest(),'policy':asdict(policy),'ledgerRegistration':policy.ledger_root})
        self._check()

    def _identity(self,request):
        if (self._owner is not self or type(self.policy) is not NativeApprovalPolicyV2
                or self.policy.digest()!=self._policy_digest
                or self._ledger._policy_hash!=self._policy_digest or self._ledger._host_id!=self.policy.host_id
                or str(self._ledger.root)!=self.policy.ledger_root
                or self._preparer._policy_hash!=self._policy_digest or self._preparer._host_id!=self.policy.host_id
                or type(request) is not RequestV2
                or request.canonical_json()!=self._request.canonical_json()):reject()

    def _claims(self):
        p=self.policy;c=json.loads(encoded(self._verifier(self._token)));now=time.time()
        if type(c) is not dict:reject()
        exact={'iss':ISSUER,'aud':AUDIENCE,'sha':p.identity.source_sha,'ref':p.ref,'ref_path':'refs/heads/'+p.ref,
            'ref_type':'branch','pipeline_source':'push','environment':p.environment,'environment_action':'start',
            'ref_protected':'true','environment_protected':'true'}
        exact.update({k:str(v) for k,v in dict(project_id=p.identity.project_id,job_project_id=p.identity.project_id,
            source_project_id=p.identity.project_id,job_id=p.job_id,pipeline_id=p.pipeline_id,user_id=p.trigger_user_id).items()})
        if any(type(c.get(k)) is not str or c[k]!=v for k,v in exact.items()):reject()
        if (any(type(c.get(k)) is not int for k in ('iat','nbf','exp'))
                or not now-600<=c['iat']<=now or c['nbf']>now or not now<c['exp']<=c['iat']+600):reject()
        return c

    def _native(self):
        p=self.policy;base='/projects/'+str(p.identity.project_id);client=self._preparer._preflight.client
        def get(path):
            value=client.request('GET',path)
            return json.loads(encoded(value))  # Private snapshot for both native comparison rounds.
        deployment=get(base+'/deployments/'+str(p.deployment_id))
        protected=get(base+'/protected_environments/'+quote(p.environment,safe=''))
        pipeline_detail=get(base+'/pipelines/'+str(p.pipeline_id))
        if (type(pipeline_detail) is not dict or type(pipeline_detail.get('id')) is not int
                or pipeline_detail['id']!=p.pipeline_id or type(pipeline_detail.get('project_id')) is not int
                or pipeline_detail['project_id']!=p.identity.project_id
                or pipeline_detail.get('sha')!=p.identity.source_sha or pipeline_detail.get('ref')!=p.ref
                or pipeline_detail.get('source')!='push' or pipeline_detail.get('status')!='running'
                or pipeline_detail.get('tag') is not False):reject()
        creator=pipeline_detail.get('user')
        if (type(creator) is not dict or type(creator.get('id')) is not int
                or creator['id']!=p.trigger_user_id or creator.get('state')!='active'):reject()
        if type(deployment) is not dict or type(protected) is not dict:reject()
        env=deployment.get('environment');job=deployment.get('deployable')
        if (type(deployment.get('id')) is not int or deployment['id']!=p.deployment_id
                or deployment.get('status')!='running' or deployment.get('sha')!=p.identity.source_sha or deployment.get('ref')!=p.ref
                or type(env) is not dict or type(env.get('id')) is not int or env['id']!=p.environment_id or env.get('name')!=p.environment
                or type(job) is not dict or type(job.get('id')) is not int or job['id']!=p.job_id):reject()
        pipeline=job.get('pipeline')
        if (type(pipeline) is not dict or type(pipeline.get('id')) is not int or pipeline['id']!=p.pipeline_id
                or pipeline.get('sha')!=p.identity.source_sha or pipeline.get('ref')!=p.ref):reject()
        for item in (deployment,job,pipeline):
            if item is pipeline and 'user' not in item:continue
            user=item.get('user')
            if type(user) is not dict or type(user.get('id')) is not int or user['id']!=p.trigger_user_id:reject()
        if protected.get('name')!=p.environment:reject()
        expected=[asdict(r) for r in p.rules]
        actual=protected.get('approval_rules')
        summary=deployment.get('approval_summary')
        if type(actual) is not list or type(summary) is not dict or type(summary.get('rules')) is not list:reject()
        def project(rule):
            if type(rule) is not dict or not set(expected[0])<=set(rule):reject()
            return {k:rule[k] for k in expected[0]}
        if encoded(sorted([project(r) for r in actual],key=lambda r:r['id']))!=encoded(sorted(expected,key=lambda r:r['id'])):reject()
        rules=summary['rules']
        if encoded(sorted([project(r) for r in rules],key=lambda r:r['id']))!=encoded(sorted(expected,key=lambda r:r['id'])):reject()
        seen=set()
        for rule in rules:
            votes=rule.get('deployment_approvals')
            if type(votes) is not list:reject()
            accepted=set()
            for vote in votes:
                if type(vote) is not dict or type(vote.get('user')) is not dict:reject()
                user=vote['user'];uid=user.get('id')
                if (type(uid) is not int or uid!=rule['user_id'] or uid in seen
                        or vote.get('status')!='approved' or user.get('state')!='active'
                        or vote.get('comment')!='dev-workflow approve '+self.bundle_hash
                        or type(vote.get('created_at')) is not str):reject()
                created=datetime.fromisoformat(vote['created_at'].replace('Z','+00:00'))
                if created.tzinfo is None or created>datetime.now(timezone.utc):reject()
                seen.add(uid);accepted.add(uid)
            if len(accepted)<rule['required_approvals']:reject()
        return {'deployment':deployment,'protected':protected,'pipeline':pipeline_detail}

    def _check(self):
        self._identity(self._request);p=self.policy
        claims=self._claims()
        now=datetime.now(timezone.utc)
        if not 0<(datetime.strptime(p.expires_at,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)-now).total_seconds()<=3600:reject()
        rebuilt=self._preparer.prepare(self._intent,expires_at=self._request.expires_at)['request']
        if (rebuilt.canonical_json()!=self._request.canonical_json() or rebuilt.identity!=p.identity
                or rebuilt.tag!=p.tag or rebuilt.operation!='remote-tag-push' or rebuilt.profile_id!=PROFILE):reject()
        first=self._native();second=self._native()
        if encoded(first)!=encoded(second):reject()
        if self._preparer.prepare(self._intent,expires_at=self._request.expires_at)['request'].canonical_json()!=rebuilt.canonical_json():reject()
        final_claims=self._claims()
        # No blocking operations follow these final local deadline checks.
        self._identity(self._request)
        current=time.time()
        self._request.ensure_fresh(datetime.fromtimestamp(current,timezone.utc))
        deadline=min(claims['exp'],final_claims['exp'],
            datetime.strptime(p.expires_at,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp(),
            datetime.strptime(self._request.expires_at,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp())
        self._live_deadline=deadline
        self._live_not_before=max(claims['iat'],claims['nbf'],final_claims['iat'],final_claims['nbf'])
        self.check_local_deadline(self._request)
        return True

    def validate(self,request):
        with self._lock:
            self._identity(request);self._check();grant=NativeGrantV2()
            self._grants[id(grant)]=(grant,secrets.token_hex(32));return grant

    def consume(self,grant,request):
        with self._lock:
            self._identity(request)
            record=self._grants.get(id(grant))
            if type(grant) is not NativeGrantV2 or record is None or record[0] is not grant or id(grant) in self._spent:reject()
            self._check();self._spent.add(id(grant))
            value=self._ledger.burn(request_hash=request.digest(),bundle_hash=self.bundle_hash,grant_nonce=record[1])
            receipt=NativeReceiptV2();self._receipts[id(receipt)]=(receipt,record[1],value);return receipt

    def guard(self,request):
        with self._lock:
            self._identity(request);self._check()
            matches=[r for r in self._receipts.values() if r[0] is not None]
            if len(matches)!=1:reject()
            r=matches[0]
            self._ledger.check(request_hash=request.digest(),bundle_hash=self.bundle_hash,grant_nonce=r[1],receipt_hash=r[2])
            return self.check_local_deadline(request)

    def receipt_hash(self,receipt,request):
        with self._lock:
            self._identity(request)
            record=self._receipts.get(id(receipt))
            if type(receipt) is not NativeReceiptV2 or record is None or record[0] is not receipt:reject()
            self._ledger.check(request_hash=request.digest(),bundle_hash=self.bundle_hash,grant_nonce=record[1],receipt_hash=record[2])
            return record[2]

    def check_local_deadline(self,request):
        """Local-only final check after blocking authority and ledger reads."""
        self._identity(request)
        current=time.time()
        request.ensure_fresh(datetime.fromtimestamp(current,timezone.utc))
        if not self._live_not_before<=current<self._live_deadline:reject()
        return True
