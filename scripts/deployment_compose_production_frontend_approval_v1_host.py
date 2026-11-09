"""Production frontend consent only; no native enrollment or runtime permit.

Rollback remains denied until an issued completed deployment-history contract
exists. Caller JSON history cannot supply that missing authority.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
import time
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/p) for p in ('packs/deployment/scripts','packs/release/scripts')]
from deployment_contract_v2 import RequestV2,SourceIdentity,TargetIdentity
from release_host import HostPolicy,GitHubActionsApproval,_deny,timestamp

PROFILE='compose-production-frontend-intent-v1'
AUDIENCE='dev-workflow-production-frontend-intent-v1'
BLOG='luohao0308/luohao-blog'
RUNTIME='luohao0308/dev-workflow'
LEDGER='luohao0308/dev-workflow-authority-ledger'
WORKFLOW=RUNTIME+'/.github/workflows/production-frontend-review.yml@refs/heads/main'
REVIEW_FIELDS={'identity','snapshotDigest','bodyDigest','protectedContainerIds','sameImage','selectedServices','representabilityChecked','engineReconstructionVerified','freshnessVerified','authorityGranted','runtimePermit','executionAvailable','productionReady','executionBlockedReasons'}
IDENTITY_FIELDS={'hostId','daemonId','project','service','containerId','containerName','imageId','sourceSha'}
HASH=re.compile('[0-9a-f]{64}\\Z')


def _digest(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(raw)>1024*1024:_deny('Production review exceeds byte budget')
    return hashlib.sha256(raw).hexdigest()


def prepare_production_frontend_request(review,*,policy_hash,expires_at,operation='deploy'):
    if operation!='deploy':_deny('Production rollback requires issued completed deployment history')
    try:
        r=deepcopy(review)
        if type(r) is not dict or set(r)!=REVIEW_FIELDS or type(r['identity']) is not dict or set(r['identity'])!=IDENTITY_FIELDS:_deny('Invalid closed production review')
        i=r['identity'];protected=r['protectedContainerIds']
        reasons=r['executionBlockedReasons']
        if (any(type(i[k]) is not str for k in IDENTITY_FIELDS)
                or i['containerName']!='blog-frontend'
                or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',i['hostId'])
                or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}',i['daemonId'])
                or type(reasons) is not list or len(reasons)>32
                or any(type(x) is not str or not re.fullmatch('[a-z0-9][a-z0-9-]{0,127}',x) for x in reasons)
                or len(reasons)!=len(set(reasons))
                or type(protected) is not list or len(protected)>32):
            _deny('Invalid production identity or blocker facts')
        if (any(type(r[k]) is not str or not HASH.fullmatch(r[k]) for k in ('snapshotDigest','bodyDigest'))
                or type(policy_hash) is not str or not HASH.fullmatch(policy_hash)
                or type(i['imageId']) is not str or not re.fullmatch('sha256:[0-9a-f]{64}',i['imageId'])
                or type(i['containerId']) is not str or not HASH.fullmatch(i['containerId'])
                or type(i['sourceSha']) is not str or not re.fullmatch('[0-9a-f]{40}',i['sourceSha'])
                or not time.time()<timestamp(expires_at).timestamp()<=time.time()+3600):_deny('Invalid production review pins or expiry')
        if (r.get('sameImage') is not True or r.get('representabilityChecked') is not True
                or r.get('selectedServices')!=['frontend'] or i['project']!='luohao-blog-prod' or i['service']!='frontend'
                or i['containerId'] in protected or type(protected) is not list or protected!=sorted(set(protected))
                or any(type(x) is not str or not HASH.fullmatch(x) for x in protected)
                or any(r.get(k) is not False for k in ('authorityGranted','runtimePermit','executionAvailable','productionReady','freshnessVerified','engineReconstructionVerified'))):
            _deny('Invalid read-only production frontend review')
        req=RequestV2(schema_version=2,operation=operation,profile_id=PROFILE,profile_version='1',
            source=SourceIdentity('github.com','https://github.com/'+BLOG+'.git',1395689651,BLOG,i['sourceSha']),
            target=TargetIdentity('compose','luohao-blog-prod','frontend'),environment='production',production=True,
            daemon_id=i['daemonId'],host_id=i['hostId'],components=('frontend',),protected_components=tuple(protected),
            before_hash=r['snapshotDigest'],after_hash=r['bodyDigest'],artifact_digest=i['imageId'].removeprefix('sha256:'),
            observation_hash=r['snapshotDigest'],history_hash=None,plan_hash=_digest(r),policy_hash=policy_hash,expires_at=expires_at,max_uses=1)
        if deepcopy(review)!=r:_deny('Production review changed during request construction')
        return req
    except (KeyError,ValueError,TypeError,AttributeError,OverflowError,RecursionError):
        _deny('Invalid read-only production frontend review')


@dataclass(frozen=True)
class ProductionFrontendGrantV1:
    grant_id:str
    request_hash:str
    expires_at:str
    max_uses:int


@dataclass(frozen=True)
class ProductionFrontendReceiptV1:
    grant_id:str
    request_hash:str
    use_number:int
    consumed_at:str


@dataclass(frozen=True,kw_only=True)
class ProductionFrontendApprovalPolicyV1(HostPolicy):
    source_sha:str
    host_id:str
    daemon_id:str
    current_image_id:str
    snapshot_hash:str
    body_hash:str
    plan_hash:str
    protected_inventory_hash:str
    request_hash:str
    policy_hash:str
    production:bool=True
    operation:str='deploy'

    def __post_init__(self):
        super().__post_init__()
        if (self.workflow_ref!=WORKFLOW or self.host_repository!=RUNTIME or self.host_repository_id!=1327491026
                or self.target_repository!=BLOG or self.target_repository_id!=1395689651
                or self.ledger_repository!=LEDGER or self.ledger_repository_id!=1436718662
                or self.production is not True or self.operation!='deploy'
                or type(self.source_sha) is not str or not re.fullmatch('[0-9a-f]{40}',self.source_sha)
                or type(self.current_image_id) is not str or not re.fullmatch('sha256:[0-9a-f]{64}',self.current_image_id)
                or type(self.host_id) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',self.host_id)
                or type(self.daemon_id) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}',self.daemon_id)
                or any(type(x) is not str or not HASH.fullmatch(x) for x in (self.snapshot_hash,self.body_hash,self.plan_hash,self.protected_inventory_hash,self.request_hash,self.policy_hash))):
            _deny('Invalid trusted production frontend policy')


class GitHubProductionFrontendApprovalV1(GitHubActionsApproval):
    profile_id=PROFILE
    audience=AUDIENCE
    request_type=RequestV2
    operations=frozenset(('deploy',))
    grant_type=ProductionFrontendGrantV1
    receipt_type=ProductionFrontendReceiptV1
    ledger_namespace='workflow-production-frontend-intent-v1'
    grant_namespace='github-production-frontend-intent-v1'

    def __init__(self,client,oidc_token,requests,policy,*,verifier=None):
        if type(policy) is not ProductionFrontendApprovalPolicyV1:_deny('Production frontend policy required')
        super().__init__(client,oidc_token,requests,policy,verifier=verifier)

    def _ledger_marker(self,request):
        return 'tags/'+self.ledger_namespace+'/'+request.digest()

    def _match(self,request):
        p=self.policy
        if (type(request) is not RequestV2 or self._requests.get(request.digest())!=request
                or request.digest()!=p.request_hash or request.operation!='deploy' or request.profile_id!=PROFILE or request.profile_version!='1'
                or request.source!=SourceIdentity('github.com','https://github.com/'+BLOG+'.git',1395689651,BLOG,p.source_sha)
                or request.target!=TargetIdentity('compose','luohao-blog-prod','frontend') or request.environment!='production'
                or request.production is not True or request.components!=('frontend',) or request.max_uses!=1 or request.history_hash is not None
                or request.host_id!=p.host_id or request.daemon_id!=p.daemon_id
                or request.before_hash!=p.snapshot_hash or request.observation_hash!=p.snapshot_hash or request.after_hash!=p.body_hash
                or request.artifact_digest!=p.current_image_id[7:] or request.plan_hash!=p.plan_hash or request.policy_hash!=p.policy_hash
                or _digest(list(request.protected_components))!=p.protected_inventory_hash):
            _deny('Production frontend request differs from trusted policy')
        now=time.time()
        if not now<timestamp(request.expires_at).timestamp()<=now+3600:_deny('Production frontend request expired or excessive')

    def _check_authority(self):
        for request in self.requests:self._match(request)
        super()._check_authority()
        for request in self.requests:self._match(request)

    def _grant_expiry(self,request):
        return min(self._expires,timestamp(request.expires_at).timestamp())

    def guard(self,request):
        _deny('Production frontend consent has no runtimePermit')

    def check_consumed_intent(self,request):
        return GitHubActionsApproval.guard(self,request)
