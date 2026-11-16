"""Protected production intent review transport; never consumes or executes."""
from contextlib import contextmanager
import stat
import weakref
from dataclasses import asdict
from datetime import datetime, timezone
import base64
import hashlib
import json
import os
import re
import threading
import time
from urllib.parse import urlencode

from deployment_compose_live_review_v3_host import GitHubLiveReviewV3, LiveReviewBlocked, CONFIG, _private
from deployment_compose_production_frontend_approval_v1_host import (
    GitHubProductionFrontendApprovalV1, GitHubProductionFrontendApprovalV2, GitHubProductionFrontendApprovalV3,
    prepare_production_frontend_request, PROFILE, RUNTIME)
from deployment_compose_full_body_review_contract import canonical, parse_stamp
from deployment_contract_v2 import RequestV2

WORKFLOW='.github/workflows/production-frontend-review.yml'
PUBLIC_ARTIFACT='production-frontend-public-review'
SEALED_ARTIFACT='production-frontend-sealed-oidc'
RELEASE_ARTIFACT = 'production-retained-release-review'
_ISSUED=weakref.WeakKeyDictionary()
_APPROVAL_TYPES = {
    '1': GitHubProductionFrontendApprovalV1,
    '2': GitHubProductionFrontendApprovalV2,
    '3': GitHubProductionFrontendApprovalV3,
}


class GitHubProductionFrontendReviewV1(GitHubLiveReviewV3):
    def __init__(self,private_root,*,runtime_sha,recipient_private_key,registered_policy_hash):
        if type(registered_policy_hash) is not str or re.fullmatch('[0-9a-f]{64}',registered_policy_hash) is None:
            raise LiveReviewBlocked('Registered production policy required')
        self._owner=(os.getpid(),threading.get_ident())
        self.registered_policy_hash=registered_policy_hash
        super().__init__(private_root,source_sha=runtime_sha,recipient_private_key=recipient_private_key)
        self._pins=(self.root,self.key,self.source_sha,self.registered_policy_hash)
        self._closed=False
        self._release = None
        self._release_dispatched = False
        self._root_fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self._root_identity=(os.fstat(self._root_fd).st_dev,os.fstat(self._root_fd).st_ino)
        _ISSUED[self]=(self._owner,self._pins,id(self.client),self._root_fd,self._root_identity,canonical(CONFIG))

    def _owned(self):
        if type(self) is not GitHubProductionFrontendReviewV1 or _ISSUED.get(self)!=(self._owner,self._pins,id(self.client),self._root_fd,self._root_identity,canonical(CONFIG)):
            raise LiveReviewBlocked('Unissued production review controller')
        if self._closed:raise LiveReviewBlocked('Production review closed')
        held=os.fstat(self._root_fd)
        if (held.st_dev,held.st_ino)!=self._root_identity:
            raise LiveReviewBlocked('Private root descriptor changed')
        info=self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode&0o777!=0o700 or info.st_uid!=os.getuid() or (info.st_dev,info.st_ino)!=self._root_identity:
            raise LiveReviewBlocked('Private root changed')
        if self._owner!=(os.getpid(),threading.get_ident()) or self._closed or self._pins!=(self.root,self.key,self.source_sha,self.registered_policy_hash):
            raise LiveReviewBlocked('Production review owner changed')

    def close(self):
        GitHubProductionFrontendReviewV1._owned(self)
        self._closed=True
        try:super().close()
        finally:os.close(self._root_fd)

    def _environment(self):
        GitHubProductionFrontendReviewV1._owned(self)
        env=super()._environment()
        if env.get('deployment_branch_policy')!={'protected_branches':False,'custom_branch_policies':True}:
            raise LiveReviewBlocked('Explicit main branch review policy required')
        branches=self._get('/environments/compose-review/deployment-branch-policies?per_page=100')
        if branches.get('total_count',101)>100 or not any(p.get('name')=='main' and p.get('type')=='branch' for p in branches.get('branch_policies',[])):
            raise LiveReviewBlocked('Main is not admitted to protected review')
        if self._get('/actions/variables/DW_PROD_FRONTEND_POLICY_HASH').get('value')!=self.registered_policy_hash:
            raise LiveReviewBlocked('Registered production policy changed')
        return env

    def _env(self,run):
        return dict(CONFIG,DW_PROD_FRONTEND_POLICY_HASH=self.registered_policy_hash,
            GITHUB_REPOSITORY=RUNTIME,GITHUB_REPOSITORY_ID='1327491026',GITHUB_REF='refs/heads/main',
            GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='workflow_dispatch',
            GITHUB_WORKFLOW_REF=RUNTIME+'/'+WORKFLOW+'@refs/heads/main',
            GITHUB_WORKFLOW_SHA=run['head_sha'],GITHUB_SHA=run['head_sha'],GITHUB_RUN_ID=str(run['id']))

    def _artifact(self,run,name,filename,limit,directory,*,attempts=1,listing=None):
        import io,zipfile,stat
        if listing is None:
            listing=self._get('/actions/runs/'+str(run['id'])+'/artifacts?per_page=100')
        if listing.get('total_count',101)>100:raise LiveReviewBlocked('Artifact listing exceeds bound')
        found=[a for a in listing.get('artifacts',[]) if a.get('name')==name]
        if not found:return None
        if len(found)!=1 or found[0].get('expired') is not False or type(found[0].get('id')) is not int or not 0<found[0].get('size_in_bytes',limit*2+1)<=limit*2:raise LiveReviewBlocked('Invalid production artifact metadata')
        for attempt in range(attempts):
            response=self._command(['gh','api','--hostname','github.com','/repos/'+RUNTIME+'/actions/artifacts/'+str(found[0]['id'])+'/zip'])
            if not response.returncode:break
            if attempt+1<attempts:time.sleep(2**attempt)
        if response.returncode:raise LiveReviewBlocked('Production artifact download failed')
        if len(response.stdout)>limit*2:raise LiveReviewBlocked('Oversized production artifact')
        try:
            with zipfile.ZipFile(io.BytesIO(response.stdout)) as archive:
                entries=archive.infolist()
                if len(entries)!=1 or entries[0].filename!=filename or entries[0].orig_filename!=filename or entries[0].file_size>limit or entries[0].flag_bits&65 or stat.S_IFMT(entries[0].external_attr>>16) not in (0,stat.S_IFREG):raise ValueError()
                return archive.read(entries[0])
        except Exception:raise LiveReviewBlocked('Unsafe production artifact') from None

    def consume_prepared(self,*args,**kwargs):
        raise LiveReviewBlocked('Legacy review entrypoint is unavailable on production controller')

    def consume_scene_recovery(self,*args,**kwargs):
        raise LiveReviewBlocked('Legacy recovery entrypoint is unavailable on production controller')

    def _consume_prepared(self,*args,**kwargs):
        raise LiveReviewBlocked('Legacy dispatch is unavailable on production controller')

    def request_release_review(self, private_plan, create_review, *, expires_at, on_review):
        """Dispatch one reviewed release from the trusted private preparation."""
        from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
        from deployment_compose_retained_release_plan_v1_host import prepare_release_plan, release_plan_digest
        from deployment_compose_retained_release_review_v1_host import verify_release_review

        GitHubProductionFrontendReviewV1._owned(self)
        if self._release_dispatched or not callable(on_review):
            raise LiveReviewBlocked('Owned release review is already dispatched or invalid')
        plan = prepare_release_plan(create_review, policy_hash=self.registered_policy_hash,
                                    runtime_sha=self.source_sha, expires_at=expires_at)
        cutover = plan['createReview']['retainedCutover']
        expected = prepare_retained_frontend_cutover(private_plan, operation_nonce=cutover['operationNonce'])
        if (expected.digest != cutover['planDigest']
                or canonical(private_plan['publicReview']) != canonical(
                    {key: value for key, value in plan['createReview'].items() if key != 'retainedCutover'})):
            raise LiveReviewBlocked('Release plan differs from private production preparation')
        self._environment()
        if self._get('/git/ref/heads/main').get('object', {}).get('sha') != self.source_sha:
            raise LiveReviewBlocked('Published main differs from fixed runtime SHA')
        workflow = self._get('/actions/workflows/production-frontend-review.yml')
        if workflow.get('path') != WORKFLOW or workflow.get('state') != 'active':
            raise LiveReviewBlocked('Production review workflow unavailable')
        digest = release_plan_digest(plan)
        payload = dict(ref='main', inputs=dict(mode='launch-release', public_payload=canonical(plan)))
        fd = os.open(f'release-{digest}.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self._root_fd)
        with os.fdopen(fd, 'w') as output:
            output.write(canonical(payload))
            output.flush()
            os.fsync(output.fileno())
        os.fsync(self._root_fd)
        self._release_dispatched = True
        since = datetime.now(timezone.utc).replace(microsecond=0)
        self._dispatch(payload, self._owned)
        query = urlencode(dict(event='workflow_dispatch', branch='main', head_sha=self.source_sha,
                               created='>='+since.strftime('%Y-%m-%dT%H:%M:%SZ'), per_page=100))
        deadline = min(time.time()+540, parse_stamp(expires_at).timestamp()-900)
        while time.time() < deadline:
            self._owned()
            listing = self._get('/actions/workflows/production-frontend-review.yml/runs?' + query)
            if listing.get('total_count', 101) > 100:
                raise LiveReviewBlocked('Release review listing exceeds bound')
            matches = []
            for run in listing.get('workflow_runs', []):
                if (run.get('head_sha') != self.source_sha or run.get('head_branch') != 'main'
                        or run.get('path') != WORKFLOW or run.get('run_attempt') != 1
                        or run.get('event') != 'workflow_dispatch' or run.get('actor', {}).get('login') != 'github-actions[bot]'
                        or parse_stamp(run['created_at']) < since):
                    continue
                raw = self._artifact(run, RELEASE_ARTIFACT, 'bundle.json', 65536, None, attempts=3)
                if raw is None:
                    continue
                raw = raw.decode('ascii')
                try:
                    artifact, _ = verify_release_review(raw, self._env(run), expected_digest=digest)
                except ValueError:
                    continue
                if artifact['plan'] == plan:
                    matches.append((run, raw, artifact))
            if len(matches) > 1:
                raise LiveReviewBlocked('Multiple matching release reviews')
            if matches:
                run, raw, artifact = matches[0]
                jobs = self._get('/actions/runs/' + str(run['id']) + '/jobs')['jobs']
                if any(job['name'] == 'protected-review' and job['status'] == 'waiting' for job in jobs):
                    self._release = (dict(run), raw, digest, expires_at)
                    on_review(dict(url=run['html_url'], comment='dev-workflow approve '+artifact['approvalHash'],
                                   expiresAt=expires_at, production=True, runId=run['id']))
                    self._owned()
                    return
            time.sleep(min(4, max(0, deadline-time.time())))
        raise LiveReviewBlocked('Timed out finding a protected release review')

    def release_stage_grant(self, stage, review, *, after_slot, witness_source=None, readiness_failure=None):
        from deployment_compose_retained_release_authority_v1_host import RetainedReleaseStageApprovalV1
        from deployment_compose_retained_release_review_v1_host import SLOT_COUNT
        from release_host import timestamp

        GitHubProductionFrontendReviewV1._owned(self)
        minima = {'create': 180, 'switch': 285, 'rollback': 230}
        if (self._release is None or type(stage) is not str or stage not in minima
                or type(after_slot) is not int or not 0 <= after_slot < SLOT_COUNT):
            raise LiveReviewBlocked('Invalid release credential stage')
        selected, artifact, digest, expiry = self._release
        deadline = min(time.time()+(840 if stage == 'create' else 170), parse_stamp(expiry).timestamp())
        while time.time() < deadline:
            self._owned()
            run = self._get('/actions/runs/' + str(selected['id']))
            if (any(run.get(key) != selected.get(key) for key in ('id', 'head_sha', 'run_attempt', 'path', 'actor', 'event'))
                    or run.get('status') == 'completed'):
                raise LiveReviewBlocked('Release approval workflow changed or ended')
            if any(row.get('state') == 'rejected' for row in self._get('/actions/runs/' + str(run['id']) + '/approvals')):
                raise LiveReviewBlocked('Protected release review rejected')
            listing = self._get('/actions/runs/' + str(run['id']) + '/artifacts?per_page=100')
            for slot in range(SLOT_COUNT, after_slot, -1):
                encrypted = self._artifact(run, f'production-retained-release-slot-{slot}', 'oidc.cms.der',
                                           1048576, None, attempts=3, listing=listing)
                if encrypted is None:
                    continue
                import subprocess

                _private(self.key, 0o600)
                result = subprocess.run(['/usr/bin/openssl', 'cms', '-decrypt', '-inform', 'DER',
                                         '-inkey', str(self.key)], input=encrypted, capture_output=True, timeout=15)
                token = result.stdout
                if result.returncode or len(token) > 32768 or not token.isascii() or token.count(b'.') != 2:
                    raise LiveReviewBlocked('Invalid release slot ciphertext')
                part = token.split(b'.')[1]
                candidate_expiry = json.loads(base64.urlsafe_b64decode(part+b'='*(-len(part)%4))).get('exp')
                # This read only chooses a candidate slot. The authority verifies
                # the entire JWT and protected review before granting a request.
                if type(candidate_expiry) is not int or min(candidate_expiry, parse_stamp(expiry).timestamp())-time.time() < minima[stage]:
                    continue
                approval = RetainedReleaseStageApprovalV1(
                    self.client, token.decode('ascii'), artifact, self._env(run), reviewed_digest=digest,
                    slot=slot, stage=stage, current_review=review, witness_source=witness_source,
                    readiness_failure=readiness_failure,
                )
                grant = approval.validate(approval.request)
                if timestamp(grant.expires_at).timestamp()-time.time() >= minima[stage]-4:
                    return slot, approval, grant
            time.sleep(min(4, max(0, deadline-time.time())))
        raise LiveReviewBlocked('No sufficiently fresh release slot')

    def request_prepared_review(self,plan,request,on_review):
        from deployment_compose_production_frontend_review_contract import verify
        GitHubProductionFrontendReviewV1._owned(self)
        if type(request) is not RequestV2 or request.profile_id!=PROFILE or not callable(on_review):
            raise LiveReviewBlocked('Exact production preparation required')
        frozen=canonical(plan)
        def check():
            GitHubProductionFrontendReviewV1._owned(self)
            if canonical(plan)!=frozen or type(plan) is not dict or set(plan)!={'privateBody','publicReview'}:
                raise LiveReviewBlocked('Private production preparation changed')
            review=plan['publicReview']
            if hashlib.sha256(canonical(plan['privateBody']).encode('ascii')).hexdigest()!=review['bodyDigest']:
                raise LiveReviewBlocked('Private body differs from review')
            if prepare_production_frontend_request(
                    review,policy_hash=self.registered_policy_hash,expires_at=request.expires_at,
                    operation=request.operation)!=request:
                raise LiveReviewBlocked('Request differs from private preparation')
        check();self._environment()
        if self._get('/git/ref/heads/main').get('object',{}).get('sha')!=self.source_sha:
            raise LiveReviewBlocked('Published main differs from fixed runtime SHA')
        workflow=self._get('/actions/workflows/production-frontend-review.yml')
        if workflow.get('path')!=WORKFLOW or workflow.get('state')!='active':
            raise LiveReviewBlocked('Production review workflow unavailable')
        wait_seconds = 1500 if request.operation == 'rollback' else 900
        deadline=min(time.time()+wait_seconds,parse_stamp(request.expires_at).timestamp())
        session_name='production-review-'+request.digest()
        os.mkdir(session_name,mode=0o700,dir_fd=self._root_fd)
        session_fd=os.open(session_name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._root_fd)
        try:
            info=os.fstat(session_fd);session_identity=(info.st_dev,info.st_ino)
            def check_session():
                check()
                current=os.stat(session_name,dir_fd=self._root_fd,follow_symlinks=False)
                if not stat.S_ISDIR(current.st_mode) or current.st_mode&0o777!=0o700 or current.st_uid!=os.getuid() or (current.st_dev,current.st_ino)!=session_identity:
                    raise LiveReviewBlocked('Private session changed')
            check_session()
            payload=dict(ref='main',inputs=dict(mode='launch',public_payload=canonical(dict(request=asdict(request),review=plan['publicReview']))))
            fd=os.open('dispatch.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=session_fd)
            with os.fdopen(fd,'w') as output:
                output.write(canonical(payload));output.flush();os.fsync(output.fileno())
            os.fsync(session_fd);check_session()
            return self._await_review(plan,request,on_review,verify,check_session,payload,deadline)
        finally:os.close(session_fd)

    def _dispatch(self,payload,check):
        """gh accepts the workflow API's empty 204 response; no ledger client POST.

        The payload is the frozen in-memory public value, never a reopened file.
        A failed/ambiguous subprocess is a single consumed launch attempt.
        """
        import subprocess
        GitHubProductionFrontendReviewV1._owned(self);check()
        raw=canonical(payload).encode('ascii')
        try:
            result=subprocess.run(['gh','api','--hostname','github.com','--method','POST',
                '-H','X-GitHub-Api-Version: 2022-11-28',
                '/repos/'+RUNTIME+'/actions/workflows/production-frontend-review.yml/dispatches',
                '--input','-'],input=raw,capture_output=True,timeout=30,check=False)
        except Exception:
            raise LiveReviewBlocked('Dispatch outcome unknown; do not retry') from None
        if result.returncode:
            raise LiveReviewBlocked('Dispatch outcome unknown; do not retry')

    def _await_review(self,plan,request,on_review,verify,check,payload,deadline):
        dispatched=datetime.now(timezone.utc).replace(microsecond=0)
        stage = {'stage': plan['publicReview']['retainedCutover']['stage']} if request.profile_version == '3' else {}
        check()
        self._dispatch(payload,check)
        selected=None;raw=None
        while time.time()<deadline:
            check()
            if selected is None:
                listing=self._get('/actions/workflows/production-frontend-review.yml/runs?event=workflow_dispatch&per_page=100')
                if listing.get('total_count',0)>100:raise LiveReviewBlocked('Review run listing exceeds bound')
                matches=[]
                for run in listing.get('workflow_runs',[]):
                    if not (run.get('head_sha')==self.source_sha and run.get('path')==WORKFLOW and run.get('run_attempt')==1 and run.get('event')=='workflow_dispatch' and run.get('actor',{}).get('login')=='github-actions[bot]' and parse_stamp(run['created_at'])>=dispatched):continue
                    artifact=self._artifact(run,PUBLIC_ARTIFACT,'bundle.json',65536,None)
                    if artifact is None:continue
                    try:
                        actual,policy,bundle_hash=verify(artifact.decode('ascii'),self._env(run))
                        if actual!=request or canonical(json.loads(artifact)['review'])!=canonical(plan['publicReview']):continue
                    except ValueError:continue
                    matches.append((run,artifact,policy,bundle_hash))
                if len(matches)>1:raise LiveReviewBlocked('Multiple matching production reviews')
                if matches:
                    selected,raw,policy,bundle_hash=matches[0]
                    on_review(dict(url=selected['html_url'],comment='dev-workflow approve '+bundle_hash,production=True,operation=request.operation,requestHash=request.digest(),expiresAt=request.expires_at,**stage))
                    check()
            if selected is not None:
                run=self._get('/actions/runs/'+str(selected['id']))
                if any(run.get(k)!=selected.get(k) for k in ('id','head_sha','run_attempt','event','path','actor')) or run.get('status')=='completed':raise LiveReviewBlocked('Review run changed or ended')
                if any(a.get('state')=='rejected' for a in self._get('/actions/runs/'+str(run['id'])+'/approvals')):raise LiveReviewBlocked('Review rejected')
                cipher=self._artifact(run,SEALED_ARTIFACT,'oidc.cms.der',1048576,None)
                if cipher is not None:
                    self._environment();check()
                    actual,policy,_=verify(raw.decode('ascii'),self._env(run))
                    if actual!=request:raise LiveReviewBlocked('Review changed')
                    _private(self.key,0o600)
                    # Input ciphertext is passed via a pipe; token is never saved.
                    import subprocess
                    result=subprocess.run(['/usr/bin/openssl','cms','-decrypt','-inform','DER','-inkey',str(self.key)],input=cipher,capture_output=True,timeout=15)
                    token=result.stdout
                    if result.returncode or len(token)>32768 or not token.isascii() or token.count(b'.')!=2:raise LiveReviewBlocked('Invalid sealed consent')
                    approval_type=_APPROVAL_TYPES[request.profile_version]
                    approval=approval_type(self.client,token.decode('ascii'),[request],policy)
                    if request.profile_version == '3':
                        grant = approval.provisional_grant(request)
                    else:
                        grant = approval.validate(request)
                    check()
                    return approval,grant,dict(runId=run['id'],url=run['html_url'],requestHash=request.digest(),runtimePermit=False,consumed=False,**stage)
            time.sleep(min(5,max(0,deadline-time.time())))
        raise LiveReviewBlocked('Production review expired; do not retry dispatch')
