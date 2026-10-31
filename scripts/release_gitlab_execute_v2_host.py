"""Host-only lightweight GitLab Tag SDK. No CLI, Release, retry or discovery.

Approval/ledger/preparation are independent host-owned objects. Matching remote
state is verification, not proof this SDK created a Tag. Real GitLab project,
protected-review and permission acceptance remain separate external requirements.
"""
from dataclasses import dataclass,asdict
from copy import deepcopy
from datetime import datetime,timezone
import threading
import time

from release_gitlab_approval_v2_host import GitLabNativeApprovalV2,NativeGrantV2
from release_gitlab_prepare_v2_host import GitLabRequestPreparationV2,PROFILE
from release_contract_v2 import RequestV2
from release_gitlab import GitLabTagProvider
from release_execute import canonical


@dataclass(frozen=True)
class _TagCommand:
    operation:str
    remote_url:str
    tag:str
    target_sha:str
    tag_object_sha:str


class GitLabExecutionV2Error(ValueError):
    def __init__(self,stage,consumed,post_attempted):
        super().__init__('gitlab-tag-execution-v2-rejected')
        self.stage=stage
        # None preserves an unverified/lost ledger acknowledgement, never a refund.
        self.consumed=True if consumed else (None if stage=='consumption' else False)
        self.post_attempted=post_attempted


class GitLabTagExecutionHostV2:
    def __init__(self, *, authority, preparer, approved_request):
        if (type(authority) is not GitLabNativeApprovalV2 or type(preparer) is not GitLabRequestPreparationV2
                or type(approved_request) is not RequestV2
                or getattr(authority,'_owner',None) is not authority
                or getattr(authority,'_preparer',None) is not preparer
                or approved_request.operation!='remote-tag-push' or approved_request.profile_id!=PROFILE):
            raise GitLabExecutionV2Error('configuration',False,False)
        authority._identity(approved_request)
        self._authority,self._preparer=authority,preparer
        self._request=RequestV2.from_json(approved_request.canonical_json())
        self._owner=self;self._lock=threading.Lock()

    def execute(self,grant):
        with self._lock:
            stage='preparation';consumed=False;calls=[]
            try:
                if self._owner is not self or type(grant) is not NativeGrantV2:raise ValueError()
                a=self._authority;r=self._request
                # Candidate-supplied observation JSON is never accepted here.
                rebuilt=self._preparer.prepare(deepcopy(a._intent),expires_at=r.expires_at)['request']
                if rebuilt.canonical_json()!=r.canonical_json():raise ValueError()
                r.ensure_fresh(datetime.now(timezone.utc))
                stage='consumption'
                receipt=a.consume(grant,r)  # Burn once; no rollback/refund on any following failure.
                consumed=True
                receipt_hash=a.receipt_hash(receipt,r)
                a.guard(r)
                command=_TagCommand(r.operation,r.remote,r.tag,r.target_sha,r.target_sha)
                pinned=canonical(asdict(command))
                def before_mutation(candidate):
                    if candidate is not command or canonical(asdict(candidate))!=pinned or calls:raise ValueError()
                    a.guard(r)
                    if a.receipt_hash(receipt,r)!=receipt_hash:raise ValueError()
                    a.check_local_deadline(r)
                    calls.append(True)
                    return time.monotonic()+min(a._live_deadline-time.time(),self._preparer._preflight.client.timeout)
                provider=GitLabTagProvider(self._preparer._preflight.client,r.identity.project_path,
                                           r.identity.project_id,before_mutation=before_mutation)
                stage='provider'
                provider.push(command)
                # No old missing-tag preparation after our POST: that state changed.
                observed=provider.inspect(command)
                if observed is None or observed['targetSha']!=r.target_sha or observed['objectSha']!=r.target_sha:
                    raise ValueError()
                return dict(outcome='tag-verified',requestHash=r.digest(),tag=r.tag,targetSha=r.target_sha,
                            postAttempted=bool(calls),consumed=True,productionReady=False)
            except Exception:
                raise GitLabExecutionV2Error(stage,consumed,bool(calls)) from None
