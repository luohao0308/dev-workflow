"""Protected release review and bounded OIDC slots for a retained frontend."""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import tempfile

import deployment_compose_full_body_review_contract as common
from deployment_compose_retained_release_plan_v1_host import (
    release_plan_digest, verify_release_plan,
)
from release_host import HostPolicy


SLOT_COUNT = 4
MAX_TOKEN_SECONDS = 300
_FIELDS = {'schema', 'kind', 'issuedAt', 'plan', 'planDigest', 'policy', 'approvalHash'}


def prepare_release_review(raw, env, now=None):
    from deployment_compose_production_frontend_review_contract import identities

    now = common.parse_stamp(common.stamp(now or datetime.now(timezone.utc)))
    plan = common._parse(raw, 32768)
    policy = HostPolicy(**identities(env), expires_at=plan['expiresAt'])
    plan_digest = release_plan_digest(plan)
    plan = verify_release_plan(plan, reviewed_digest=plan_digest, runtime_sha=policy.workflow_sha, now=now)
    if plan['policyHash'] != env['DW_PROD_FRONTEND_POLICY_HASH']:
        raise ValueError('Release plan differs from registered policy')
    approval = hashlib.sha256(
        b'dev-workflow:retained-release-review:v1\0'
        + common.canonical(dict(planDigest=plan_digest, policy=asdict(policy))).encode('ascii')
    ).hexdigest()
    return dict(schema=1, kind='retained-release-review', issuedAt=common.stamp(now),
                plan=plan, planDigest=plan_digest, policy=asdict(policy), approvalHash=approval)


def verify_release_review(raw, env, *, expected_digest=None, now=None):
    now = now or datetime.now(timezone.utc)
    artifact = common._parse(raw, 65536)
    common._closed(artifact, _FIELDS)
    issued = common.parse_stamp(artifact['issuedAt'])
    if issued > now:
        raise ValueError('Release review issued in the future')
    expected = prepare_release_review(common.canonical(artifact['plan']), env, issued)
    if common.canonical(expected) != raw or (expected_digest is not None and expected_digest != expected['planDigest']):
        raise ValueError('Release review differs from pinned artifact')
    verify_release_plan(expected['plan'], reviewed_digest=expected['planDigest'], runtime_sha=env['GITHUB_SHA'], now=now)
    values = expected['policy']
    policy = HostPolicy(**values)
    return expected, policy


def slot_audience(approval_hash, slot):
    common._hex(approval_hash)
    if type(slot) is not int or not 1 <= slot <= SLOT_COUNT:
        raise ValueError('Invalid release OIDC slot')
    return f'dev-workflow-retained-frontend-release-v1:{approval_hash}:{slot}'


def release_summary(raw, env):
    artifact, policy = verify_release_review(raw, env)
    review = artifact['plan']['createReview']
    cutover = review['retainedCutover']
    identity = review['identity']
    return (
        '## Production retained frontend release\n\n'
        f"Same immutable image `{identity['imageId']}` for `{identity['project']}` on `{identity['hostId']}`.\n\n"
        f"Create one candidate using the reviewed body, switch once, then retain a healthy candidate. "
        f"Cutover plan `{cutover['planDigest']}`, protection `{cutover['protectionDigest']}`.\n\n"
        'Automatic rollback requires four definitely closed switch writes and a verified, matching readiness failure. '
        'Any ambiguous write requires separate recovery. Each stage can be claimed once.\n\n'
        f"Runtime `{policy.workflow_sha}`. Approval expires at `{policy.expires_at}`.\n\n"
        f"Exact approval comment: `dev-workflow approve {artifact['approvalHash']}`\n"
    )


def seal_release_slot(raw, env, recipient, output, *, slot):
    output = Path(output)
    if os.path.lexists(output):
        raise FileExistsError('Release evidence output exists')
    artifact, _ = verify_release_review(raw, env)
    token = common._fetch_verified_audience(env, slot_audience(artifact['approvalHash'], slot))
    verify_release_review(raw, env)
    fd, name = tempfile.mkstemp(prefix='.retained-release-slot-', dir=output.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        common.encrypt_token(token, recipient, temporary)
        verify_release_review(raw, env)
        os.link(temporary, output, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
