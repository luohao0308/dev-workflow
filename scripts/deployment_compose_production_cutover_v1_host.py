"""Exact same-image switch plan that keeps the original container for restoration."""
from dataclasses import dataclass
import hashlib
import json
import re

from deployment_compose_production_frontend_v3_host import _encode

PROFILE = 'production-frontend-retain-original-v1'
PREFIX = '/v1.45/containers/'
HEX = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class ContainerOperation:
    phase: str
    path: str
    body: bytes = b''


@dataclass(frozen=True)
class RetainedFrontendCutoverV1:
    original_id: str
    protected_ids: tuple[str, ...]
    candidate_name: str
    retained_name: str
    body: bytes
    digest: str

    def create(self):
        return ContainerOperation('create', PREFIX + 'create?name=' + self.candidate_name, self.body)

    def switch(self, candidate_id):
        candidate = self._candidate(candidate_id)
        original = PREFIX + self.original_id
        return (
            ContainerOperation('stop-original', original + '/stop?t=10'),
            ContainerOperation('retain-original', original + '/rename?name=' + self.retained_name),
            ContainerOperation('name-candidate', candidate + '/rename?name=blog-frontend'),
            ContainerOperation('start-candidate', candidate + '/start'),
        )

    def restore(self, candidate_id, *, switch_prefix, candidate_running):
        """Plan a separately approved restoration from an observed closed prefix."""
        candidate = self._candidate(candidate_id)
        original = PREFIX + self.original_id
        if (type(switch_prefix) is not int or not 1 <= switch_prefix <= 4
                or type(candidate_running) is not bool or candidate_running and switch_prefix != 4):
            raise ValueError('invalid-frontend-restoration-prefix')
        operations = []
        if candidate_running:
            operations.append(ContainerOperation('stop-candidate', candidate + '/stop?t=10'))
        if switch_prefix >= 3:
            operations.append(ContainerOperation('unname-candidate', candidate + '/rename?name=' + self.candidate_name))
        if switch_prefix >= 2:
            operations.append(ContainerOperation('rename-original', original + '/rename?name=blog-frontend'))
        operations.append(ContainerOperation('start-original', original + '/start'))
        return tuple(operations)

    def _candidate(self, candidate_id):
        if (type(candidate_id) is not str or not HEX.fullmatch(candidate_id)
                or candidate_id == self.original_id or candidate_id in self.protected_ids):
            raise ValueError('invalid-frontend-create-receipt')
        return PREFIX + candidate_id


def prepare_retained_frontend_cutover(plan, *, operation_nonce):
    """Bind the sequence and reserved names to a previously prepared private body.

    Runtime must revalidate the host, candidate receipt, phase and protection
    evidence. The current production consent profile does not approve this digest.
    """
    try:
        if (type(operation_nonce) is not str or not HEX.fullmatch(operation_nonce)
                or type(plan) is not dict or set(plan) != {'privateBody', 'publicReview'}):
            raise ValueError()
        raw = _encode(plan)
        frozen = json.loads(raw)
        body, review = frozen['privateBody'], frozen['publicReview']
        identity = review['identity']
        original = identity['containerId']
        protected = review['protectedContainerIds']
        if (not HEX.fullmatch(original) or identity['project'] != 'luohao-blog-prod'
                or identity['service'] != 'frontend' or identity['containerName'] != 'blog-frontend'
                or review['selectedServices'] != ['frontend'] or review['sameImage'] is not True
                or not IMAGE.fullmatch(identity['imageId']) or body['Image'] != identity['imageId']
                or any(review.get(key) is not False for key in
                       ('authorityGranted', 'runtimePermit', 'executionAvailable', 'productionReady'))):
            raise ValueError()
        if (type(protected) is not list or len(protected) > 32
                or any(type(cid) is not str or not HEX.fullmatch(cid) for cid in protected)
                or protected != sorted(set(protected)) or original in protected):
            raise ValueError()
        body_bytes = _encode(body)
        body_digest = hashlib.sha256(body_bytes).hexdigest()
        if body_digest != review['bodyDigest'] or _encode(plan) != raw:
            raise ValueError()
        suffix = operation_nonce[:24] + '-frontend'
        candidate_name, retained_name = 'dwc-' + suffix, 'dwb-' + suffix
        # Include exact operation paths with a fixed symbolic receipt value.
        occupied = set(protected) | {original}
        symbolic = next(cid for cid in (f'{index:064x}' for index in range(len(occupied) + 1))
                        if cid not in occupied)
        draft = RetainedFrontendCutoverV1(original, tuple(protected), candidate_name,
                                           retained_name, body_bytes, '')
        material = dict(
            profile=PROFILE, nonce=operation_nonce, review=review, bodyDigest=body_digest,
            create=draft.create().path,
            candidateReceiptPlaceholder=symbolic,
            switch=[op.path for op in draft.switch(symbolic)],
            restore=[
                dict(prefix=prefix, candidateRunning=running, paths=[
                    op.path for op in draft.restore(symbolic, switch_prefix=prefix, candidate_running=running)
                ])
                for prefix in range(1, 5)
                for running in ((False, True) if prefix == 4 else (False,))
            ],
        )
        digest = hashlib.sha256(b'compose-retained-frontend-cutover-v1\0' + _encode(material)).hexdigest()
        return RetainedFrontendCutoverV1(original, tuple(protected), candidate_name,
                                         retained_name, body_bytes, digest)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError):
        raise ValueError('production-frontend-cutover-plan-rejected') from None
