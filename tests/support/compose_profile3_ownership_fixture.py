"""Host-local cleanup bookkeeping only; never execution or admission authority.

Initial IDs must come from the embedding fixture's confirmed create receipts.
This reducer does not contact Docker and accepts no serialized history authority.
"""
import re
import json

from deployment_compose_history_v3_host import AuthenticatedHistoryV3
from deployment_compose_coordinator_v3_host import canonical


def _id(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


class FixtureOwnershipTrackerV3:
    def __init__(self, *, project, daemon_id, policy_hash, witness_pub_hash, epoch,
                 initial_confirmed_ids, protected_ids):
        initial = list(initial_confirmed_ids)
        protected = set(protected_ids)
        if (not project or not daemon_id or len(set(initial)) != len(initial)
                or not all(_id(x) for x in initial + list(protected))
                or not protected <= set(initial)
                or not all(_id(x) for x in (policy_hash, witness_pub_hash, epoch))):
            raise ValueError('fixture-ownership-invalid-bootstrap')
        self.project, self.daemon_id = project, daemon_id
        self.policy_hash, self.witness_pub_hash, self.epoch = policy_hash, witness_pub_hash, epoch
        self._owned, self._seen, self._protected = initial, set(initial), protected
        self._initial = frozenset(initial)
        self._root = None
        self._requests = {}
        self.uncertain = False

    @property
    def owned_ids(self):
        return tuple(self._owned)

    def mark_product_pending(self):
        self.uncertain = True

    def reconcile(self, history):
        self.uncertain = True
        if type(history) is not AuthenticatedHistoryV3:
            raise ValueError('fixture-ownership-authenticated-history-required')
        context = (history._request.digest(), history._bundle.digest)
        if history._parent is None and self._root is not None and context != self._root:
            raise ValueError('fixture-ownership-second-root')
        # capture() performs fresh witness, signature and MAC verification.
        proof = history.capture()
        value = json.loads(proof.canonical)
        bundle = history._bundle.to_dict()
        identity = bundle['identity']
        status = value['chainStatus']
        if (identity['project'] != self.project or identity['daemonId'] != self.daemon_id
                or status['policyHash'] != self.policy_hash or status['epoch'] != self.epoch
                or history._client.key_hash != self.witness_pub_hash
                or history._policy.identity_hash() != self.policy_hash
                or value['pending'] is not None or value['blocker'] is not None
                or status['activePhase'] != 'closed' or not value['closedTail']):
            raise ValueError('fixture-ownership-unresolved-or-foreign-history')
        prefix = list(value['knownPrefix'])
        scopes = list(value['scopes'])
        key = value['originalRequestHash']
        prior = self._requests.get(key)
        parent = value.get('parent')
        start = 0
        if parent is None:
            selected = {s['baselineContainerId'] for s in bundle['services']}
            protected = {s['containerId'] for s in bundle['protectedContainers']}
            if (protected != self._protected or selected & protected
                    or selected | protected != self._initial):
                raise ValueError('fixture-ownership-bootstrap-context-mismatch')
        if parent is not None:
            registered = self._requests.get(parent['originalRequestHash'])
            if (self._root != (parent['originalRequestHash'], parent['bundleDigest'])
                    or registered is None or registered['digest'] != parent['historyDigest']
                    or registered['parent'] is not None
                    or registered['bundle'] != parent['bundleDigest']):
                raise ValueError('fixture-ownership-unregistered-parent')
            if history._request.operation == 'rollback':
                if not registered['complete'] or parent['startWriteIndex'] != 0:
                    raise ValueError('fixture-ownership-incomplete-parent')
            elif history._request.operation == 'recovery':
                start = parent['startWriteIndex']
                if (start != len(registered['prefix'])
                        or canonical(prefix[:start]) != canonical(registered['prefix'])):
                    raise ValueError('fixture-ownership-recovery-prefix')
            else:
                raise ValueError('fixture-ownership-invalid-child')
        elif history._request.operation != 'deploy':
            raise ValueError('fixture-ownership-root-must-deploy')
        if prior is not None:
            if (canonical(prefix[:len(prior['prefix'])]) != canonical(prior['prefix'])
                    or canonical(scopes[:len(prior['scopes'])]) != canonical(prior['scopes'])
                    or prior['bundle'] != value['bundleDigest']):
                raise ValueError('fixture-ownership-history-regressed')
            start = len(prior['prefix'])
        owned, seen = list(self._owned), set(self._seen)
        baselines = {s['name']: s['baselineContainerId'] for s in bundle['services']}
        for op in prefix[start:]:
            if op['phase'] == 'create':
                cid = value['receiptMap'].get(op['service'])
                if op['expectedStatus'] != 201 or not _id(cid) or cid in seen:
                    raise ValueError('fixture-ownership-reused-or-invalid-create')
                owned.append(cid); seen.add(cid)
            elif op['phase'] == 'delete':
                cid = baselines[op['service']]
                if cid in self._protected or cid not in owned:
                    raise ValueError('fixture-ownership-protected-or-unknown-delete')
                owned.remove(cid)
        total = sum(op['phase'] != 'readiness' for op in bundle['operations'])
        record = dict(prefix=prefix, scopes=scopes, digest=proof.digest,
                      bundle=value['bundleDigest'], parent=parent,
                      complete=len(prefix) == total)
        self._owned, self._seen = owned, seen
        self._requests[key] = record
        if parent is None:
            self._root = context
        self.uncertain = False
        return self.owned_ids

    def apply_to_session(self, session, history):
        self.uncertain = True
        session.unknown_write_result = True
        if (session.project != self.project
                or getattr(getattr(session, 'target', None), 'daemon_id', None) != self.daemon_id):
            raise ValueError('fixture-ownership-session-mismatch')
        owned = self.reconcile(history)
        session.created_ids = list(owned)
        session.unknown_write_result = False
        return owned
