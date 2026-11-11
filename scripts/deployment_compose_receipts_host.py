"""Retain exact create results and diagnose candidate IDs; never issue authority.

Host-provisioned inputs only. Archive references are untrusted locators, not
capabilities. Gate finish, durable archive, then journal completion are required;
a pending journal is never repaired from an archive or a live container name.
All stores remain within one filesystem threat boundary; rollback is not solved.
"""
import base64
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))

from deployment_compose_journal_host import BatchJournal
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_gateway import AdmissionTicket, FileWriterGate

HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
MAX_RESPONSE = 8192


@dataclass(frozen=True, eq=False)
class RetainedCreateReceipt:
    reference: str

    def __reduce_ex__(self, protocol):
        fail()

    def __copy__(self):
        fail()

    def __deepcopy__(self, memo):
        fail()


def fail():
    raise ValueError('compose-create-receipt-rejected')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail()
        result[key] = value
    return result


def response_digest(status, body):
    if type(status) is not int or status != 201 or type(body) is not bytes or len(body) > MAX_RESPONSE:
        fail()
    return hashlib.sha256(str(status).encode('ascii') + b'\0' + body).hexdigest()


class ComposeCreateReceipts:
    def __init__(self, journal, archive, *, creates, forbidden_container_ids, derivation_digests=None,
                 source_model_bindings=None, generation_source_binding=False):
        """creates: exact ordered prefix of {index, service, candidateDigest}.

        Host separately validates these expectations against its reviewed plan.
        This class does not authenticate source/project assertions or approve a
        plan, and is deliberately not connected to RequestHost or a transport.
        Optional service-keyed derivation_digests selects binding schema 2;
        it records host expectations and does not verify their source itself.
        Optional source_model_bindings requires derivation pins and selects
        schema3. Host must validate source assertions before constructing this
        recorder; source provenance is not established by storing a digest.
        """
        if (type(journal) is not BatchJournal or type(archive) is not ComposeRecoveryStore
                or type(creates) is not tuple or not 1 <= len(creates) <= 32
                or len(creates) > len(journal.action_digests)
                or type(forbidden_container_ids) is not tuple
                or any(type(value) is not str or not HEX.fullmatch(value) for value in forbidden_container_ids)
                or len(set(forbidden_container_ids)) != len(forbidden_container_ids)):
            fail()
        services = []
        for index, item in enumerate(creates):
            if (type(item) is not dict or set(item) != {'index', 'service', 'candidateDigest'}
                    or type(item['index']) is not int or item['index'] != index
                    or type(item['service']) is not str or not NAME.fullmatch(item['service'])
                    or type(item['candidateDigest']) is not str or not HEX.fullmatch(item['candidateDigest'])):
                fail()
            services.append(item['service'])
        if len(set(services)) != len(services):
            fail()
        if derivation_digests is not None and (
                type(derivation_digests) is not dict or set(derivation_digests) != set(services)
                or any(type(value) is not str or not HEX.fullmatch(value) for value in derivation_digests.values())):
            fail()
        self.journal, self.archive = journal, archive
        self.creates = deepcopy(creates)
        self.forbidden = frozenset(forbidden_container_ids)
        # Host must independently verify the derivation against its pinned
        # recipe/plan. A supplied digest alone does not establish that origin.
        self._derivations = deepcopy(derivation_digests)
        if source_model_bindings is not None:
            if (derivation_digests is None or type(source_model_bindings) is not dict
                    or set(source_model_bindings) != set(services)):
                fail()
            for value in source_model_bindings.values():
                if (type(value) is not dict or set(value) != {
                        'sourceSha', 'modelDigest', 'sourceAssertionDigest', 'createBodyDigest'}
                        or type(value['sourceSha']) is not str
                        or not re.fullmatch('[0-9a-f]{40}', value['sourceSha'])
                        or any(type(value[k]) is not str or not HEX.fullmatch(value[k])
                               for k in ('modelDigest', 'sourceAssertionDigest', 'createBodyDigest'))):
                    fail()
        self._source_models = deepcopy(source_model_bindings)
        if (type(generation_source_binding) is not bool
                or generation_source_binding and source_model_bindings is None):
            fail()
        self._generation_source_binding = generation_source_binding
        self._retained = {}

    @property
    def source_context_digest(self):
        if self._source_models is None:
            return None
        return hashlib.sha256(b'dev-workflow:compose-generation-source-context:v1\0' + canonical({
            'planHash': self.journal.plan_hash, 'requestHash': self.journal.request_hash,
            'creates': self.creates, 'derivations': self._derivations,
            'sources': self._source_models})).hexdigest()

    def _binding(self, index, attempt, generation, operations):
        if type(index) is not int or not 0 <= index < len(self.creates):
            fail()
        binding = {'schemaVersion': 1, 'kind': 'compose-definitive-create-response',
            'planHash': self.journal.plan_hash, 'requestHash': self.journal.request_hash,
            'generation': generation, 'operation': list(operations[index]),
            'actionDigest': self.journal.action_digests[index], 'attempt': attempt,
            **self.creates[index]}
        if self._derivations is not None:
            binding.update(schemaVersion=2, kind='compose-derived-create-response',
                sourceDerivationDigest=self._derivations[binding['service']])
        if self._source_models is not None:
            source = self._source_models[binding['service']]
            if operations[index][2] != source['createBodyDigest']:
                fail()
            binding.update(schemaVersion=3, kind='compose-source-bound-create-response',
                           sourceModelBinding=deepcopy(source))
            if self._generation_source_binding:
                binding.update(schemaVersion=4, kind='compose-generation-source-bound-create-response',
                               sourceContextDigest=self.source_context_digest)
        return binding

    def _response(self, status, body):
        digest = response_digest(status, body)
        try:
            value = json.loads(body, object_pairs_hook=pairs)
        except (ValueError, UnicodeError, RecursionError):
            fail()
        if (type(value) is not dict or set(value) != {'Id', 'Warnings'}
                or type(value['Id']) is not str or not HEX.fullmatch(value['Id'])
                or value['Id'] in self.forbidden
                or value['Warnings'] is not None and (type(value['Warnings']) is not list
                    or len(value['Warnings']) > 32 or any(type(v) is not str or len(v) > 1024
                        for v in value['Warnings']))):
            fail()
        return value['Id'], digest

    def _gate(self, gate, generation, operations):
        if type(gate) is not FileWriterGate:
            fail()
        # This is an authenticated comparison of local histories, not an anchor.
        result = self.journal.reconcile_gate(gate, generation, operations)
        if not result['matched']:
            fail()
        for index in range(len(self.creates)):
            method, path, _ = operations[index]
            if method != 'POST' or not re.fullmatch(r'/v1\.45/containers/create\?name=(?:dwf-[0-9a-f]{64}|dev-workflow-[a-z0-9][a-z0-9_.-]{0,127})', path):
                fail()
        evidence = FileWriterGate.generation_evidence(gate, generation)
        opening = evidence['binding']
        if self._generation_source_binding:
            if (opening.get('source_binding_schema') != 1
                    or opening.get('source_context_digest') != self.source_context_digest):
                fail()
        elif 'source_context_digest' in opening:
            fail()
        return evidence

    def _live_ticket(self, gate, generation, attempt, admission):
        if type(gate) is not FileWriterGate or type(admission) is not AdmissionTicket:
            fail()
        with gate._locked():
            if (admission.generation != generation or admission.attempt_ref != attempt
                    or gate._tickets.get((generation, attempt)) is not admission):
                fail()

    def retain(self, index, attempt, *, status, body, gate, generation, operations, admission):
        """Retain a gateway-finished response; leaves pending journal unchanged."""
        try:
            self._live_ticket(gate, generation, attempt, admission)
            binding = self._binding(index, attempt, generation, operations)
            _, digest = self._response(status, body)
            snapshot = self.journal.snapshot()
            if snapshot['unknown'] != {'index': index, 'action': binding['actionDigest'], 'attempt': attempt}:
                fail()
            evidence = self._gate(gate, generation, operations)
            if (not evidence['events'] or evidence['events'][-1] != {'kind': 'finish', 'data': {
                    'ref': attempt, 'definitive': True, 'response_hash': digest}}):
                fail()
            payload = canonical(dict(binding, status=status, body=base64.b64encode(body).decode('ascii')))
            reference = self.archive.put(payload)
            if self.archive.get(reference) != payload:
                fail()
            token = RetainedCreateReceipt(reference)
            self._retained[(index, attempt)] = token
            return token
        except Exception:
            raise ValueError('compose-create-receipt-rejected') from None

    def _load(self, index, attempt, reference, digest, generation, operations):
        payload = self.archive.get(reference)
        value = json.loads(payload, object_pairs_hook=pairs)
        binding = self._binding(index, attempt, generation, operations)
        if (type(value) is not dict or set(value) != set(binding) | {'status', 'body'}
                or canonical({k: value[k] for k in binding}) != canonical(binding) or canonical(value) != payload
                or type(value['body']) is not str):
            fail()
        body = base64.b64decode(value['body'], validate=True)
        identity, observed = self._response(value['status'], body)
        if observed != digest:
            fail()
        return identity

    def complete(self, index, attempt, retained, *, gate, generation, operations, admission):
        """Complete only from an archived exact finish; never fix a restarted writer.

        Requires the original in-memory Gate ticket and this recorder's retained
        token. Archive locators and restarted objects cannot finish a pending
        journal. This is a recording helper, not a recovery entry point.
        """
        try:
            self._live_ticket(gate, generation, attempt, admission)
            if (type(retained) is not RetainedCreateReceipt
                    or self._retained.get((index, attempt)) is not retained):
                fail()
            binding = self._binding(index, attempt, generation, operations)
            snapshot = self.journal.snapshot()
            if snapshot['unknown'] != {'index': index, 'action': binding['actionDigest'], 'attempt': attempt}:
                fail()
            evidence = self._gate(gate, generation, operations)
            event = evidence['events'][-1]
            if (event['kind'] != 'finish' or event['data']['ref'] != attempt
                    or event['data']['definitive'] is not True):
                fail()
            self._load(index, attempt, retained.reference, event['data']['response_hash'], generation, operations)
            self.journal.record_complete(index, binding['actionDigest'], attempt, event['data']['response_hash'])
        except Exception:
            raise ValueError('compose-create-receipt-rejected') from None

    def bindings(self, references, *, gate, generation, operations):
        """Read a complete create prefix; exported IDs remain non-authoritative."""
        try:
            if (type(references) is not dict or set(references) != set(range(len(self.creates)))
                    or any(type(index) is not int for index in references)):
                fail()
            self._gate(gate, generation, operations)
            snapshot = self.journal.snapshot()
            if snapshot['unknown'] is not None or len(snapshot['completed']) < len(self.creates):
                fail()
            ids = {}
            for index, expected in enumerate(self.creates):
                item = snapshot['completed'][index]
                identity = self._load(index, item['attempt'], references[index], item['response'], generation, operations)
                if identity in ids.values():
                    fail()
                ids[expected['service']] = identity
            # Catch changes across the independent history/receipt reads.
            self._gate(gate, generation, operations)
            if self.journal.snapshot() != snapshot:
                fail()
            result = {'candidateIds': ids, 'blocked': True, 'blocker': 'independent-anchor-required',
                'replaySafe': False, 'quiescenceProven': False,
                'authorityGranted': False, 'executionAvailable': False, 'productionReady': False}
            if self._derivations is not None:
                result.update(payloadSchemaVersion=2, sourceDerivationDigests=dict(self._derivations))
            if self._source_models is not None:
                result.update(payloadSchemaVersion=3, sourceModelBindings=deepcopy(self._source_models),
                              sourceModelProvenanceVerified=False, sourceBindingRecordedBeforeWriteVerified=False)
                if self._generation_source_binding:
                    result.update(payloadSchemaVersion=4, sourceContextDigest=self.source_context_digest,
                                  sourceBindingRecordedBeforeWriteVerified=True)
            return result
        except Exception:
            raise ValueError('compose-create-receipt-rejected') from None
