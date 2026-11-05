"""Full Gate envelopes in a signed witness chain; evidence grants no authority."""
import base64
import hashlib
import json
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, ZERO, hex_value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


class GateOperationWitnessAdapterV3:
    def __init__(self, client):
        if type(client) is not OperationWitnessClientV3:
            raise ValueError('gate-operation-witness-v3-rejected')
        self._client = client

    @property
    def binding(self):
        return self._client.binding

    @property
    def key_hash(self):
        return self._client.key_hash

    @staticmethod
    def _data(event, attempt):
        kind, data = event['kind'], event['data']
        if kind in ('open', 'proof'):
            return {}
        if kind == 'prepare':
            return {'attemptRef': data['ref']}
        if kind == 'admit':
            return {'attemptRef': data}
        if kind == 'close':
            return {'attemptRef': attempt}
        return dict(attemptRef=data['ref'], definitive=data['definitive'],
                    status=data['status'], bodyBase64=data['bodyBase64'])

    def _records(self):
        try:
            records = self._client.events_after(seq=0, head=ZERO)
            previous, attempt, directory = ZERO, None, None
            for index, record in enumerate(records):
                raw = base64.b64decode(record['externalMaterialBase64'], validate=True)
                envelope = json.loads(raw)
                event = envelope['payload']
                if (type(envelope) is not dict or set(envelope) != {'version', 'domain', 'policy', 'payload', 'mac'}
                        or type(envelope['version']) is not int or envelope['version'] != 1
                        or not hex_value(envelope['mac'])
                        or type(event) is not dict or set(event) != {'generation', 'directory', 'previous', 'kind', 'data'}
                        or canonical(envelope) != raw or envelope['domain'] != 'dev-workflow.writer-gate.event'
                        or event['generation'] != self.binding['generation'] or event['previous'] != previous
                        or event['kind'] != ['open', 'prepare', 'admit', 'finish', 'close', 'proof'][index]
                        or envelope['policy'].get('operation_profile') != 'compose-v3'
                        or hashlib.sha256(canonical(envelope['policy'])).hexdigest() != self.binding['policyHash']):
                    raise ValueError
                if index == 0:
                    directory = event['directory']
                elif event['directory'] != directory:
                    raise ValueError
                if index == 1:
                    attempt = event['data']['ref']
                if record['event']['data'] != self._data(event, attempt):
                    raise ValueError
                previous = hashlib.sha256(canonical(event)).hexdigest()
            return records, previous, attempt
        except Exception:
            raise ValueError('gate-operation-witness-v3-rejected') from None

    def check(self, generation, count, gate_head):
        records, previous, _ = self._records()
        if generation != self.binding['generation'] or len(records) != count or previous != gate_head:
            raise ValueError('gate-operation-witness-v3-rejected')
        return self._client.check(expected_seq=count, expected_head=records[-1]['head'] if records else ZERO)

    def reserve_event(self, generation, count, gate_head, event, envelope_bytes):
        self.check(generation, count, gate_head)
        records, _, attempt = self._records()
        if (type(envelope_bytes) is not bytes or canonical(json.loads(envelope_bytes)['payload']) != canonical(event)
                or canonical(json.loads(envelope_bytes)) != envelope_bytes):
            raise ValueError('gate-operation-witness-v3-rejected')
        if (event['generation'] != generation or event['previous'] != gate_head
                or event['kind'] != ['open', 'prepare', 'admit', 'finish', 'close', 'proof'][count]):
            raise ValueError('gate-operation-witness-v3-rejected')
        if event['kind'] == 'prepare':
            attempt = event['data']['ref']
        head = records[-1]['head'] if records else ZERO
        witness_event = dict(binding=self.binding, sequence=count + 1, previousHead=head,
                             kind=['open', 'prepared', 'admitted', 'response', 'completed', 'closed'][count],
                             data=self._data(event, attempt), materialDigest=hashlib.sha256(envelope_bytes).hexdigest())
        return self._client.append_event(expected_seq=count, expected_head=head, event=witness_event,
                                         external_material=envelope_bytes)

    def authenticated_material_after(self, *, seq=0, head=ZERO):
        records, _, _ = self._records()
        if (type(seq) is not int or not 0 <= seq <= len(records)
                or head != (records[seq - 1]['head'] if seq else ZERO)):
            raise ValueError('gate-operation-witness-v3-rejected')
        return dict(records=records[seq:], authorityGranted=False, productionReady=False)
