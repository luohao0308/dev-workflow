"""Disposable historical executor; parent owns Engine and signed witness service."""
import json
from dataclasses import asdict
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT/'scripts'), str(ROOT/'packs/deployment/scripts'), str(ROOT/'packs/release/scripts')]
from tests.test_deployment_compose_history_v3_host import HistoryTests
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_image_defaults import ZERO_DEFAULTS
from deployment_compose_reader_host import _UnixDocker
from deployment_contract_v2 import RequestV2
from deployment_gateway import GatePolicy


def send(value):
    print(json.dumps(value), flush=True)


def run(spec):
    h = HistoryTests('test_two_scopes_and_no_local_files')
    sys.platform = 'linux'  # Same explicit host-platform seam as GateFixture.
    h.root = Path(spec['root'])
    h.public = bytes.fromhex(spec['public'])
    value = spec['bundle']
    for key in ('operations', 'resolverRules', 'resolverContract', 'imageDefaultsDigests'): value.pop(key)
    h.bundle = ExecutionBundleV3(value, authenticated_image_defaults={s['name']: ZERO_DEFAULTS for s in value['services']})
    h.req = RequestV2.from_json(json.dumps(spec['request'], sort_keys=True, separators=(',', ':')))
    h.policy = GatePolicy(**spec['policy'])
    h.binding = spec['binding']; h.receipt = spec['receipt']; h.cert = spec['cert']; h.receipts = {}
    def transport(method, request):
        send(dict(kind='rpc', method=method, request=request))
        return json.loads(sys.stdin.readline())
    h.transport = transport
    for index, op in enumerate(spec['operations']):
        h.index = index; h.open_scope()
        ticket = h.admitted(h.current_gate)
        connection = _UnixDocker(spec['socket'], 3)
        try:
            body = b'' if op['body'] is None else json.dumps(op['body'], sort_keys=True, separators=(',', ':')).encode('ascii')
            connection.request(op['method'], op['path'], body=body)
            response = connection.getresponse(); status = response.status; body = response.read()
        finally:
            connection.close()
        if not spec['unknown']:
            h.current_gate.finish_response(ticket, definitive=True, status=status, body=body)
            h.current_gate.close_generation(h.gen)
        if op['phase'] == 'create': h.receipts[op['service']] = json.loads(body)['Id']
    send(dict(kind='checkpoint', binding=h.binding, policy=asdict(h.policy), receipts=h.receipts))
    # The supervisor must kill and reap this executor; normal cleanup is forbidden.
    while True: time.sleep(60)


if __name__ == '__main__':
    run(json.loads(sys.stdin.readline()))
