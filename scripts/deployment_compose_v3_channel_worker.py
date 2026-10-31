"""Fixed synthetic V3 worker: no Docker transport, approval or runtime permit."""
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import struct
import sys
import tempfile
import time

from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, encode, hex_value
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_gate_witness import key_material, opening_scope
from deployment_gateway import FileWriterGate, GatePolicy

LIMIT = 4 * 1024 * 1024
ENTRYPOINT = 'synthetic-gate-v3'


def reject():
    raise ValueError('compose-v3-channel-rejected')


def write_frame(stream, value, timeout=30):
    raw = encode(value)
    if not 0 < len(raw) <= LIMIT: reject()
    pending = memoryview(struct.pack('!I',len(raw)) + raw)
    fd = stream.fileno()
    was_blocking = os.get_blocking(fd)
    deadline = time.monotonic() + timeout
    os.set_blocking(fd,False)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(fd,selectors.EVENT_WRITE)
            while pending:
                remaining = deadline-time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('compose-v3-channel-write-deadline')
                try: count = os.write(fd,pending)
                except BlockingIOError: continue
                if count <= 0: reject()
                pending = pending[count:]
    finally:
        os.set_blocking(fd,was_blocking)


def read_frame(stream, timeout=30):
    deadline = time.monotonic() + timeout
    def exact(size):
        chunks = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(stream, selectors.EVENT_READ)
            while len(chunks) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('compose-v3-channel-deadline')
                chunk = os.read(stream.fileno(), size-len(chunks))
                if not chunk: reject()
                chunks.extend(chunk)
        return bytes(chunks)
    size = struct.unpack('!I', exact(4))[0]
    if not 0 < size <= LIMIT: reject()
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value: reject()
            value[key] = item
        return value
    raw = exact(size)
    value = json.loads(raw, object_pairs_hook=pairs)
    if encode(value) != raw: reject()
    return value


def material(generation, public):
    body = b'{"fixture":"synthetic-non-authorizing-v3"}'
    operations = (('POST', '/v1.45/containers/create?name=dwc-'+'6'*24+'-synthetic', hashlib.sha256(body).hexdigest()),)
    request, receipt, source, cert = '1'*64, '2'*64, '3'*64, '4'*64
    scope = opening_scope(generation, request, receipt, operations, source)
    policy = GatePolicy('synthetic-owned-ssh-v3', 'synthetic-gate-key', '5'*64, cert,
        True, scope, hashlib.sha256(key_material(public)).hexdigest(), operation_profile='compose-v3')
    return policy, operations, body, request, receipt, source, cert


def diagnostic(config, stdin, stdout):
    if (type(config) is not dict or set(config) != {'entrypoint','channelNonce','publicKey','gateKey','binding'}
            or config['entrypoint'] != ENTRYPOINT or not hex_value(config['channelNonce'])):
        reject()
    public = base64.b64decode(config['publicKey'], validate=True)
    key = base64.b64decode(config['gateKey'], validate=True)
    if len(key) != 32: reject()
    binding = config['binding']
    policy, operations, body, request, receipt, source, cert = material(binding['generation'], public)
    if binding['scopeHash'] != policy.witness_scope_hash or binding['policyHash'] != policy.identity_hash(): reject()
    def transport(method, request):
        write_frame(stdout, dict(kind='rpc', channelNonce=config['channelNonce'], service='witness', method=method, request=request))
        reply = read_frame(stdin)
        if (type(reply) is not dict or set(reply) != {'kind','channelNonce','response'}
                or reply['kind'] != 'reply' or reply['channelNonce'] != config['channelNonce']): reject()
        return reply['response']
    client = OperationWitnessClientV3(binding, public, transport)
    with tempfile.TemporaryDirectory(prefix='dw-synthetic-gate-v3-') as directory:
        root = Path(directory).resolve(); root.chmod(0o700)
        gate = FileWriterGate(policy, root/'gate', key=key, witness=GateOperationWitnessAdapterV3(client))
        session = gate.open_generation(generation=binding['generation'],request_hash=request,
            receipt_hash=receipt,operations=operations,source_context_digest=source)
        attempt = session.prepare_attempt(operations[0][0],operations[0][1],body)
        ticket = gate.admit(binding['generation'],attempt.ref,method=attempt.method,path=attempt.path,
                            body=body,writer_certificate_sha256=cert)
        gate.finish_response(ticket,definitive=True,status=201,body=b'{"Id":"synthetic-only"}')
        gate.close_generation(binding['generation'])
        records = client.events_after(seq=0,head='0'*64)
        view = client.read()
        if len(records) != 6 or view['phase'] != 'closed' or view['seq'] != 6: reject()
    return dict(kind='synthetic-gate-v3-diagnostic',success=True,sealedEventCount=6,
        dockerWrites=0,approvalAvailable=False,authorityGranted=False,runtimePermit=False,
        productionReady=False,liveExecutionReusable=False,subjectPlatform=sys.platform)
