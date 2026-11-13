"""Fixed native worker session for a source-verified retained frontend deployment."""
import base64
import hashlib
from pathlib import Path
import sys
import tempfile

from deployment_compose_host_snapshot_v3_host import HostSnapshotV3
from deployment_compose_live_worker_v3_host import writer_tls
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, encode, hex_value
from deployment_compose_production_caddy_probe_v1_host import ProductionCaddyProbeV1
from deployment_compose_production_scope_v1_host import ScopeRegistrationV1
from deployment_compose_retained_frontend_worker_v1_host import (
    POST_WRITE_OBSERVATION_STAGES, RetainedFrontendWorkerV1, RetainedPostWriteObservationFailed,
)
from deployment_compose_retained_intent_relay_v1_host import (
    ConsumedReceiptRejected, RetainedIntentBindingV1, RetainedIntentClientV1,
)
from deployment_compose_retained_source_v1_host import check_loaded_source
from deployment_compose_retained_write_v1_host import RetainedDockerWriteUncertain, RetainedWriteV1
from deployment_compose_write_gateway_v3_host import ADMITTED_FAILURE_STAGES
from deployment_compose_v3_channel_worker import read_frame, write_frame
from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material
from deployment_gateway import GatePolicy

CONFIGURE = {'privatePlan', 'operationNonce', 'policyHash', 'intentPublicKey',
             'witnessPublicKey', 'gateKey', 'caddyId', 'networkId'}
BLOCKED_FIELDS = {'knownPrefix', 'failureStage'}
FAILURE_STAGES = frozenset((
    'parse-request', 'validate-intent', 'verify-consumed-receipt', 'execute-worker', 'prepare-restore',
)) | ADMITTED_FAILURE_STAGES | POST_WRITE_OBSERVATION_STAGES
# Leave time for the controller to close the session after its 15-minute review wait.
REVIEW_COMMAND_TIMEOUT = 1020


def reject():
    raise ValueError('retained-production-native-channel-rejected') from None


class _Channel:
    def __init__(self, nonce, stdin, stdout):
        if not hex_value(nonce):
            reject()
        self.nonce, self.stdin, self.stdout = nonce, stdin, stdout

    def emit(self, kind, **fields):
        write_frame(self.stdout, dict(kind=kind, channelNonce=self.nonce, **fields), timeout=30)

    def receive(self, *shapes, timeout=900):
        value = read_frame(self.stdin, timeout=timeout)
        if type(value) is not dict or value.get('channelNonce') != self.nonce:
            reject()
        for kind, fields in shapes:
            if value.get('kind') == kind and set(value) == {'kind', 'channelNonce'} | set(fields):
                return kind, {key: value[key] for key in fields}
        reject()

    def rpc(self, service, method, request):
        self.emit('rpc', service=service, method=method, request=request)
        _, frame = self.receive(('reply', {'response'}), timeout=90)
        return frame['response']

    def consume(self, request, before_consume):
        self.emit('rpc', service='intent', method='authorize', request=request)
        fields = {'nonce', 'requestHash', 'scopeGeneration'}
        _, challenge = self.receive(('consume-check', fields), timeout=90)
        if (not hex_value(challenge['nonce']) or challenge['requestHash'] != request['requestHash']
                or type(challenge['scopeGeneration']) is not int
                or challenge['scopeGeneration'] != request['generation']):
            reject()
        before_consume()
        self.emit('consume-confirmed', **challenge)
        _, frame = self.receive(('reply', {'response'}), timeout=90)
        return frame['response']


def _binary(value):
    if type(value) is not str or not 0 < len(value) <= 8192:
        reject()
    return base64.b64decode(value, validate=True)


def run_channel(config, receipt, observer, registration, *, stdin=None, stdout=None):
    """Run a single deploy and optional separately approved live restoration."""
    if type(observer) is not HostSnapshotV3 or type(registration) is not ScopeRegistrationV1:
        reject()
    source = check_loaded_source(receipt)
    nonce = source['channelNonce']
    if config['channelNonce'] != nonce:
        reject()
    channel = _Channel(nonce, sys.stdin.buffer if stdin is None else stdin,
                       sys.stdout.buffer if stdout is None else stdout)
    _, data = channel.receive(('configure', CONFIGURE))
    if any(not hex_value(data[key]) for key in ('operationNonce', 'policyHash', 'caddyId', 'networkId')):
        reject()
    intent_public = key_material(_binary(data['intentPublicKey']))
    witness_public = key_material(_binary(data['witnessPublicKey']))
    gate_key = _binary(data['gateKey'])
    if len(gate_key) != 32:
        reject()
    plan = data['privatePlan']
    if (data['caddyId'] not in plan['publicReview']['protectedContainerIds']
            or plan['privateBody']['NetworkingConfig']['EndpointsConfig']['luohao-blog-prod_default']['NetworkID'] != data['networkId']):
        reject()
    readiness = ProductionCaddyProbeV1(observer, caddy_id=data['caddyId'], network_id=data['networkId'])
    with tempfile.TemporaryDirectory(prefix='dw-retained-tls-', dir=config['workDirectory']) as directory:
        server_tls, client_tls, server_pin, writer_pin = writer_tls(Path(directory).resolve())
        witness_hash = hashlib.sha256(witness_public).hexdigest()

        def factory(bound_observer, first, request_hash, receipt_hash, execution_digest):
            descriptor = RetainedWriteV1.scope_descriptor(first, request_hash=request_hash,
                receipt_hash=receipt_hash, plan_digest=execution_digest, index=0)
            policy = GatePolicy('blog-retained', 'retained-' + nonce[:16], data['policyHash'], writer_pin,
                True, descriptor['scopeHash'], witness_hash, operation_profile='compose-v3')
            binding = channel.rpc('witness', 'register', dict(requestHash=request_hash, receiptHash=receipt_hash,
                executionDigest=execution_digest, scopeGeneration=worker._lease.generation))
            return RetainedWriteV1(gate_policy=policy, gate_root=registration.root/('gate-' + request_hash),
                gate_key=gate_key, witness_client_factory=lambda exact: OperationWitnessClientV3(
                    exact, witness_public, lambda method, request: channel.rpc('witness', method, request)),
                registered_binding=binding, tls_server_context=server_tls, tls_client_context=client_tls,
                server_certificate_sha256=server_pin, observer=bound_observer, timeout=120)

        worker = RetainedFrontendWorkerV1(plan, operation_nonce=data['operationNonce'], observer=observer,
            registration=registration, writer_source_sha=source['sourceSha'], writer_archive_digest=source['archiveDigest'],
            policy_hash=data['policyHash'], witness_transport_factory=factory, readiness=readiness,
            loaded_source=receipt)
        try:
            deploy_review = worker.deploy_review()
            channel.emit('prepared', review=deploy_review, writerCertificateSha256=writer_pin)

            def execute(frame, review, operation):
                stage = 'parse-request'
                try:
                    request = RequestV2.from_json(encode(frame['request']).decode('ascii'))
                    if request.operation != operation:
                        reject()
                    stage = 'validate-intent'
                    binding = RetainedIntentBindingV1(nonce, source['sourceSha'], source['archiveDigest'],
                        source['originDigest'], review['retainedCutover']['protectionDigest'])
                    client = RetainedIntentClientV1(request, binding=binding, public_key=intent_public,
                        transport=lambda rpc: channel.rpc('intent', 'authorize', rpc), consume_transport=channel.consume)
                    grant = client.validate(request)
                    stage = 'execute-worker'
                    result = worker.deploy(client, grant, request) if operation == 'deploy' else worker.restore(client, grant, request)
                except ConsumedReceiptRejected:
                    return 'verify-consumed-receipt'
                except RetainedDockerWriteUncertain as error:
                    return error.stage
                except RetainedPostWriteObservationFailed as error:
                    return error.stage
                except Exception:
                    return stage
                channel.emit('executed', result=result)
                return None

            kind, frame = channel.receive(('execute', {'request'}), ('finish', set()),
                                          timeout=REVIEW_COMMAND_TIMEOUT)
            if kind == 'finish':
                return
            failure = execute(frame, deploy_review, 'deploy')
            # Only a worker-owned, exact closed prefix can yield a restore
            # review. An uncertain request leaves the scope journal pending.
            try:
                restore_review = worker.restore_review()
            except Exception:
                channel.emit('blocked', knownPrefix=False, failureStage=failure or 'prepare-restore')
                return
            channel.emit('restore-prepared', review=restore_review)
            kind, frame = channel.receive(('execute', {'request'}), ('finish', set()),
                                          timeout=REVIEW_COMMAND_TIMEOUT)
            if kind == 'execute':
                failure = execute(frame, restore_review, 'rollback')
                if failure is not None:
                    channel.emit('blocked', knownPrefix=False, failureStage=failure)
        finally:
            worker.close()
