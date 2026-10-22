#!/usr/bin/env python3
"""Host-injected, single-component Docker replacement. No local credentials/CLI loader.

An uncertain write is terminal. This backend never retries, cleans up candidates,
pulls an image, or implicitly rolls back. Exported intents are not capabilities.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import http.client
import json
import math
from pathlib import Path
import re
import secrets
import ssl
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve()
sys.path.insert(0, str(SCRIPT.parent))
import deployment_authorize as sdk
import deployment_runtime as runtime
from workflow_lock import LifecycleLock, pending_upgrades

PROFILE = 'docker-container-replace-v1'
MAX_BODY = 1024 * 1024
EXECUTION_LABEL = 'dev-workflow.execution-id'
canonical = runtime.canonical
digest = runtime.digest


class ExecutionError(ValueError):
    """Safe error code and write timing, without daemon/credential/error bodies."""
    def __init__(self, code, *, may_have_mutated=False):
        self.code = code
        self.may_have_mutated = bool(may_have_mutated)
        super().__init__(code)


def _specifications(policy):
    import deployment_spec
    return deployment_spec.parse_specifications(policy.specifications_json)


@dataclass(frozen=True)
class ExecutionPolicy:
    runtime_policy: runtime.RuntimePolicy
    writer_certificate_sha256: str
    stop_timeout: int = 10
    execution_deadline: int = 180

    def __post_init__(self):
        if (type(self.runtime_policy) is not runtime.RuntimePolicy
                or not getattr(self.runtime_policy, 'specifications_json', None)
                or not isinstance(self.writer_certificate_sha256, str)
                or not runtime.HEX.fullmatch(self.writer_certificate_sha256)
                or type(self.stop_timeout) is not int or not 1 <= self.stop_timeout <= 60
                or type(self.execution_deadline) is not int or not 1 <= self.execution_deadline <= 600):
            raise ExecutionError('invalid-execution-policy')
        _specifications(self.runtime_policy)

    def identity_hash(self):
        return digest(dict(profile=PROFILE, runtimePolicyHash=self.runtime_policy.identity_hash(),
                           writerCertificateSha256=self.writer_certificate_sha256,
                           stopTimeout=self.stop_timeout, executionDeadline=self.execution_deadline))


class DockerMutationClient:
    """Fixed writes over pinned mTLS; transport(method,path,body) is a trusted test hook.

    The hook returns (HTTP status, JSON value or None). It represents an already
    authenticated connection. Production always connects and pins before guarding.
    """
    def __init__(self, policy, *, ca_file: Path, cert_file: Path, key_file: Path,
                 timeout=30, transport=None):
        if (type(policy) is not ExecutionPolicy or type(timeout) not in (int, float)
                or not 0 < timeout <= 300):
            raise ExecutionError('invalid-writer-policy')
        self.policy, self.timeout, self._transport = policy, timeout, transport
        self._context = None
        if transport is None:
            try:
                pem = Path(cert_file).read_text(encoding='ascii')
                match = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
                certificate = ssl.PEM_cert_to_DER_cert(match[0])
                if hashlib.sha256(certificate).hexdigest() != policy.writer_certificate_sha256:
                    raise ValueError
                context = ssl.create_default_context(cafile=str(ca_file))
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                context.keylog_filename = None
                context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
                self._context = context
            except Exception:
                raise ExecutionError('writer-credentials-rejected') from None

    def create(self, name, body, *, before_send):
        try:
            frozen = canonical(body)
            if (not isinstance(name, str) or not re.fullmatch(r'dwf-[0-9a-f]{64}', name)
                    or len(frozen.encode('ascii')) > MAX_BODY or not isinstance(body, dict)):
                raise ValueError
            execution_id = body['Labels'][EXECUTION_LABEL]
            if not isinstance(execution_id, str) or not runtime.HEX.fullmatch(execution_id):
                raise ValueError
            if name != 'dwf-' + execution_id:
                raise ValueError
            specs = _specifications(self.policy.runtime_policy)
            if not any(canonical(spec.to_create(self.policy.runtime_policy.project, execution_id)) == frozen
                       for spec in specs.values()):
                raise ValueError
        except Exception:
            raise ExecutionError('create-payload-rejected') from None
        return self._write('POST', '/v1.45/containers/create?' + urlencode({'name': name}),
                           json.loads(frozen), before_send, 201)

    def _container(self, action, container_id, before_send):
        if not isinstance(container_id, str) or not runtime.CONTAINER.fullmatch(container_id):
            raise ExecutionError('container-id-rejected')
        method, suffix = {'stop': ('POST', '/stop?t=' + str(self.policy.stop_timeout)),
                          'remove': ('DELETE', '?force=false&v=false'),
                          'start': ('POST', '/start')}[action]
        return self._write(method, '/v1.45/containers/' + container_id + suffix,
                           None, before_send, 204)

    def stop(self, container_id, *, before_send):
        return self._container('stop', container_id, before_send)

    def remove(self, container_id, *, before_send):
        return self._container('remove', container_id, before_send)

    def start(self, container_id, *, before_send):
        return self._container('start', container_id, before_send)

    def _write(self, method, path, body, before_send, expected):
        if (not callable(before_send) or not (
                (method == 'POST' and expected == 201 and body is not None
                 and re.fullmatch(r'/v1\.45/containers/create\?name=dwf-[0-9a-f]{64}', path))
                or (method == 'POST' and expected == 204 and body is None
                    and re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/(?:start|stop\?t=' + str(self.policy.stop_timeout) + ')', path))
                or (method == 'DELETE' and expected == 204 and body is None
                    and re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}\?force=false&v=false', path)))):
            raise ExecutionError('writer-route-rejected')
        try:
            wire_body = canonical(body).encode('ascii') if body is not None else None
        except Exception:
            raise ExecutionError('writer-payload-rejected') from None
        connection = response = None
        watchdog = None
        timeout = max(self.timeout, self.policy.stop_timeout + 5) if '/stop?' in path else self.timeout
        timeout = min(timeout, self.policy.execution_deadline)
        absolute_deadline = None
        attempted = False
        phase = 'writer-connect-failed'
        try:
            if self._transport is None:
                endpoint = urlsplit(self.policy.runtime_policy.endpoint)
                connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443,
                                                         context=self._context, timeout=timeout)
                connection.connect()
                certificate = connection.sock.getpeercert(binary_form=True)
                if hashlib.sha256(certificate).hexdigest() != self.policy.runtime_policy.server_certificate_sha256:
                    raise ExecutionError('writer-peer-pin-rejected')
            phase = 'execution-guard-rejected'
            supplied_deadline = before_send()
            if type(supplied_deadline) in (int, float):
                remaining = supplied_deadline - time.monotonic()
                if not math.isfinite(supplied_deadline) or remaining <= 0:
                    raise ExecutionError('execution-deadline-exceeded')
                absolute_deadline = supplied_deadline
                timeout = min(timeout, remaining)
                if connection is not None and connection.sock is not None:
                    connection.sock.settimeout(timeout)
            phase = 'writer-response-unknown'
            attempted = True
            if self._transport is not None:
                status, value = self._transport(method, path, body)
                raw = canonical(value).encode('ascii') if value is not None else b''
            else:
                # Inactivity limits do not bound trickled status/header bytes.
                # Abort this connection at the total budget; the Docker write
                # still has an uncertain outcome and is never retried.
                peer = connection.sock
                response_deadline = min(time.monotonic() + timeout,
                    absolute_deadline if absolute_deadline is not None else float('inf'))
                watchdog = runtime.deadline_watchdog(peer, response_deadline)
                if time.monotonic() >= response_deadline:
                    raise ExecutionError('writer-response-unknown', may_have_mutated=True)
                connection.request(method, path, body=wire_body,
                                   headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
                response = connection.getresponse()
                status = response.status
                # Bounded overall response read, including slow streaming peers.
                deadline = response_deadline
                raw = bytearray()
                while len(raw) <= MAX_BODY:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError
                    if connection.sock is not None:
                        connection.sock.settimeout(remaining)
                    part = response.read1(min(65536, MAX_BODY + 1 - len(raw)))
                    if not part:
                        break
                    raw.extend(part)
                if time.monotonic() >= deadline:
                    raise ExecutionError('writer-response-unknown', may_have_mutated=True)
            if len(raw) > MAX_BODY or status != expected:
                raise ExecutionError('writer-http-rejected', may_have_mutated=True)
            if expected == 201:
                value = runtime.parse_json(bytes(raw).decode('utf-8'))
                if (not isinstance(value, dict) or not isinstance(value.get('Id'), str)
                        or not runtime.CONTAINER.fullmatch(value['Id'])
                        or value.get('Warnings') not in (None, [])):
                    raise ExecutionError('create-response-unverified', may_have_mutated=True)
                return value
            if raw:
                raise ExecutionError('writer-response-unverified', may_have_mutated=True)
            return None
        except ExecutionError as error:
            if attempted and not error.may_have_mutated:
                raise ExecutionError('writer-response-unknown', may_have_mutated=True) from None
            raise
        except Exception:
            raise ExecutionError(phase, may_have_mutated=attempted) from None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


@dataclass(frozen=True, eq=False)
class ExecutionIntent:
    binding_json: str
    _issuer: object

    @property
    def policy_hash(self):
        return json.loads(self.binding_json)['policyHash']

    def validate(self, root, plan, operation, collector, observation, rollback_target=None):
        if type(self._issuer) is not DockerExecutor:
            raise ExecutionError('intent-issuer-rejected')
        DockerExecutor._validate_intent(self._issuer, self, root, plan, operation, collector, observation, rollback_target)


def _request_scope(request):
    # Expiry is supplied by the authorizing host later. Every other SDK field is
    # fixed at preparation, including the original observation and full mapping.
    from dataclasses import asdict
    value = asdict(request)
    value.pop('expires_at')
    value.pop('execution_json', None)
    return canonical(value)


class DockerExecutor:
    def __init__(self, policy, client, collector):
        if (type(policy) is not ExecutionPolicy or type(client) is not DockerMutationClient
                or type(collector) is not runtime.TrustedDockerCollector
                or client.policy != policy or collector.policy != policy.runtime_policy
                or collector.client.policy != policy.runtime_policy):
            raise ExecutionError('executor-policy-mismatch')
        self.policy, self.client, self.collector = policy, client, collector
        self._policy_hash = policy.identity_hash()
        self._issued, self._lock = {}, threading.Lock()

    def _fixed(self):
        if (self.policy.identity_hash() != self._policy_hash or self.client.policy != self.policy
                or self.collector.policy != self.policy.runtime_policy
                or self.collector.client.policy != self.policy.runtime_policy):
            raise ExecutionError('executor-policy-changed')

    def _request(self, root, plan, operation, observation, rollback_target, expires_at=None):
        return sdk.build_request(root, plan, operation, collector=self.collector, observation=observation,
                                 rollback_target=rollback_target,
                                 repository_slug=self.policy.runtime_policy.repository, repository_id=1,
                                 expires_at=expires_at or (sdk.clock() + timedelta(minutes=1)).isoformat())

    def _inventory(self, deadline):
        self._fixed()
        reader = self.collector.client
        def read(path):
            if time.monotonic() >= deadline:
                raise ExecutionError('execution-deadline-exceeded')
            result = reader.get(path, deadline=deadline)
            if time.monotonic() >= deadline:
                raise ExecutionError('execution-deadline-exceeded')
            return result
        if read('/v1.45/info').get('ID') != self.policy.runtime_policy.daemon_id:
            raise ExecutionError('daemon-identity-changed')
        listed = read(reader.list_path)
        if not isinstance(listed, list):
            raise ExecutionError('inventory-invalid')
        result = {}
        for item in listed:
            cid = item.get('Id') if isinstance(item, dict) else None
            if not isinstance(cid, str) or not runtime.CONTAINER.fullmatch(cid) or cid in result:
                raise ExecutionError('inventory-invalid')
            container = read('/v1.45/containers/' + cid + '/json')
            labels = container.get('Config', {}).get('Labels', {})
            if (container.get('Id') != cid or labels != item.get('Labels')
                    or labels.get('com.docker.compose.project') != self.policy.runtime_policy.project):
                raise ExecutionError('inventory-scope-changed')
            # Inspect paths alone do not prove Docker-managed file contents.
            # Newly created / stopped containers have no active configuration;
            # active unselected instances must retain their exact file bytes.
            managed = None
            if container.get('State', {}).get('Running') is True:
                managed = {}
                for name in runtime.MANAGED_FILES:
                    if time.monotonic() >= deadline:
                        raise ExecutionError('execution-deadline-exceeded')
                    content = reader.managed_file(cid, name, deadline=deadline)
                    managed[name] = hashlib.sha256(content).hexdigest()
            container['_workflowManagedFiles'] = managed
            result[cid] = container
        return result

    def _image(self, record, deadline):
        spec, entry = record['spec'], record['entry']
        image = self.collector.client.get('/v1.45/images/' + spec.image_id + '/json', deadline=deadline)
        if (image.get('Id') != spec.image_id or image.get('Os') != 'linux'
                or image.get('Os') != entry['os'] or image.get('Architecture') != entry['architecture']
                or (entry['artifact']['kind'] == 'registry'
                    and entry['artifact']['ref'] not in (image.get('RepoDigests') or []))):
            raise ExecutionError('preloaded-image-unverified')
        host = spec.to_dict()['hostConfig']
        rebuilt = type(spec).from_image(spec.component, image, network_mode=host['NetworkMode'],
                                        port_bindings=host['PortBindings'])
        if rebuilt.configuration_digest() != spec.configuration_digest():
            raise ExecutionError('preloaded-image-specification-mismatch')
        if 'image' in record and canonical(image) != record['image']:
            raise ExecutionError('preloaded-image-changed')
        if time.monotonic() >= deadline:
            raise ExecutionError('execution-deadline-exceeded')
        return canonical(image)

    def prepare(self, root, plan, operation, *, observation, rollback_target=None):
        self._fixed()
        root = Path(root).resolve()
        frozen = canonical(plan)
        request = self._request(root, json.loads(frozen), operation, observation, rollback_target)
        if len(request.components) != 1:
            raise ExecutionError('exactly-one-component-required')
        component = request.components[0]
        desired = next(item for item in json.loads(request.after_json)['components'] if item['name'] == component)
        candidates = [entry for (name, _), entry in runtime._catalog(self.policy.runtime_policy).items()
                      if name == component and entry['sourceSha'] == desired['sourceSha']
                      and entry['artifact'] == desired['artifact'] and entry['migration']['mode'] == 'none']
        if len(candidates) != 1:
            raise ExecutionError('desired-image-catalog-unverified')
        entry = candidates[0]
        spec = _specifications(self.policy.runtime_policy).get((component, entry['imageId']))
        if spec is None or spec.configuration_digest() != desired['configurationDigest']:
            raise ExecutionError('desired-specification-unverified')
        self.collector.recheck(observation)
        deadline = time.monotonic() + self.policy.runtime_policy.capture_deadline
        baseline = self._inventory(deadline)
        second = self._inventory(deadline)
        if canonical(baseline) != canonical(second):
            raise ExecutionError('runtime-changed-during-preparation')
        instances = observation.to_dict()['instances']
        old_ids = [item['containerId'] for item in instances if item['component'] == component]
        if len(old_ids) != 1 or old_ids[0] not in baseline:
            raise ExecutionError('baseline-instance-unverified')
        for item in instances:
            actual = baseline.get(item['containerId'], {})
            state = actual.get('State', {})
            if (actual.get('Image') != item['imageId'] or state.get('Pid') != item['pid']
                    or state.get('StartedAt') != item['startedAt']):
                raise ExecutionError('baseline-instance-changed')
        # Close the gap between collector proof and private raw fingerprints.
        self.collector.recheck(observation)
        if canonical(baseline) != canonical(self._inventory(deadline)):
            raise ExecutionError('runtime-changed-during-preparation')
        nonce = secrets.token_hex(32)
        binding = dict(schemaVersion=1, profile=PROFILE, policyHash=self._policy_hash, intentId=nonce,
                       specHash=spec.configuration_digest(), component=component, imageId=spec.image_id,
                       beforeContainerId=old_ids[0], resourceName='dwf-' + nonce,
                       actions=['create', 'stop', 'remove', 'start'])
        intent = ExecutionIntent(canonical(binding), self)
        # Repository ID is supplied by the host, not a Docker scope identity.
        scope = json.loads(_request_scope(request))
        scope.pop('repository_id')
        record = dict(intent=intent, binding=intent.binding_json, root=root, plan=frozen, operation=operation,
                      observation=observation, rollback_target=rollback_target, scope=canonical(scope),
                      spec=spec, entry=entry, baseline=canonical(baseline), used=False)
        record['image'] = self._image(record, deadline)
        with self._lock:
            self._issued[id(intent)] = record
        return intent

    def _validate_intent(self, intent, root, plan, operation, collector, observation, rollback_target):
        self._fixed()
        record = self._issued.get(id(intent))
        if (type(intent) is not ExecutionIntent or record is None or record['intent'] is not intent
                or intent._issuer is not self or intent.binding_json != record['binding']
                or Path(root).resolve() != record['root'] or canonical(plan) != record['plan']
                or operation != record['operation'] or collector is not self.collector
                or observation is not record['observation'] or rollback_target is not record['rollback_target']):
            raise ExecutionError('intent-not-issued-for-scope')
        if record['used'] and not record.get('active', False):
            raise ExecutionError('intent-already-dispatched')
        request = self._request(root, plan, operation, observation, rollback_target)
        scope = json.loads(_request_scope(request))
        scope.pop('repository_id')
        if canonical(scope) != record['scope']:
            raise ExecutionError('intent-scope-changed')

    @staticmethod
    def _stopped(container, *, created=False):
        state = container.get('State', {})
        return (state.get('Running') is False and state.get('Pid') == 0
                and state.get('Paused') is False and state.get('Restarting') is False
                and state.get('Dead') is False
                and state.get('Status') in (('created',) if created else ('exited',)))

    @staticmethod
    def _running(container):
        state = container.get('State', {})
        return (state.get('Running') is True and type(state.get('Pid')) is int and state['Pid'] > 0
                and state.get('Paused') is False and state.get('Restarting') is False
                and state.get('Dead') is False and state.get('Status') == 'running'
                and isinstance(state.get('StartedAt'), str) and state['StartedAt'][:4].isdigit()
                and int(state['StartedAt'][:4]) >= 1970)

    def _stage(self, record, stage, new_id, deadline):
        baseline = json.loads(record['baseline'])
        binding = json.loads(record['binding'])
        old_id = binding['beforeContainerId']
        current = self._inventory(deadline)
        expected = set(baseline)
        if stage >= 1:
            expected.add(new_id)
        if stage >= 3:
            expected.remove(old_id)
        if set(current) != expected:
            raise ExecutionError('project-inventory-changed')
        for cid, before in baseline.items():
            if cid == old_id and stage >= 2:
                if stage >= 3:
                    continue
                after = current[cid]
                # Docker updates State/network bookkeeping on stop. Application
                # configuration, image, mounts, start identity and restart count
                # must still prove this is the same stopped old container.
                fields = ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'Created', 'Name',
                          'Path', 'Args', 'RestartCount', 'HostsPath', 'HostnamePath', 'ResolvConfPath')
                if (any(after.get(key) != before.get(key) for key in fields)
                        or after.get('State', {}).get('StartedAt') != before['State']['StartedAt']
                        or not self._stopped(after)):
                    raise ExecutionError('old-container-changed')
            elif canonical(current[cid]) != canonical(before):
                raise ExecutionError('baseline-container-drift')
        if stage >= 1:
            new = current[new_id]
            if (not record['spec'].matches(new)
                    or new.get('Config', {}).get('Labels', {}).get(EXECUTION_LABEL) != binding['intentId']
                    or new.get('Config', {}).get('Labels', {}).get('dev-workflow.spec') != binding['specHash']
                    or new.get('Config', {}).get('Labels', {}).get('com.docker.compose.project') != self.policy.runtime_policy.project
                    or new.get('Config', {}).get('Labels', {}).get('com.docker.compose.service') != binding['component']
                    or new.get('Name') != '/' + binding['resourceName']
                    or new.get('RestartCount') != 0
                    or not (self._running(new) if stage == 4 else self._stopped(new, created=True))):
                raise ExecutionError('candidate-container-unverified')
            key = 'running' if stage == 4 else 'created'
            if key in record and canonical(new) != record[key]:
                raise ExecutionError('candidate-container-drift')
            record.setdefault(key, canonical(new))
        self._image(record, deadline)
        self._fixed()
        if time.monotonic() >= deadline:
            raise ExecutionError('execution-deadline-exceeded')

    def execute(self, root, permit, intent):
        if type(permit) is not sdk.DeploymentPermit or type(intent) is not ExecutionIntent:
            raise ExecutionError('execution-capability-required')
        record = self._issued.get(id(intent))
        if record is None:
            raise ExecutionError('intent-not-issued-for-scope')
        intent.validate(root, json.loads(record['plan']), record['operation'], self.collector,
                        record['observation'], record['rollback_target'])
        request = permit.request
        scope = json.loads(_request_scope(request))
        scope.pop('repository_id')
        if (type(request) is not sdk.Request or getattr(request, 'execution_json', None) != intent.binding_json
                or canonical(scope) != record['scope']):
            raise ExecutionError('permit-execution-binding-mismatch')
        root = Path(root).resolve()
        binding = json.loads(intent.binding_json)
        relative = sdk.RECORDS + 'execution-' + binding['intentId'] + '.json'
        result = dict(schemaVersion=1, kind='deployment-execution-result', profile=PROFILE,
                      policyHash=self._policy_hash, intentId=binding['intentId'], requestHash=request.digest(),
                      operation=request.operation, component=binding['component'], resourceName=binding['resourceName'],
                      imageId=binding['imageId'], specHash=binding['specHash'],
                      beforeContainerId=binding['beforeContainerId'], containerId=None,
                      executionAvailable=True, productionReady=False, status='pending', execution='not-performed',
                      authorizationConsumed=True, reconcileRequired=False, actions=[], lastAction=None,
                      verification=dict(runtime='unknown', deployment='unknown', rollback='unknown',
                                        health='unknown', smoke='unknown', backup='unknown'))
        with LifecycleLock(root, 'deployment-execution'):
            if pending_upgrades(root):
                raise ExecutionError('unfinished-upgrade')
            sdk._assert_output(root, relative)
            with self._lock:
                if record['used']:
                    raise ExecutionError('intent-already-dispatched')
                # No second grant can resurrect an intent after a claim attempt.
                record['used'] = True
                record['active'] = True
            stage, new_id, attempted, completed = 0, None, False, 0
            deadline = time.monotonic() + self.policy.execution_deadline
            try:
                sdk._audit(root, relative, result)
                permit.claim_for_dispatch()
                for action in binding['actions']:
                    result['lastAction'] = action
                    action_record = dict(action=action, status='guard-pending')
                    result['actions'].append(action_record)
                    sdk._audit(root, relative, result)
                    def before_send():
                        # Persist before the final authority/runtime guard. No disk
                        # or network work is allowed between that guard and send.
                        action_record['status'] = 'dispatch-attempted'
                        sdk._audit(root, relative, result)
                        permit.guard_for_execution(runtime_check=lambda: self._stage(record, stage, new_id, deadline))
                        return deadline
                    try:
                        if action == 'create':
                            response = self.client.create(binding['resourceName'],
                                record['spec'].to_create(self.policy.runtime_policy.project, binding['intentId']),
                                before_send=before_send)
                            new_id = response['Id']
                            result['containerId'] = new_id
                            if new_id in json.loads(record['baseline']):
                                raise ExecutionError('create-returned-existing-id', may_have_mutated=True)
                        else:
                            getattr(self.client, action)(new_id if action == 'start' else binding['beforeContainerId'],
                                                         before_send=before_send)
                    except ExecutionError as error:
                        attempted = attempted or error.may_have_mutated
                        action_record['status'] = 'unknown' if error.may_have_mutated else 'not-sent'
                        raise
                    attempted = True
                    completed += 1
                    stage += 1
                    action_record['status'] = 'response-verified'
                    sdk._audit(root, relative, result)
                    self._stage(record, stage, new_id, deadline)
                observation = self.collector.collect()
                self.collector.validate(observation)
                actual = sdk.ordered(observation.snapshot()['components'])
                if actual != sdk.ordered(json.loads(request.after_json)['components']):
                    raise ExecutionError('final-runtime-mapping-mismatch')
                permit.guard_for_execution(runtime_check=lambda: self._stage(record, 4, new_id, deadline))
                result.update(status='executed-verified', execution='performed',
                              declaredVersion=json.loads(request.after_json)['version'],
                              runtimeVersion=observation.snapshot()['version'], runtimeObservation=observation.to_dict())
                result['verification']['runtime'] = 'verified'
                result['verification']['deployment' if request.operation == 'deployment-deploy' else 'rollback'] = 'verified'
                sdk._audit(root, relative, result)
                # Keep actual collector-issued proof for a fresh, separate rollback
                # preparation. Audit/export above contains only its JSON evidence.
                return dict(result, observation=observation)
            except Exception as error:
                unknown = isinstance(error, ExecutionError) and error.may_have_mutated
                result.update(status='unknown' if unknown else ('executed-unverified' if completed else 'failed'),
                              execution='unknown' if unknown else ('performed' if completed else 'not-performed'),
                              failureCode=error.code if isinstance(error, ExecutionError) else 'execution-validation-rejected',
                              reconcileRequired=attempted)
                sdk._audit(root, relative, result)
                return result
            finally:
                record['active'] = False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'execute'))
    args = parser.parse_args(argv)
    result = dict(trustedBackendAvailable=True, executionAvailable=False, productionReady=False,
                  profile=PROFILE, mode='trusted-host-injection-required')
    if args.action == 'execute':
        result['error'] = 'Trusted execution host required'
    print(json.dumps(result, sort_keys=True))
    return int(args.action == 'execute')


if __name__ == '__main__':
    sys.exit(main())
