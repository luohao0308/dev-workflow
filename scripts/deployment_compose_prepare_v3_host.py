"""Host authenticated unsigned full-body intent. No permit or execution API.

Constructor material is private host configuration. Results contain secrets;
only ``review`` is suitable for publication. Authentication here does not prove
machine enrollment, build provenance, reconstruction, or coordinator admission.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import inspect
import hmac
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity
from deployment_compose_bundle_v3 import ExecutionBundleV3, PROFILE, PROFILE_VERSION, _encode
from deployment_compose_image_defaults import derive_defaults, ZERO_DEFAULTS
from deployment_compose_observation_host import ComposeObservationHost
from deployment_compose_recovery_host import ComposeRecoveryHost
from deployment_compose_operations import BaselineContainer, _topological
from deployment_compose_restore_body_host import compile_retained_restore_body
from deployment_compose_private import commit, MOUNT
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, protected_state_digest, baseline_state_bytes, baseline_state_digest
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3


def _fail():
    raise ValueError('compose-preparation-v3-rejected')


def _digest(value):
    return hashlib.sha256(_encode(value)).hexdigest()


class ComposePreparationHostV3:
    def __init__(self, *, whole_observer, recovery, retention_observer, baseline,
                 source_inputs, target_inputs, source, target, host_id, daemon_id,
                 environment, policy_hash, dependencies, protected_names,
                 protected_ids, protected_hashes, archive_reference, protected_private_keys=None, phase_state_producer=None, production=False):
        try:
            if (type(whole_observer) is not ComposeObservationHost
                    or whole_observer.scope_kind != 'whole-project'
                    or type(retention_observer) is not ComposeObservationHost
                    or type(recovery) is not ComposeRecoveryHost
                    or recovery._observer is not retention_observer
                    or type(source) is not SourceIdentity or type(target) is not TargetIdentity
                    or target.runtime != 'compose' or not target.namespace.startswith('dw-')
                    or production is not False or type(baseline) is not tuple
                    or not 1 <= len(baseline) <= 16
                    or any(type(b) is not BaselineContainer for b in baseline)):
                _fail()
            services = tuple(b.service for b in baseline)
            if (len(set(services)) != len(services) or recovery._baseline != baseline
                    or type(source_inputs) is not dict or set(source_inputs) != set(services)
                    or type(target_inputs) is not dict or set(target_inputs) != set(services)):
                _fail()
            _topological(services, dependencies)
            scope = whole_observer._policy
            for observer in (whole_observer, retention_observer):
                p = observer._policy
                if (p.get('project') != target.namespace or p.get('daemonId') != daemon_id
                        or tuple(p.get('selectedServices', ())) != services
                        or p.get('selectedContainerIds') != {b.service:b.container_id for b in baseline}
                        or any(p.get('containerNames', {}).get(b.service) != b.final_name for b in baseline)
                        or observer._baseline_artifacts != whole_observer._baseline_artifacts):
                    _fail()
            protected = scope.get('protectedServices')
            if (type(protected) is not list or any(type(v) is not dict or set(v) != set(protected)
                    for v in (protected_names, protected_ids, protected_hashes))
                    or scope.get('protectedContainerIds', {}) != protected_ids
                    or scope.get('protectedConfigHmacs', {}) != protected_hashes
                    or any(scope.get('containerNames', {}).get(n) != protected_names[n] for n in protected)
                    or len(set([b.final_name for b in baseline] + list(protected_names.values()))) != len(baseline)+len(protected)):
                _fail()
            for observer in (retention_observer,):
                for key in ('protectedServices','protectedContainerIds','protectedConfigHmacs','imageIds'):
                    if observer._policy.get(key, {}) != scope.get(key, {}):
                        _fail()
                if any(observer._policy.get('containerNames', {}).get(n) != protected_names[n] for n in protected):
                    _fail()
            allowed = set(inspect.signature(compile_retained_restore_body).parameters) - {'recovery','reference','observer','observation','service','operation_nonce'}
            for b in baseline:
                si, ti = source_inputs[b.service], target_inputs[b.service]
                if (type(si) is not dict or set(si)-allowed or type(ti) is not dict
                        or set(ti) != {'image','commitment','key','expected_key_id','expected_image_id','expected_registry_digest','expected_architecture'}
                        or any(type(k) is not bytes or not 32 <= len(k) <= 4096 for k in (si['private_key'],si['image_key'],si['declaration_key'],ti['key']))
                        or any(si['identity'].get(k) != v for k,v in dict(hostId=host_id,daemonId=daemon_id,project=target.namespace,service=b.service,containerId=b.container_id,containerName=b.final_name,imageId=b.image_id).items())):
                    _fail()
            self._whole, self._retention, self._recovery = whole_observer, retention_observer, recovery
            self._baseline, self._source, self._target = baseline, source, target
            self._source_inputs, self._target_inputs = deepcopy((source_inputs, target_inputs))
            self._host, self._daemon, self._environment, self._policy = host_id, daemon_id, environment, policy_hash
            self._dependencies, self._names, self._ids, self._hashes = deepcopy((dependencies,protected_names,protected_ids,protected_hashes))
            if protected_private_keys is None:
                protected_private_keys = {}
            if (type(protected_private_keys) is not dict or set(protected_private_keys) != set(protected)
                    or any(type(v) is not tuple or len(v) != 2 or type(v[0]) is not str
                           or type(v[1]) is not bytes or not 32 <= len(v[1]) <= 4096
                           for v in protected_private_keys.values())):
                _fail()
            if (type(phase_state_producer) is not TrustedPhaseStateProducerV3
                    or phase_state_producer.project != target.namespace
                    or phase_state_producer.daemon_id != daemon_id
                    or phase_state_producer.container_ids != tuple(sorted(
                        [b.container_id for b in baseline] + list(protected_ids.values())))):
                _fail()
            self._phase_state = phase_state_producer
            self._protected_keys = deepcopy(protected_private_keys)
            self._reference = archive_reference
            self._scopes = deepcopy((whole_observer._policy,retention_observer._policy))
            self._artifacts = deepcopy(whole_observer._baseline_artifacts)
        except Exception:
            _fail()

    def _protected_state_pins(self, observation):
        """Bind private host captures to authenticated HMAC and instance pins.

        The public observer remains masked. Only the explicit host Unix producer
        supplies full rows; no caller digest or network-reader raw JSON is trusted.
        """
        self._whole.commitment(observation)
        ids = {b.service:b.container_id for b in self._baseline} | self._ids
        captures = []
        for _ in range(2):
            rows, instances, pins = {}, {}, {}
            captured = self._phase_state.capture()
            for service, cid in sorted(ids.items()):
                row = captured[cid]
                if (row['Id'] != cid or row['Image'] != self._scopes[0]['imageIds'][service]
                        or row['Name'] != '/' + self._scopes[0]['containerNames'][service]
                        or row['Config']['Labels']['com.docker.compose.project'] != self._target.namespace
                        or row['Config']['Labels']['com.docker.compose.service'] != service):
                    _fail()
                PhaseGuardV3._healthy(row)
                instances[cid] = (row['State']['Pid'],row['State']['StartedAt'],row['RestartCount'])
                if service in self._ids:
                    projection = {k:row[k] for k in ('Config','HostConfig','Mounts','NetworkSettings')}
                    # Match the authenticated gateway's commitment projection;
                    # keep the original raw rows unchanged for lifecycle retention.
                    projection['Mounts'] = [{**{k:None for k in MOUNT}, **mount}
                                            for mount in row['Mounts']]
                    key_id, key = self._protected_keys[service]
                    actual = commit(self._target.namespace,service,projection,key_id,key)['configHmac']
                    if not hmac.compare_digest(actual,self._hashes[service]):
                        _fail()
                    pins[cid] = protected_state_digest(row)
                rows[cid] = row
            raw = json.dumps(instances,sort_keys=True,separators=(',', ':')).encode('ascii')
            if hashlib.sha256(b'dev-workflow:compose-instance-batch:v1\0'+raw).hexdigest() != observation._instance:
                _fail()
            self._whole.commitment(observation)
            captures.append((rows,pins))
        if _encode(captures[0]) != _encode(captures[1]):
            _fail()
        return captures[0]

    def _derive(self, whole, retention, nonce, expires):
        if (_encode([self._whole._policy,self._retention._policy]) != _encode(list(self._scopes))
                or self._whole._baseline_artifacts != self._artifacts
                or self._retention._baseline_artifacts != self._artifacts):
            _fail()
        observed = self._whole.commitment(whole)
        self._retention.retention_commitment(retention)
        baseline_rows, protected_pins = self._protected_state_pins(whole)
        baseline_bytes = baseline_state_bytes(baseline_rows)
        baseline_reference = self._recovery._store.put(baseline_bytes)
        if self._recovery._store.get(baseline_reference) != baseline_bytes:
            _fail()
        services, defaults, manifests, snapshots, bindings, networks, mounts = [], {}, {}, {}, {}, {}, {}
        for b in self._baseline:
            s = b.service
            retained = compile_retained_restore_body(self._recovery,self._reference,self._retention,retention,
                service=s,operation_nonce=nonce,**self._source_inputs[s])
            candidate = retained['candidate']; body = candidate['body']
            ti = self._target_inputs[s]
            if ti['commitment']['keyId'] != ti['expected_key_id']:
                _fail()
            derived = derive_defaults(ti['image'],ti['commitment'],ti['key'],
                **{k:ti[k] for k in ('expected_image_id','expected_registry_digest','expected_architecture')})
            defaults[s] = {k:derived[k] for k in ZERO_DEFAULTS}
            manifests[s] = {'image':ti['image'],'commitment':ti['commitment'],
                'expectedKeyId':ti['expected_key_id'],'registryDigest':ti['expected_registry_digest'],
                'architecture':ti['expected_architecture']}
            target_body = deepcopy(body); target_body['Image'] = ti['expected_image_id']
            services.append(dict(name=s,finalName=b.final_name,baselineContainerId=b.container_id,
                baselineImageId=b.image_id,targetImageId=ti['expected_image_id'],baselineCreateBody=body,
                targetCreateBody=target_body,dependsOn=list(self._dependencies[s])))
            snapshots[s] = candidate['sourceSnapshotDigest']; bindings[s] = retained['retentionBinding']
            mounts[s] = body['HostConfig']['Mounts']
            for name, endpoint in body['NetworkingConfig']['EndpointsConfig'].items():
                net = networks.setdefault(name, {'id':endpoint['NetworkID'],'aliases':{}})
                if net['id'] != endpoint['NetworkID']: _fail()
                net['aliases'][s] = endpoint['Aliases']
        value = dict(schemaVersion=1,profile=PROFILE,profileVersion=PROFILE_VERSION,
            identity=dict(hostId=self._host,daemonId=self._daemon,project=self._target.namespace,
                sourceIdentity=_encode(asdict(self._source)).decode('ascii')),
            services=services,protectedContainers=[dict(containerId=self._ids[n],staticConfigDigest=protected_pins[self._ids[n]]) for n in sorted(self._ids)],
            networks=networks,mounts=mounts,archiveReference=self._reference,sourceSnapshotDigest=_digest(snapshots),
            retentionBindingDigest=_digest(bindings),baselineStateReference=baseline_reference,
            baselineStateDigest=baseline_state_digest(baseline_rows),operationNonce=nonce,expiresAt=int(expires.timestamp()))
        bundle = ExecutionBundleV3(value, authenticated_image_defaults=defaults)
        return bundle, observed, _digest({s['name']:s['targetCreateBody'] for s in services}), _digest(manifests)

    def prepare_intent(self, whole_observation, retention_observation, *, operation_nonce, expires_at):
        try:
            expires = datetime.strptime(expires_at,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
            if not 0 < (expires-datetime.now(timezone.utc)).total_seconds() <= 3600: _fail()
            first = self._derive(whole_observation,retention_observation,operation_nonce,expires)
            bundle, observed, after, artifact = first
            request = RequestV2(2,'deploy',PROFILE,PROFILE_VERSION,self._source,self._target,self._environment,
                False,self._daemon,tuple(b.service for b in self._baseline),tuple(self._scopes[0]['protectedServices']),
                self._artifacts.digest(),after,artifact,observed,None,self._host,bundle.digest,self._policy,expires_at,1)
            review = bundle.public_review()
            review.update(targetManifestDigest=artifact,requestDigest=request.digest(),authorityGranted=False,
                executionAvailable=False,productionReady=False,blockers=['machine-enrollment-required',
                'build-provenance-required','reconstruction-evidence-required','history-policy-required',
                'coordinator-admission-and-recovery-required'])
            again = self._derive(whole_observation,retention_observation,operation_nonce,expires)
            if first[0].canonical_bytes != again[0].canonical_bytes or first[1:] != again[1:]: _fail()
            request.ensure_fresh(datetime.now(timezone.utc))
            return {'bundle':bundle,'request':request,'review':deepcopy(review)}
        except Exception:
            _fail()

    def verify_intent(self, prepared, whole_observation, retention_observation, *, operation_nonce, expires_at):
        try:
            expected = self.prepare_intent(whole_observation,retention_observation,operation_nonce=operation_nonce,expires_at=expires_at)
            if (type(prepared) is not dict or set(prepared) != set(expected)
                    or type(prepared['bundle']) is not ExecutionBundleV3 or type(prepared['request']) is not RequestV2
                    or prepared['bundle'].canonical_bytes != expected['bundle'].canonical_bytes
                    or _encode(asdict(prepared['request'])) != _encode(asdict(expected['request']))
                    or _encode(prepared['review']) != _encode(expected['review'])): _fail()
        except Exception:
            _fail()
