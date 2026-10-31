"""Unit host seams authenticate values, not production machine provenance."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import hashlib
import os
import unittest
from unittest.mock import patch
from tests.test_deployment_compose_restore_body_host import retained_fixture, seal
from tests.test_deployment_compose_snapshot import KEY
from deployment_compose_private import commit
from deployment_compose_recovery_host import ComposeRecoveryHost
from deployment_compose_image_defaults import commit_image_config
from deployment_contract_v2 import SourceIdentity, TargetIdentity
import deployment_compose_prepare_v3_host as host


def fixture():
    args, options, _, _, observer, _, store = retained_fixture()
    project = 'dw-test'
    observer._policy['project'] = project
    args['identity']['project'] = project
    args['raw']['Config']['Labels']['com.docker.compose.project'] = project
    args['raw']['Config']['Image'] = args['identity']['imageId']
    projection = {k:deepcopy(args['raw'][k]) for k in ('Config','HostConfig','NetworkSettings','Mounts')}
    digest = commit(project,'web',projection,'inspect-key',KEY)['configHmac']
    artifact = replace(args['artifact'],config_hmac=digest)
    args['artifact'] = artifact
    observer._baseline_artifacts = replace(observer._baseline_artifacts,services=(artifact,))
    # The observation test seam reads the mutable observed fixture dictionary.
    original = observer._collect
    def collect(*a, **kw):
        observed = original(*a, **kw); observed['serviceConfigHmacs']['web'] = digest
        return observed
    observer._collect = collect
    baseline = (host.BaselineContainer('web',args['identity']['containerId'],args['identity']['containerName'],artifact.image_id),)
    recovery = ComposeRecoveryHost(store=store,observer=observer,baseline=baseline,
        projections={'web':projection},private_keys={'inspect-key':KEY})
    seal(args)
    inputs = {k:v for k,v in args.items() if k not in ('raw','artifact','operation_nonce')}
    image = deepcopy(args['image']);image['Id']='sha256:'+'9'*64;image['Config']={}
    targets = {'web':dict(image=image,commitment=commit_image_config(image,'target-key',KEY),key=KEY,
        expected_key_id='target-key',expected_image_id=image['Id'],expected_registry_digest=image['RepoDigests'][0],expected_architecture=image['Architecture'])}
    scope=observer._policy
    scope['protectedContainerIds']={'db':'2'*64}
    scope['containerNames']['db']='dw-db-1'
    # Explicit unit-only trusted reader seam; this does not exercise real TLS.
    row=deepcopy(args['raw'])
    row.update(RestartCount=0,State=dict(Pid=123,StartedAt='initial',Running=True,
        Paused=False,Restarting=False,Dead=False,Status='running',Health={'Status':'healthy'}))
    protected=deepcopy(row);protected.update(Id='2'*64,Name='/dw-db-1',Image=scope['imageIds']['db'])
    protected['Config']['Labels']['com.docker.compose.service']='db'
    rows={row['Id']:row,protected['Id']:protected}
    projection_db={k:protected[k] for k in ('Config','HostConfig','Mounts','NetworkSettings')}
    db_hmac=commit(project,'db',projection_db,'protected-key',KEY)['configHmac']
    scope['protectedConfigHmacs']['db']=db_hmac
    base_collector=observer._collect
    def collect_complete(*a,**k):
        value=base_collector(*a,**k)
        value['serviceConfigHmacs']['db']=db_hmac
        instances={cid:(r['State']['Pid'],r['State']['StartedAt'],r['RestartCount']) for cid,r in rows.items()}
        value['instanceDigest']=hashlib.sha256(b'dev-workflow:compose-instance-batch:v1\0'+json.dumps(instances,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
        return value
    observer._collect=collect_complete
    reader_get=observer._reader.get
    def get_complete(path,**kw):
        if '/containers/' in path:return deepcopy(rows[path.split('/')[-2]])
        return reader_get(path,**kw)
    producer=host.TrustedPhaseStateProducerV3(socket_path='/unit-only/docker.sock',
        project=project,daemon_id=scope['daemonId'],container_ids=tuple(sorted(rows)))
    def raw_get(path):
        if path=='/v1.45/info':return {'ID':scope['daemonId']}
        return get_complete(path)
    producer._get=raw_get
    observer._unit_rows=rows
    observation=observer.issue();reference=recovery.retain(observation)
    kwargs=dict(whole_observer=observer,retention_observer=observer,recovery=recovery,baseline=baseline,
        source_inputs={'web':inputs},target_inputs=targets,
        source=SourceIdentity('github.com','https://github.com/o/r.git',1,'o/r','a'*40),
        target=TargetIdentity('compose',project,'test'),host_id=args['identity']['hostId'],daemon_id=scope['daemonId'],
        environment='test',policy_hash='e'*64,dependencies={'web':()},protected_names={'db':'dw-db-1'},protected_ids={'db':'2'*64},protected_hashes=scope['protectedConfigHmacs'],archive_reference=reference,phase_state_producer=producer,protected_private_keys={'db':('protected-key',KEY)})
    return kwargs, observation


@unittest.skipUnless(os.name == 'posix', 'private recovery store requires POSIX semantics')
class PreparationTests(unittest.TestCase):
    def test_health_log_progress_does_not_rebase_stable_lifecycle(self):
        kw, observation=fixture()
        producer=kw['phase_state_producer'];original=producer.capture;calls=[]
        def capture():
            rows=original();calls.append(True)
            for row in rows.values():
                row['State']['Health']['Log']=[dict(Start=str(len(calls)),End=str(len(calls)),
                                                  ExitCode=0,Output='healthy')]
            return rows
        producer.capture=capture
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        prepared=host.ComposePreparationHostV3(**kw).prepare_intent(observation,observation,
            operation_nonce='f'*64,expires_at=expiry)
        raw=kw['recovery']._store.get(prepared['bundle'].to_dict()['baselineStateReference'])
        self.assertGreaterEqual(len(calls),4)
        self.assertNotIn(b'"Log"',raw)
        self.assertEqual(json.loads(raw)['2'*64]['State']['Pid'],
                         kw['whole_observer']._unit_rows['2'*64]['State']['Pid'])

    def test_engine_omitted_bind_fields_match_gateway_hmac_without_rewriting_baseline(self):
        kw, observation=fixture()
        protected=kw['whole_observer']._unit_rows['2'*64]
        binds=[m for m in protected['Mounts'] if m['Type']=='bind']
        self.assertTrue(binds)
        for mount in binds:
            self.assertIsNone(mount.pop('Name'))
            self.assertIsNone(mount.pop('Driver'))
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        prepared=host.ComposePreparationHostV3(**kw).prepare_intent(observation,observation,
            operation_nonce='f'*64,expires_at=expiry)
        retained=json.loads(kw['recovery']._store.get(prepared['bundle'].to_dict()['baselineStateReference']))
        archived=next(m for m in retained['2'*64]['Mounts'] if m['Type']=='bind')
        self.assertNotIn('Name',archived)
        self.assertNotIn('Driver',archived)

    def test_full_body_image_only_and_safe_review(self):
        kw, observation=fixture(); prep=host.ComposePreparationHostV3(**kw)
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        value=prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)
        service=value['bundle'].to_dict()['services'][0]
        baseline=deepcopy(service['baselineCreateBody']);baseline['Image']=service['targetImageId']
        self.assertEqual(service['targetCreateBody'],baseline)
        self.assertIn('HostConfig',baseline);self.assertIn('Env',baseline)
        self.assertNotIn('Env',json.dumps(value['review']))
        self.assertEqual(json.loads(value['bundle'].to_dict()['identity']['sourceIdentity'])['project_id'],1)
        self.assertEqual(value['request'].plan_hash,value['bundle'].digest)
        prep.verify_intent(value,observation,observation,operation_nonce='f'*64,expires_at=expiry)
        value['review']['authorityGranted']=True
        with self.assertRaises(ValueError):prep.verify_intent(value,observation,observation,operation_nonce='f'*64,expires_at=expiry)

    def test_target_pins_and_expiry_fail_closed(self):
        for field in ('expected_image_id','expected_key_id','expected_registry_digest','key'):
            kw, observation=fixture()
            kw['target_inputs']['web'][field]= b'x'*32 if field=='key' else 'wrong'
            prep=host.ComposePreparationHostV3(**kw)
            expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
            with self.subTest(field=field),self.assertRaises(ValueError):prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)
        kw, observation=fixture();prep=host.ComposePreparationHostV3(**kw)
        with self.assertRaises(ValueError):prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at='2099-01-01T00:00:00Z')

    def test_caller_inputs_copied_and_archive_drift_rejected(self):
        kw, observation=fixture(); prep=host.ComposePreparationHostV3(**kw)
        kw['target_inputs']['web']['key']=b'x'*32
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)
        kw['recovery']._store.get=lambda _:b'{}'
        with self.assertRaises(ValueError):prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)

    def test_request_hashes_and_rehashed_body_tamper(self):
        kw, observation=fixture();prep=host.ComposePreparationHostV3(**kw)
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        value=prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)
        bodies={s['name']:s['targetCreateBody'] for s in value['bundle'].to_dict()['services']}
        self.assertEqual(value['request'].after_hash,host._digest(bodies))
        self.assertEqual(value['request'].before_hash,kw['whole_observer']._baseline_artifacts.digest())
        changed=value['bundle'].to_dict()
        for key in ('resolverContract','resolverRules','imageDefaultsDigests','operations'):changed.pop(key)
        for field in ('baselineCreateBody','targetCreateBody'):changed['services'][0][field]['Env'].append('EXTRA=secret')
        from deployment_compose_image_defaults import ZERO_DEFAULTS
        value['bundle']=host.ExecutionBundleV3(changed,authenticated_image_defaults={'web':deepcopy(ZERO_DEFAULTS)})
        value['request']=replace(value['request'],plan_hash=value['bundle'].digest)
        value['review']=value['bundle'].public_review()
        with self.assertRaises(ValueError):prep.verify_intent(value,observation,observation,operation_nonce='f'*64,expires_at=expiry)

    def test_source_and_lifecycle_drift_during_compile(self):
        for drift in ('policy','source','lifecycle'):
            kw, observation=fixture();prep=host.ComposePreparationHostV3(**kw)
            expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
            original=host.compile_retained_restore_body
            def compile_and_drift(*a,**k):
                result=original(*a,**k)
                if drift=='policy':kw['whole_observer']._policy['daemonId']='changed'
                elif drift=='source':kw['recovery']._projections['web']['Config']['Env'].append('DRIFT=true')
                else:
                    collector=kw['whole_observer']._collect
                    def stopped(*args,**kwargs):
                        got=collector(*args,**kwargs);got['serviceState']['web']['running']=False;return got
                    kw['whole_observer']._collect=stopped
                return result
            with self.subTest(drift=drift),patch.object(host,'compile_retained_restore_body',side_effect=compile_and_drift),self.assertRaises(ValueError):
                prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)

    def test_source_view_cannot_supply_whole_project_authority(self):
        kw, _=fixture()
        kw['whole_observer']._source_container_ids=('1'*64,'2'*64)
        with self.assertRaises(ValueError):host.ComposePreparationHostV3(**kw)

    def test_baseline_and_target_host_scope_substitution_rejected(self):
        for field in ('production','namespace','identity','key_id'):
            kw, observation=fixture()
            if field=='production':kw['production']=True
            elif field=='namespace':kw['target']=TargetIdentity('compose','blog','test')
            elif field=='identity':kw['source_inputs']['web']['identity']['hostId']='substituted'
            else:kw['target_inputs']['web']['commitment']['keyId']='substituted'
            with self.subTest(field=field),self.assertRaises(ValueError):
                prep=host.ComposePreparationHostV3(**kw)
                expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
                prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)

    def test_prepared_protected_pin_constructs_real_phase_guard(self):
        from deployment_compose_phase_guard_v3_host import PhaseGuardV3, protected_state_digest
        kw, observation=fixture();prep=host.ComposePreparationHostV3(**kw)
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        value=prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)
        rows=kw['phase_state_producer'].reload(kw['recovery']._store,value['bundle'],read_json=lambda path:None,
            daemon_version={'Version':'29.8.2','GitCommit':'8af9fe3'})
        pin=value['bundle'].to_dict()['protectedContainers'][0]['staticConfigDigest']
        self.assertEqual(pin,protected_state_digest(rows['2'*64]))
        self.assertNotEqual(pin,kw['protected_hashes']['db'])
        guard=PhaseGuardV3(value['bundle'],rows,read_json=lambda path:None,
            daemon_version={'Version':'29.8.2','GitCommit':'8af9fe3'})
        self.assertIsInstance(guard,PhaseGuardV3)

    def test_original_baseline_cas_survives_restart_and_rejects_rebase(self):
        from deployment_compose_phase_guard_v3_host import PhaseGuardV3, baseline_state_digest
        kw, observation=fixture();prep=host.ComposePreparationHostV3(**kw)
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        prepared=prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)
        bundle=prepared['bundle'];store=kw['recovery']._store
        raw=store.get(bundle.to_dict()['baselineStateReference'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),bundle.to_dict()['baselineStateDigest'])
        self.assertIn(b'HostConfig',raw)
        rows=kw['whole_observer']._unit_rows
        rows['1'*64]['State']['Pid']=456
        rows['1'*64]['State']['StartedAt']='restarted'
        rows['1'*64]['RestartCount']=1
        options=dict(read_json=lambda path:None,daemon_version={'Version':'29.8.2','GitCommit':'8af9fe3'})
        # Reconstructed host loader does not read the current daemon at all.
        with patch.object(kw['phase_state_producer'],'capture',side_effect=AssertionError('fresh rebase')):
            original=host.TrustedPhaseStateProducerV3.reload(store,bundle,**options)
        self.assertEqual(original['1'*64]['State']['Pid'],123)
        self.assertEqual(baseline_state_digest(original),bundle.to_dict()['baselineStateDigest'])
        with self.assertRaises(ValueError):PhaseGuardV3(bundle,rows,**options)
        with patch.object(store,'get',return_value=b'{}'),self.assertRaises(ValueError):
            host.TrustedPhaseStateProducerV3.reload(store,bundle,**options)
        original['1'*64]['State']['Health']['Log']=['noise']
        PhaseGuardV3(bundle,original,**options)

    def test_protected_full_facts_and_original_hmac_required(self):
        for mutation in ('paused','missing-paused','restart','hmac','identity'):
            kw, observation=fixture();prep=host.ComposePreparationHostV3(**kw)
            row=kw['whole_observer']._unit_rows['2'*64]
            if mutation=='paused':row['State']['Paused']=True
            elif mutation=='missing-paused':row['State'].pop('Paused')
            elif mutation=='restart':row['RestartCount']+=1
            elif mutation=='hmac':row['Config']['Env'].append('MUTATED=secret')
            else:row['Config']['Labels']['com.docker.compose.service']='other'
            expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)

    def test_explicit_host_producer_required(self):
        kw, _=fixture()
        for producer in (None, object(), lambda: kw['whole_observer']._unit_rows):
            kw['phase_state_producer']=producer
            with self.assertRaises(ValueError):host.ComposePreparationHostV3(**kw)

    def test_host_producer_scope_and_daemon_fail_closed(self):
        for field in ('project','daemon_id','container_ids'):
            kw, _=fixture()
            setattr(kw['phase_state_producer'],field,('3'*64,) if field=='container_ids' else 'other')
            with self.subTest(field=field),self.assertRaises(ValueError):
                host.ComposePreparationHostV3(**kw)
        kw, _=fixture();producer=kw['phase_state_producer'];original=producer._get
        producer._get=lambda path: {'ID':'other'} if path=='/v1.45/info' else original(path)
        with self.assertRaises(ValueError):producer.capture()

    def test_real_unix_producer_with_masked_observer(self):
        import socketserver
        import tempfile
        import threading
        from http.server import BaseHTTPRequestHandler
        from deployment_compose_reader_host import _project
        kw, observation=fixture()
        rows=kw['whole_observer']._unit_rows
        daemon=kw['daemon_id']
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self, *args):pass
            def do_GET(self):
                value={'ID':daemon} if self.path=='/v1.45/info' else rows[self.path.split('/')[-2]]
                raw=json.dumps(value).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(raw)))
                self.end_headers();self.wfile.write(raw)
        with tempfile.TemporaryDirectory() as directory:
            path=directory+'/docker.sock'
            with socketserver.UnixStreamServer(path,Handler) as server:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    producer=host.TrustedPhaseStateProducerV3(socket_path=path,project='dw-test',
                        daemon_id=daemon,container_ids=tuple(sorted(rows)))
                    kw['phase_state_producer']=producer
                    original=kw['whole_observer']._reader.get
                    def masked(path,**options):
                        if '/containers/' in path:
                            return _project(path,rows[path.split('/')[-2]],'unused')
                        return original(path,**options)
                    kw['whole_observer']._reader.get=masked
                    masked_row=masked('/v1.45/containers/'+'2'*64+'/json')
                    self.assertNotIn('HostConfig',masked_row)
                    self.assertNotIn('Env',masked_row['Config'])
                    self.assertNotIn('Paused',masked_row['State'])
                    prep=host.ComposePreparationHostV3(**kw)
                    expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
                    value=prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)
                    self.assertEqual(set(producer.reload(kw['recovery']._store,value['bundle'],read_json=lambda path:None,
                        daemon_version={'Version':'29.8.2','GitCommit':'8af9fe3'})),set(rows))
                finally:
                    server.shutdown();thread.join()

    def test_protected_reader_drift_between_captures_rejected(self):
        kw, observation=fixture();prep=host.ComposePreparationHostV3(**kw)
        reader=kw['phase_state_producer'];original=reader._get;calls=[]
        def drifting(path,**kwargs):
            result=original(path,**kwargs)
            if path.endswith('/'+ '2'*64 + '/json'):
                calls.append(path)
                if len(calls)>1:result['RestartCount']+=1
            return result
        reader._get=drifting
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        with self.assertRaises(ValueError):prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry)
