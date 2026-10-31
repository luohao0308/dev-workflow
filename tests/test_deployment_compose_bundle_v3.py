"""Coordinator value-contract acceptance: private bodies and exact receipt resolution."""
from copy import deepcopy
import hashlib
import json
import unittest
from tests.test_deployment_compose_restore_body_host import fixture as source_fixture
from deployment_compose_image_defaults import ZERO_DEFAULTS
from deployment_compose_bundle_v3 import ExecutionBundleV3, PROFILE, PROFILE_VERSION


def baseline_rows(value):
    """Complete private test rows; value-contract fixtures grant no authority."""
    rows={}
    for service in value['services']:
        row=deepcopy(source_fixture()['raw'])
        row.update(Id=service['baselineContainerId'],Name='/'+service['finalName'],
            Image=service['baselineImageId'],RestartCount=0,
            State=dict(Pid=123,StartedAt='initial',Running=True,Paused=False,Restarting=False,
                       Dead=False,Status='running',Health=dict(Status='healthy',Log=[])))
        body=service['baselineCreateBody']
        row['Config']={k:deepcopy(v) for k,v in body.items() if k not in ('HostConfig','NetworkingConfig')}
        row['HostConfig']=deepcopy(body['HostConfig'])
        for name,endpoint in body['NetworkingConfig']['EndpointsConfig'].items():
            row['NetworkSettings']['Networks'][name].update(deepcopy(endpoint))
        rows[row['Id']]=row
    for protected in value['protectedContainers']:
        row=deepcopy(next(iter(rows.values())))
        row.update(Id=protected['containerId'],Name='/guard')
        row['Config']['Labels']['com.docker.compose.service']='guard'
        rows[row['Id']]=row
    return rows


def bind_baseline(value):
    from deployment_compose_phase_guard_v3_host import baseline_state_digest, protected_state_digest
    rows=baseline_rows(value)
    for protected in value['protectedContainers']:
        protected['staticConfigDigest']=protected_state_digest(rows[protected['containerId']])
    value['baselineStateDigest']=baseline_state_digest(rows)
    # A value-contract CAS reference, never passed to the trusted loader.
    value['baselineStateReference']=hashlib.sha256(b'unit-cas-reference').hexdigest()
    return rows


def fixture():
    args = source_fixture(); raw = args['raw']
    b = deepcopy(raw['Config']); b['Labels']['com.docker.compose.service']='web'; b['Image'] = raw['Image']; b['HostConfig'] = deepcopy(raw['HostConfig'])
    b['NetworkingConfig'] = {'EndpointsConfig': {n: {'NetworkID': nid, 'Aliases': ['web']} for n, nid in args['network_ids'].items()}}
    t = deepcopy(b); t['Image'] = 'sha256:' + '9'*64
    service = dict(name='web', finalName='project-web-1', baselineContainerId='1'*64, baselineImageId=b['Image'], targetImageId=t['Image'], baselineCreateBody=b, targetCreateBody=t, dependsOn=[])
    value = dict(schemaVersion=1, profile=PROFILE, profileVersion=PROFILE_VERSION,
        identity=dict(hostId='host', daemonId='daemon', project=args['identity']['project'], sourceIdentity='source:abc'), services=[service],
        protectedContainers=[dict(containerId='2'*64, staticConfigDigest='3'*64)],
        networks={n:dict(id=nid, aliases={'web':['web']}) for n,nid in args['network_ids'].items()},
        mounts={'web':deepcopy(b['HostConfig']['Mounts'])}, archiveReference='archive:exact', sourceSnapshotDigest='4'*64, retentionBindingDigest='5'*64, operationNonce='6'*64, expiresAt=2000000000)
    bind_baseline(value)
    return value, {'web':deepcopy(ZERO_DEFAULTS)}


class BundleTests(unittest.TestCase):
    def test_complete_private_preservation_and_immutable_snapshot(self):
        v,d = fixture(); original=deepcopy(v); bundle=ExecutionBundleV3(v, authenticated_image_defaults=d)
        self.assertEqual(bundle.to_dict()['services'][0]['baselineCreateBody'],original['services'][0]['baselineCreateBody'])
        v['services'][0]['baselineCreateBody']['Env'].append('SECRET=changed')
        got=bundle.to_dict(); got['services'][0]['targetCreateBody']['Env'].clear()
        self.assertEqual(bundle.to_dict()['services'][0]['baselineCreateBody'], original['services'][0]['baselineCreateBody'])
        self.assertEqual(bundle.canonical_bytes, ExecutionBundleV3(original, authenticated_image_defaults=d).canonical_bytes)
        self.assertNotIn('Env', json.dumps(bundle.public_review()))
        with self.assertRaises(AttributeError): bundle._canonical=b'changed'

    def test_original_baseline_binding_is_required_and_closed(self):
        for key in ('baselineStateReference','baselineStateDigest'):
            value,defaults=fixture();value.pop(key)
            with self.subTest(missing=key),self.assertRaises(ValueError):
                ExecutionBundleV3(value,authenticated_image_defaults=defaults)
            value,defaults=fixture();value[key]='not-a-digest'
            with self.subTest(invalid=key),self.assertRaises(ValueError):
                ExecutionBundleV3(value,authenticated_image_defaults=defaults)

    def test_alternate_target_cannot_be_rehashed_into_contract(self):
        v,d=fixture(); v['services'][0]['targetCreateBody']['HostConfig']['LogConfig']['Config']['max-size']='99m'
        with self.assertRaises(ValueError): ExecutionBundleV3(v, authenticated_image_defaults=d)

    def test_inheritance_hazards(self):
        for defaults in ({'Env':['NEW=secret']}, {'Env':['A=x','A=y']}, {'Labels':{'x':'y'}}, {'Volumes':{'/new':{}}}, {'ExposedPorts':{'80/tcp':{}}}, {'Healthcheck':{'Test':['CMD','true']}}, {'StopSignal':'SIGQUIT'}, {'User':'new-user'}, {'WorkingDir':'/new'}):
            v,d=fixture(); d['web'].update(defaults)
            if 'User' in defaults or 'WorkingDir' in defaults:
                for body in ('baselineCreateBody','targetCreateBody'): v['services'][0][body][next(iter(defaults))]=''
            with self.subTest(defaults=defaults), self.assertRaises(ValueError): ExecutionBundleV3(v, authenticated_image_defaults=d)

    def test_dag_order_and_exact_delete_flags(self):
        v,d=fixture(); s=deepcopy(v['services'][0]); s.update(name='api', finalName='api-1', baselineContainerId='7'*64, dependsOn=['web']);
        for key in ('baselineCreateBody','targetCreateBody'): s[key]['Labels']['com.docker.compose.service']='api'
        v['services'].insert(0,s); d['api']=deepcopy(d['web']); v['mounts']['api']=deepcopy(v['mounts']['web'])
        for net in v['networks'].values(): net['aliases']['api']=['web']
        b=ExecutionBundleV3(v, authenticated_image_defaults=d)
        ops=b.resolve_operations({'web':'a'*64,'api':'b'*64})
        self.assertEqual([(x['phase'],x['service']) for x in ops[:6]], [('create','web'),('create','api'),('stop','api'),('stop','web'),('delete','api'),('delete','web')])
        self.assertTrue(all(x['path'].endswith('?force=false&v=false') for x in ops if x['phase']=='delete'))
        self.assertEqual(ops[-2]['prerequisitesHealthy'],['web'])
        with self.assertRaises(ValueError): b.resolve_operations({'web':'a'*64,'api':'a'*64})
        reordered=deepcopy(v); reordered['services'].reverse()
        self.assertEqual(b.digest,ExecutionBundleV3(reordered,authenticated_image_defaults=d).digest)
        v['services'][1]['dependsOn']=['api']
        with self.assertRaises(ValueError): ExecutionBundleV3(v, authenticated_image_defaults=d)

    def test_receipt_scope_and_bounds(self):
        v,d=fixture(); b=ExecutionBundleV3(v,authenticated_image_defaults=d)
        for receipts in ({}, {'web':'a'*64,'foreign':'b'*64}, {'web':'1'*64}, {'web':'2'*64}, {'web':'short'}):
            with self.subTest(receipts=receipts), self.assertRaises(ValueError): b.resolve_operations(receipts)
        ops=b.resolve_operations({'web':'a'*64})
        self.assertIn('dwc-'+ '6'*24+'-web', ops[0]['path'])
        self.assertIn('a'*64,ops[-1]['path'])
        v['services']*=17
        with self.assertRaises(ValueError): ExecutionBundleV3(v,authenticated_image_defaults=d)
        v,d=fixture(); v['verified']=True
        with self.assertRaises(ValueError): ExecutionBundleV3(v,authenticated_image_defaults=d)

    def test_null_entrypoint_and_empty_cmd_reject_new_inheritance(self):
        for field, value, default in [('Cmd', [], ['unexpected']), ('Entrypoint', None, ['new-entry'])]:
            v,d=fixture()
            for body in ('baselineCreateBody','targetCreateBody'): v['services'][0][body][field]=value
            d['web'][field]=default
            with self.subTest(field=field), self.assertRaises(ValueError): ExecutionBundleV3(v, authenticated_image_defaults=d)

    def test_topology_and_protected_pin_binding(self):
        for change in ('alias','mount','protected'):
            v,d=fixture()
            if change=='alias': next(iter(v['networks'].values()))['aliases']['web']=['other']
            elif change=='mount': v['mounts']['web']=[]
            else: v['protectedContainers'][0]['containerId']=v['services'][0]['baselineContainerId']
            with self.subTest(change=change), self.assertRaises(ValueError): ExecutionBundleV3(v,authenticated_image_defaults=d)

    def test_creation_prefix_and_wire_body_hashes(self):
        v,d=fixture(); b=ExecutionBundleV3(v,authenticated_image_defaults=d)
        creates=b.creation_operations()
        resolved=b.resolve_operations({'web':'a'*64})
        self.assertEqual(creates, resolved[:len(creates)])
        expected=json.dumps(creates[0]['body'],sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode('ascii')
        self.assertEqual(creates[0]['bodyDigest'],hashlib.sha256(expected).hexdigest())
        for op in resolved[1:]:
            self.assertIsNone(op['body'])
            self.assertEqual(op['bodyDigest'],hashlib.sha256(b'').hexdigest())
            self.assertNotEqual(op['bodyDigest'],hashlib.sha256(b'null').hexdigest())
        for op in resolved:
            request={k:op[k] for k in ('method','path','bodyDigest')}
            encoded=json.dumps(request,sort_keys=True,separators=(',', ':')).encode('ascii')
            self.assertEqual(op['requestDigest'],hashlib.sha256(encoded).hexdigest())
        creates[0]['body']['Env'].append('MUTATED=yes')
        self.assertEqual(b.creation_operations(),resolved[:1])

    def test_type_changing_image_only_target_rejected(self):
        for field, replacement in (('Tty', 0), ('ReadonlyRootfs', 0)):
            v,d=fixture()
            base=v['services'][0]['baselineCreateBody']
            target=v['services'][0]['targetCreateBody']
            base_field=base if field=='Tty' else base['HostConfig']
            target_field=target if field=='Tty' else target['HostConfig']
            base_field[field]=False
            target_field[field]=replacement
            # Python equality masks this edit, and rehashing cannot legitimize it.
            expected=deepcopy(base); expected['Image']=target['Image']
            self.assertEqual(target,expected)
            with self.subTest(field=field), self.assertRaises(ValueError):
                ExecutionBundleV3(v,authenticated_image_defaults=d)

    def test_all_resolved_writes_match_profile3_gate_grammar(self):
        import deployment_gateway as gateway
        v,d=fixture(); bundle=ExecutionBundleV3(v,authenticated_image_defaults=d)
        # Grammar-only gate instance: no filesystem, witness, session or authority.
        gate=object.__new__(gateway.FileWriterGate)
        gate.policy=gateway.GatePolicy('store','key','a'*64,'b'*64,True,'c'*64,'d'*64,
                                       operation_profile='compose-v3')
        ops=bundle.resolve_operations({'web':'e'*64})
        self.assertEqual(bundle.creation_operations(),ops[:1])
        writes=[op for op in ops if op['phase']!='readiness']
        self.assertEqual([op['phase'] for op in writes],['create','stop','delete','rename','start'])
        for op in writes:
            exact=(op['method'],op['path'],op['bodyDigest'])
            with self.subTest(phase=op['phase']):
                self.assertEqual(gate._operation(*exact),exact)
        stop=next(op for op in writes if op['phase']=='stop')
        self.assertTrue(stop['path'].endswith('/stop?t=10'))
        self.assertEqual(bundle.to_dict()['resolverRules']['stopTimeoutSeconds'],10)
