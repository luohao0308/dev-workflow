"""Live guard tests use complete private bodies and explicit Engine transitions."""
from copy import deepcopy
import unittest
from urllib.parse import unquote

from tests.test_deployment_compose_bundle_v3 import fixture, bind_baseline
from tests.test_deployment_compose_restore_body_host import fixture as source_fixture
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, protected_state_digest


class GuardTests(unittest.TestCase):
    def setUp(self):
        v, defaults = fixture()
        self.base=bind_baseline(v)
        self.bundle=ExecutionBundleV3(v, authenticated_image_defaults=defaults)
        self.rows=deepcopy(self.base); self.calls=[]
        self.version={'Version':'29.8.2','GitCommit':'8af9fe3'}
        self.guard=PhaseGuardV3(self.bundle,self.base,read_json=self.read,daemon_version=self.version)
        self.done=[]; self.receipts={}

    def read(self,path):
        self.calls.append(path)
        if path.endswith('/version'): return deepcopy(self.version)
        if path.endswith('/info'): return {'ID':'daemon','DockerRootDir':'/var/lib/docker'}
        if '/containers/json?' in path: return [{'Id':cid} for cid in self.rows]
        if '/containers/' in path: return deepcopy(self.rows[path.split('/')[-2]])
        if '/networks/' in path:
            name,pin=next(iter(self.bundle.to_dict()['networks'].items()))
            return dict(Id=pin['id'],Name=name,Labels={'com.docker.compose.project':self.bundle.to_dict()['identity']['project']},Containers={cid:{} for cid in self.rows})
        if '/volumes/' in path:
            name=unquote(path.split('/')[-1]);return dict(Name=name,Driver='local',Options=None,Mountpoint='/var/lib/docker/volumes/'+name+'/_data')
        raise AssertionError(path)

    def snapshot(self):
        ops=self.bundle.resolve_operations(self.receipts) if self.receipts else self.bundle.creation_operations()
        return dict(phase_index=sum(op['method']!='GET' for op in self.done), operation=deepcopy(ops[len(self.done)]),receipts=deepcopy(self.receipts),completed_operations=deepcopy(self.done))

    def transition(self):
        op=self.snapshot()['operation'];self.done.append(op);phase=op['phase']
        if phase=='create':
            self.receipts={'web':'a'*64};row=deepcopy(self.base['1'*64]);body=op['body']
            row.update(Id='a'*64,Name='/dwc-'+'6'*24+'-web',Image=body['Image'])
            row['Config']['Image']=body['Image'];row['State'].update(Pid=0,StartedAt='',Running=False,Status='created')
            self.rows[row['Id']]=row
        elif phase=='stop': self.rows['1'*64]['State'].update(Pid=0,Running=False,Status='exited')
        elif phase=='delete': del self.rows['1'*64]
        elif phase=='rename': self.rows['a'*64]['Name']='/project-web-1'
        elif phase=='start': self.rows['a'*64]['State'].update(Pid=456,StartedAt='new',Running=True,Status='running')

    def test_explicit_write_transitions_and_two_live_captures(self):
        for _ in range(5):
            self.assertIs(self.guard(self.snapshot()),True);self.transition()
        inventories=[p for p in self.calls if '/containers/json?' in p]
        self.assertEqual(len(inventories),10)
        self.assertTrue(all('all=1&filters=' in p and 'id' not in unquote(p).split('filters=')[1] for p in inventories))

    def test_protected_and_old_drift_fail_closed(self):
        mutations=[lambda r:r['Config']['Env'].append('SECRET=x'),lambda r:r.update(RestartCount=1),
                   lambda r:r['State'].update(Pid=999),lambda r:r['HostConfig'].update(ReadonlyRootfs=0),
                   lambda r:r['Mounts'][1].update(Source='/other'),
                   lambda r:next(iter(r['NetworkSettings']['Networks'].values())).update(Aliases=['other'])]
        for cid in self.base:
            for mutate in mutations:
                self.rows=deepcopy(self.base);mutate(self.rows[cid])
                with self.subTest(cid=cid,mutation=mutate),self.assertRaisesRegex(ValueError,'^compose-phase-guard-v3-blocked$'):self.guard(self.snapshot())

    def test_lifecycle_drift_rejected_for_protected_old_and_new(self):
        changes = [('Paused', True), ('Restarting', True), ('Dead', True),
                   ('Status', 'paused'), ('Status', 'dying'), ('Status', 'restarting'),
                   ('Running', False), ('Paused', 0), ('Pid', True),
                   ('StartedAt', 0), ('Status', True)]
        for phase in range(5):
            for cid in list(self.rows):
                for key, value in changes:
                    saved = deepcopy(self.rows[cid])
                    if type(saved['State'][key]) is type(value) and saved['State'][key] == value:
                        continue
                    self.rows[cid]['State'][key] = value
                    with self.subTest(phase=phase,cid=cid,key=key,value=value),self.assertRaises(ValueError):
                        self.guard(self.snapshot())
                    self.rows[cid] = saved
            self.transition()

    def test_missing_lifecycle_fields_and_invalid_baseline_rejected(self):
        for key in ('Paused', 'Restarting', 'Dead', 'Status'):
            for cid in self.base:
                base=deepcopy(self.base);del base[cid]['State'][key]
                with self.subTest(key=key,cid=cid),self.assertRaises(ValueError):
                    PhaseGuardV3(self.bundle,base,read_json=self.read,daemon_version=self.version)
        for key in ('Paused', 'Restarting', 'Dead'):
            base=deepcopy(self.base);base['1'*64]['State'][key]=True
            with self.assertRaises(ValueError):
                PhaseGuardV3(self.bundle,base,read_json=self.read,daemon_version=self.version)

    def test_unknown_or_replaced_id(self):
        self.rows['b'*64]=deepcopy(self.rows['2'*64])
        with self.assertRaises(ValueError):self.guard(self.snapshot())
        del self.rows['2'*64]
        with self.assertRaises(ValueError):self.guard(self.snapshot())

    def test_forged_prefix_receipts_and_bool_index(self):
        snap=self.snapshot();snap['phase_index']=False
        with self.assertRaises(ValueError):self.guard(snap)
        for receipts in ({'web':'a'*64},{'foreign':'a'*64},{'web':'2'*64}):
            snap=self.snapshot();snap['receipts']=receipts
            with self.assertRaises(ValueError):self.guard(snap)
        self.transition();snap=self.snapshot();snap['completed_operations'][0]['requestDigest']='0'*64
        with self.assertRaises(ValueError):self.guard(snap)

    def test_known_pending_oom_only(self):
        self.transition();self.rows['a'*64]['HostConfig']['OomKillDisable']=False
        self.assertIs(self.guard(self.snapshot()),True)
        for value in (0,True):
            self.rows['a'*64]['HostConfig']['OomKillDisable']=value
            with self.assertRaises(ValueError):self.guard(self.snapshot())

    def test_stopped_generated_network_fields_allowed(self):
        self.transition();self.transition()
        row=self.rows['1'*64];row['NetworkSettings']['SandboxID']=''
        next(iter(row['NetworkSettings']['Networks'].values()))['IPAddress']=''
        self.assertIs(self.guard(self.snapshot()),True)

    def test_two_pass_restart_and_volume_drift(self):
        original=self.guard._read
        def read(path):
            result=original(path)
            if path.endswith('/version') and self.calls.count(path)==2:self.rows['2'*64]['RestartCount']=1
            return result
        self.guard._read=read
        with self.assertRaises(ValueError):self.guard(self.snapshot())
        self.rows=deepcopy(self.base)
        def bad_volume(path):
            result=original(path)
            if '/volumes/' in path:result['Driver']='remote'
            return result
        self.guard._read=bad_volume
        with self.assertRaises(ValueError):self.guard(self.snapshot())

    def test_health_log_noise_ignored_and_digest_type_sensitive(self):
        self.rows['2'*64]['State']['Health']['Log']=[{'Output':'private'}]
        self.assertIs(self.guard(self.snapshot()),True)
        a=deepcopy(self.base['2'*64]);b=deepcopy(a)
        a['HostConfig']['ReadonlyRootfs']=False;b['HostConfig']['ReadonlyRootfs']=0
        self.assertNotEqual(protected_state_digest(a),protected_state_digest(b))


if __name__=='__main__':unittest.main()
