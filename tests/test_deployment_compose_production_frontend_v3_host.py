"""Value-only production frontend comparison, not enrollment or execution."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_compose_production_frontend_v3_host as adapter
from tests.test_deployment_compose_bundle_v3 import fixture,baseline_rows


def material():
    value,_=fixture();row=next(iter(baseline_rows(value).values()))
    row['Name']='/blog-frontend'
    row['Config']['Labels'].update({'com.docker.compose.project':'luohao-blog-prod','com.docker.compose.service':'frontend'})
    row['HostConfig'].update(Memory=0,MemorySwap=0,NanoCpus=0,PidsLimit=None,
        RestartPolicy={'Name':'unless-stopped','MaximumRetryCount':0},
        LogConfig={'Type':'json-file','Config':{'max-size':'10m','max-file':'3'}},Mounts=[])
    row['Mounts']=[];row['Config']['Volumes']=None
    network=next(iter(row['NetworkSettings']['Networks']));row['HostConfig']['NetworkMode']=network
    image=dict(Id=row['Image'],Os='linux',Architecture='amd64',Config={'Labels':{'org.opencontainers.image.revision':'a'*40},'ArgsEscaped':True})
    row['Config']['Labels']['org.opencontainers.image.revision']='a'*40
    identity=dict(hostId='host',daemonId='daemon',project='luohao-blog-prod',service='frontend',containerId=row['Id'],containerName='blog-frontend',imageId=row['Image'],sourceSha='a'*40)
    args=dict(expected_identity=identity,expected_snapshot_digest=adapter.snapshot_digest(row,image,[]),network_ids={network:row['NetworkSettings']['Networks'][network]['NetworkID']},protected_container_ids=[])
    return row,image,args


class FrontendPlanTests(unittest.TestCase):
    def test_exact_unlimited_resources_and_private_body_without_authority(self):
        row,image,args=material();before=deepcopy(row)
        result=adapter.prepare_frontend_plan(row,image,**args)
        self.assertEqual(result['privateBody']['HostConfig'],row['HostConfig'])
        self.assertEqual(result['privateBody']['Image'],row['Image'])
        self.assertTrue(result['privateBody']['ArgsEscaped'])
        self.assertEqual(row,before)
        for key in ('runtimePermit','executionAvailable','productionReady','authorityGranted','engineReconstructionVerified'):
            self.assertIs(result['publicReview'][key],False)
        self.assertNotIn('Env',str(result['publicReview']))

    def test_stale_snapshot_or_identity_or_source_rejected(self):
        for field in ('containerId','imageId','sourceSha','project'):
            row,image,args=material();args['expected_identity'][field]='b'*40 if field=='sourceSha' else 'wrong'
            with self.subTest(field=field),self.assertRaises(ValueError):adapter.prepare_frontend_plan(row,image,**args)
        row,image,args=material();row['Config']['Env'].append('PUBLIC=drift')
        with self.assertRaises(ValueError):adapter.prepare_frontend_plan(row,image,**args)

    def test_unknown_fields_mounts_and_uncovered_inheritance_rejected(self):
        for change in ('unknown','mount','inheritance','boolean'):
            row,image,args=material()
            if change=='unknown':image['Config']['Unknown']=True
            elif change=='mount':row['Mounts']=[{}]
            elif change=='inheritance':image['Config']['Env']=['UNBOUND=value']
            else:row['HostConfig']['Memory']=True
            args['expected_snapshot_digest']=adapter.snapshot_digest(row,image,[])
            with self.subTest(change=change),self.assertRaises(ValueError):adapter.prepare_frontend_plan(row,image,**args)

    def test_missing_zero_fields_remain_missing_in_original_body(self):
        row,image,args=material();row['Config']['Healthcheck'].pop('StartPeriod',None);row['HostConfig'].pop('Tmpfs',None)
        args['expected_snapshot_digest']=adapter.snapshot_digest(row,image,[])
        result=adapter.prepare_frontend_plan(row,image,**args)
        self.assertNotIn('StartPeriod',result['privateBody']['Healthcheck'])
        self.assertNotIn('Tmpfs',result['privateBody']['HostConfig'])

    def test_endpoint_options_are_not_silently_dropped(self):
        cases=(('IPAMConfig',{'IPv4Address':'172.18.0.99'}),('Links',['other:alias']),
               ('DriverOpts',{'key':'value'}),('GwPriority',1),('GwPriority',True),('UnknownSetting',{}))
        for field,value in cases:
            row,image,args=material();endpoint=next(iter(row['NetworkSettings']['Networks'].values()))
            endpoint[field]=value;args['expected_snapshot_digest']=adapter.snapshot_digest(row,image,[])
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                adapter.prepare_frontend_plan(row,image,**args)

    def test_malformed_image_defaults_rejected_even_with_rehashed_snapshot(self):
        cases=(('Cmd',True),('Entrypoint','node'),('User',False),('WorkingDir',[]),
               ('ArgsEscaped',1),('Env',['INVALID-NAME=value']),('Env',['A=x','A=y']),
               ('Env',['A='+'x'*8193]),('Labels',{'invalid':1}),
               ('ExposedPorts',{'3000/tcp':{'unknown':True}}),
               ('Healthcheck',{'Test':['CMD','true'],'Interval':True}),
               ('Healthcheck',{'Test':True}))
        for field,value in cases:
            row,image,args=material();image['Config'][field]=value
            args['expected_snapshot_digest']=adapter.snapshot_digest(row,image,[])
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                adapter.prepare_frontend_plan(row,image,**args)

    def test_contradictory_running_state_rejected(self):
        for field in ('Paused','Restarting','Dead'):
            row,image,args=material();row['State'][field]=True
            args['expected_snapshot_digest']=adapter.snapshot_digest(row,image,[])
            with self.subTest(field=field),self.assertRaises(ValueError):
                adapter.prepare_frontend_plan(row,image,**args)
