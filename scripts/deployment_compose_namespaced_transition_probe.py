"""Private namespace two-image transition; not a product writer or recovery proof."""
from copy import deepcopy
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

from deployment_compose_namespaced_runtime_probe import PrivateDaemon,PRODUCTION,environment,transfer_image,ensure_capacity
from deployment_compose_log_probe import IMAGE,ID,diagnostic
from deployment_compose_runtime_probe import runtime_recipe,wait_healthy
from deployment_compose_create import compile_create
from deployment_compose_create_inspect import compare_create_inspect_wire
from deployment_compose_image_defaults import commit_image_config,derive_defaults
from compose_transition_probe import server_code,client_code

V2='python@sha256:bf12ecc0bea3f171d55145dd02c78b5eeb09f30ee2ac9cc2b4c9e4e8f5e30741'
ROLES=('backend','frontend')


def source_image(ref):
    if ref not in (IMAGE,V2):raise ValueError('source-reference-not-allowed')
    rows=json.loads(subprocess.run(['docker','--host',PRODUCTION,'image','inspect',ref],env=environment(),
        capture_output=True,check=True,timeout=30).stdout)
    if len(rows)!=1 or ref not in rows[0]['RepoDigests']:raise ValueError('source-image-mismatch')
    return rows[0]


def post(target,candidate):
    if candidate['method']!='POST' or not re.fullmatch(r'/v1\.45/containers/create\?name=dw-transition-[a-f0-9]{24}-(?:backend|frontend)(?:-(?:v2|rollback))?',candidate['path']):
        raise ValueError('transition-create-scope')
    connection=target.connection()
    try:
        connection.request('POST',candidate['path'],json.dumps(candidate['body']),{'Content-Type':'application/json'})
        response=connection.getresponse();body=response.read(1024*1024+1)
        if response.status!=201 or len(body)>1024*1024:raise ValueError('unknown-create-response')
        return json.loads(body)
    finally:connection.close()


def delete(target,receipt):
    if type(receipt) is not str or not ID.fullmatch(receipt):raise ValueError('invalid-delete-id')
    connection=target.connection()
    try:
        connection.request('DELETE','/v1.45/containers/'+receipt+'?force=false&v=false')
        response=connection.getresponse();body=response.read(4097)
        if response.status!=204 or body:raise ValueError('unknown-delete-response')
    finally:connection.close()


def switch(target,active,pending,known,write,project):
    for role in reversed(ROLES):
        old=active[role]
        write(lambda old=old:target.stop(old))
        known[old]['running']=False
    for role in reversed(ROLES):
        old=active[role]
        write(lambda old=old:delete(target,old));known.pop(old)
    for role in ROLES:
        receipt=pending[role];name=project+'-'+role
        def rename(receipt=receipt,name=name):
            if target.run('container','rename',receipt,name).strip():raise ValueError('unknown-rename-response')
            row=json.loads(target.run('container','inspect',receipt))
            if len(row)!=1 or row[0]['Id']!=receipt or row[0]['Name']!='/'+name:raise ValueError('rename-inspect-mismatch')
        write(rename)


def transition_recipe(image,project,network,volume,bind,role,token):
    recipe=runtime_recipe(image,project,network,volume,bind,role,token)
    # Explicit existing tmpfs path avoids inheriting image-specific cwd defaults.
    recipe['process']['workingDir']='/tmp'
    return recipe


def run_transition(root,info):
    target=PrivateDaemon(root,info)
    result={'kind':'namespace-two-image-transition','stages':[], 'cleanup':[],
            'unknownWriteResult':False,'success':False,'inventoryBaselineCaptured':False,'productionReady':False,'authorityGranted':False,
            'executionAvailable':False,'configurationRestoreEquivalenceVerified':False,'crashRecoveryValidated':False,
            'independentAntiRollbackVerified':False,'actualProductWriterValidated':False,'independentMachine':False,'registryProvenanceVerified':False}
    known={};ever=set();active={};loaded=[];network=None;volume=None;bind_root=None;phase='preflight'
    project='dw-transition-'+uuid.uuid4().hex[:24]
    before_networks=None
    def write(fn):
        result['unknownWriteResult']=True
        value=fn();result['unknownWriteResult']=False
        return value
    def inspect(receipt):
        rows=json.loads(target.run('container','inspect',receipt))
        if len(rows)!=1 or rows[0]['Id']!=receipt:raise ValueError('container-identity-drift')
        return rows[0]
    def check(version):
        values={r:inspect(active[r]) for r in ROLES};checks={}
        for role,peer in (('backend','frontend'),('frontend','backend')):
            ip=values[peer]['NetworkSettings']['Networks'][project+'-net']['IPAddress']
            ipaddress.IPv4Address(ip)
            code=client_code(peer,peer,project,version,ip)
            def execute(role=role,peer=peer,code=code):
                value=json.loads(target.run('container','exec',active[role],'/usr/local/bin/python3','-c',code))
                keys={'sentinel_preserved','bind_read','bind_readonly','root_readonly'}
                if peer=='frontend':keys|={'volume_readonly','image_include_present'}
                if (type(value) is not dict or set(value)!={'role','token','version','checks'}
                        or (value['role'],value['token'],value['version'])!=(peer,project,version)
                        or type(value['checks']) is not dict or set(value['checks'])!=keys
                        or any(v is not True for v in value['checks'].values())):raise ValueError('transition-peer-mismatch')
                return value
            checks[peer]=write(execute)
        return checks
    try:
        fresh=json.loads(target.run('info','--format','{{json .}}'))
        if fresh.get('ID')!=info['ID'] or fresh.get('DockerRootDir')!=str(root/'data') or fresh.get('SwapLimit') is not True:
            raise ValueError('private-daemon-mismatch')
        production=json.loads(subprocess.run(['docker','--host',PRODUCTION,'info','--format','{{json .}}'],env=environment(),capture_output=True,check=True,timeout=30).stdout)
        if production['ID']==fresh['ID'] or target.run('ps','-aq').strip() or target.run('images','-aq').strip():raise ValueError('daemon-not-private-and-empty')
        before_networks=sorted(target.run('network','ls','-q','--no-trunc').split())
        if target.run('volume','ls','-q').strip():raise ValueError('private-volumes-not-empty')
        result['inventoryBaselineCaptured']=True
        images={v:source_image(ref) for v,ref in (('v1',IMAGE),('v2',V2))}
        # Reserve both images together; individual checks alone don't cover overlap.
        needed=sum(ensure_capacity(root,image) for image in images.values())
        if shutil.disk_usage(root).free<needed:raise ValueError('two-image-capacity-insufficient')
        if images['v1']['Id']==images['v2']['Id']:raise ValueError('transition-images-not-distinct')
        defaults={}
        for version,ref in (('v1',IMAGE),('v2',V2)):
            phase='import-'+version;image=images[version]
            write(lambda image=image:transfer_image(image['Id'],target));loaded.append(image['Id'])
            imported=json.loads(target.run('image','inspect',image['Id']))
            if len(imported)!=1 or any(json.dumps(imported[0].get(k),sort_keys=True)!=json.dumps(image.get(k),sort_keys=True) for k in ('Id','Os','Architecture','Config','RootFS')):
                raise ValueError('imported-image-drift')
            key=os.urandom(32)
            defaults[version]=derive_defaults(image,commit_image_config(image,'transition-test-key',key),key,
                expected_image_id=image['Id'],expected_registry_digest=ref,expected_architecture=image['Architecture'])
        phase='network-create'
        def create_network():
            value=target.run('network','create','--internal','--driver=bridge','--label=com.docker.compose.project='+project,project+'-net').strip()
            if not ID.fullmatch(value):raise ValueError('unknown-network-receipt')
            item=json.loads(target.run('network','inspect',value))[0]
            if (item['Id']!=value or item['Name']!=project+'-net' or item['Driver']!='bridge'
                    or item['Internal'] is not True or item['Labels'].get('com.docker.compose.project')!=project):
                raise ValueError('network-ownership-mismatch')
            return value
        network=write(create_network)
        phase='volume-create'
        def create_volume():
            name=project+'-data'
            if target.run('volume','create','--driver=local','--label=com.docker.compose.project='+project,name).strip()!=name:raise ValueError('unknown-volume-receipt')
            item=json.loads(target.run('volume','inspect',name))[0]
            if item['Name']!=name or item['Driver']!='local' or item['Labels'].get('com.docker.compose.project')!=project:
                raise ValueError('volume-ownership-mismatch')
            return name
        volume=write(create_volume)
        bind_root=Path(tempfile.mkdtemp(prefix=project+'-'))
        for index,(label,version) in enumerate((('initial','v1'),('v2','v2'),('rollback','v1'))):
            pending={};directory=bind_root/label;directory.mkdir()
            bind=directory/'config.txt';bind.write_text(project+'\n');bind.chmod(0o600)
            for role in ROLES:
                phase=label+'-'+role+'-create'
                (directory/(role+'-runtime.py')).write_text(server_code(role,project,version,index==0))
                (directory/(role+'-health.py')).write_text(client_code('127.0.0.1',role,project,version))
                recipe=transition_recipe(images[version],project,network,volume,str(bind),role,project)
                if index:recipe['containerName']+='-'+label
                candidate=compile_create(recipe,baseline_image_id=images[version]['Id'],image_defaults=defaults[version],
                    identity={'hostId':'transition-diagnostic','daemonId':info['ID'],'project':project,'service':role,'containerName':recipe['containerName']},
                    network_ids={project+'-net':network},allowed_mounts=deepcopy(recipe['mounts']),hostname=role)
                def create(candidate=candidate,role=role):
                    value=post(target,candidate);receipt=value.get('Id')
                    if type(receipt) is not str or not ID.fullmatch(receipt) or receipt in ever:raise ValueError('unknown-create-id')
                    known[receipt]={'running':False,'role':role};ever.add(receipt)
                    return receipt
                receipt=write(create);pending[role]=receipt
                observed=inspect(receipt)
                if observed['State']['Running'] is not False or observed['State']['Status']!='created':raise ValueError('candidate-not-stopped')
                comparison=compare_create_inspect_wire(candidate,observed,expected_receipt_id=receipt,image_defaults=defaults[version])
                if not comparison['requestedFieldsMatchUnderWireProfile']:raise ValueError('unexplained-create-difference')
            if index:
                phase=label+'-old-alias-check';check('v1' if index==1 else 'v2')
                phase=label+'-switch';switch(target,active,pending,known,write,project)
            active=pending
            for role in ROLES:
                phase=label+'-'+role+'-start'
                receipt=active[role]
                def start(receipt=receipt):
                    if target.run('container','start',receipt).strip()!=receipt:raise ValueError('unknown-start-response')
                    known[receipt]['running']=True
                write(start);wait_healthy(target.run,receipt)
            phase=label+'-peer-check'
            checks=check(version)
            result['stages'].append({'label':label,'version':version,'imageId':images[version]['Id'],
                'ids':dict(active),'peerChecks':checks,'sameVolume':volume})
        result['completed']=True
    except (OSError,ValueError,KeyError,TypeError,IndexError,http.client.HTTPException,subprocess.SubprocessError) as error:
        result['privateFailure']=diagnostic(error,phase)
    finally:
        if not result['unknownWriteResult'] and result['inventoryBaselineCaptured']:
            try:
                for receipt in reversed(list(known)):
                    if known[receipt]['running']:write(lambda receipt=receipt:target.stop(receipt))
                    write(lambda receipt=receipt:delete(target,receipt));result['cleanup'].append('container')
                if volume:
                    def remove_volume():
                        if target.run('volume','rm',volume).strip()!=volume:raise ValueError('unknown-volume-remove')
                    write(remove_volume)
                if network:
                    def remove_network():
                        if target.run('network','rm',network).strip()!=network:raise ValueError('unknown-network-remove')
                    write(remove_network)
                for image_id in loaded:write(lambda image_id=image_id:target.run('image','rm',image_id))
                if bind_root:shutil.rmtree(bind_root)
                if target.run('ps','-aq').strip() or target.run('images','-aq').strip() or target.run('volume','ls','-q').strip():
                    raise ValueError('private-inventory-not-empty')
                if sorted(target.run('network','ls','-q','--no-trunc').split())!=before_networks:
                    raise ValueError('private-network-inventory-changed')
                result['cleanupComplete']=True
            except (OSError,ValueError,http.client.HTTPException,subprocess.SubprocessError) as error:
                result['privateCleanupFailure']=diagnostic(error,'cleanup')
        result['success']=bool(result.get('completed') and len(result['stages'])==3 and result.get('cleanupComplete') and not result['unknownWriteResult'])
        result['imageRoundTripVerified']=bool(result['success'] and result['stages'][0]['imageId']==result['stages'][2]['imageId']
            and result['stages'][0]['imageId']!=result['stages'][1]['imageId'])
        result['volumeContinuityVerified']=bool(result['success'] and len({x['sameVolume'] for x in result['stages']})==1)
    return result
