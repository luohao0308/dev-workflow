"""Real mTLS source-retention gateway over the owned private Docker socket.

Keys are isolated diagnostic PKI, never enrolled as production trust.
"""
import hashlib
import http.client
from dataclasses import replace
import ssl
import subprocess
import threading
from pathlib import Path

from deployment_compose_reader_host import ComposeReaderHostPolicy, create_gateway
from deployment_compose_reader import ComposeReadPolicy, ComposeDockerReader
from deployment_compose_observation_host import ComposeObservationHost
from deployment_compose_artifacts import ComposeArtifacts
from deployment_compose_collect import collect
from deployment_compose_snapshot import _encode


def source_observer(root, target, identity, artifact, private_key, raw, networks, mounts):
    directory = root/'source-tls'; directory.mkdir(mode=0o700)
    def openssl(*args):
        result = subprocess.run(['openssl',*args],cwd=directory,capture_output=True,timeout=20)
        if result.returncode:
            raise ValueError('source-tls-certificate-generation-failed')
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem',
        '-days','1','-subj','/CN=Source retention diagnostic CA',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    for name in ('server','reader'):
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name)
        (directory/(name+'.ext')).write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+
            ('serverAuth' if name=='server' else 'clientAuth')+'\n')
        openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial',
            '-out',name+'.pem','-days','1','-extfile',name+'.ext')
    for path in directory.iterdir():path.chmod(0o600)
    def fingerprint(name):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory/(name+'.pem')).read_text())).hexdigest()
    volumes = {mount['source']:{'driver':'local','options':{}} for mount in mounts.values() if mount['type']=='volume'}
    service = artifact.service
    source_ids = (identity['containerId'],)
    scope = {'project':identity['project'],'daemonId':identity['daemonId'],'selectedServices':[service],
        'protectedServices':[],'protectedContainerIds':{},'protectedConfigHmacs':{},
        'selectedContainerIds':{service:identity['containerId']},'containerNames':{service:identity['containerName']},
        'imageIds':{service:artifact.image_id},'baselineSourceShas':{service:artifact.source_sha},
        'networks':networks,'volumes':volumes,
        'mounts':{service:[{'type':value['type'],'source':value['source'],'target':path,'readOnly':value['readOnly']}
                          for path,value in mounts.items()]},
        'networkAttachments':{service:{name:raw['NetworkSettings']['Networks'][name]['Aliases'] for name in networks}}}
    policy = ComposeReaderHostPolicy(identity['project'],identity['daemonId'],fingerprint('reader'),
        (service,),source_ids,(artifact.image_id,),tuple(sorted(networks.values())),tuple(sorted(volumes)),
        private_key_id=artifact.config_key_id,source_view=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory/'server.pem'),str(directory/'server.key'))
    context.load_verify_locations(str(directory/'ca.pem')); context.verify_mode=ssl.CERT_REQUIRED
    servers = []
    def gateway(host_policy):
        server = create_gateway(host_policy,tls_context=context,docker_socket=Path(target.socket),private_hmac_key=private_key)
        thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start();servers.append((server,thread))
        return server
    server = gateway(policy)
    whole_policy = replace(policy,source_view=False)
    whole = gateway(whole_policy)
    def close():
        for listener,worker in servers:
            listener.shutdown();worker.join(timeout=5);listener.server_close()
            if worker.is_alive():raise ValueError('source-tls-gateway-not-stopped')
    try:
        reader_policy = ComposeReadPolicy('https://localhost:'+str(server.server_port),fingerprint('server'),
            identity['daemonId'],identity['project'],tuple(sorted(volumes)),gateway_policy_hash=policy.digest(),
            private_key_id=artifact.config_key_id,source_container_ids=source_ids)
        observer = ComposeObservationHost(reader_policy=reader_policy,scope_policy=scope,
            baseline_artifacts=ComposeArtifacts(1,(artifact,)),ca_file=directory/'ca.pem',
            cert_file=directory/'reader.pem',key_file=directory/'reader.key',max_age_seconds=120)
        observation = observer.issue()
        if observation is None:
            audit=collect(observer._reader,scope)
            routes=['/v1.45/info',observer._reader.list_path,'/v1.45/containers/'+identity['containerId']+'/json',
                '/v1.45/workflow/private/'+identity['containerId'],'/v1.45/images/'+artifact.image_id+'/json']
            routes += ['/v1.45/networks/'+value for value in networks.values()]
            routes += ['/v1.45/volumes/'+value for value in volumes]
            audit['readFailureCodes']={}
            for route in routes:
                try: observer._reader.get(route)
                except Exception as error:audit['readFailureCodes'][route]=getattr(error,'code',type(error).__name__)
            path=root/'source-tls-failure.private.json';path.write_bytes(_encode(audit));path.chmod(0o600)
            raise ValueError('source-tls-observation-not-issued')
        if observer._test_only is not False or observer._reader._transport is not None or observer._reader._context is None:
            raise ValueError('source-tls-production-constructor-not-verified')
        whole_reader = ComposeDockerReader(ComposeReadPolicy('https://localhost:'+str(whole.server_port),
            fingerprint('server'),identity['daemonId'],identity['project'],tuple(sorted(volumes)),
            gateway_policy_hash=whole_policy.digest(),private_key_id=artifact.config_key_id),
            ca_file=directory/'ca.pem',cert_file=directory/'reader.pem',key_file=directory/'reader.key')
        def check_whole(expected_status):
            connection=http.client.HTTPSConnection('localhost',whole.server_port,context=whole_reader._context,timeout=10)
            try:
                connection.connect()
                if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()!=fingerprint('server'):
                    raise ValueError('whole-diagnostic-peer-pin-mismatch')
                connection.request('GET',whole_reader.list_path,headers={'Connection':'close'})
                response=connection.getresponse();body=response.read(65537)
                if response.status!=expected_status or len(body)>65536:
                    raise ValueError('whole-diagnostic-inventory-result-mismatch')
                return True
            finally:connection.close()
        check_whole(200)
        return observer,observation,close,{'realObservationTransportValidated':True,
            'productionTrustEnrolled':False,'viewKind':observer.scope_kind,'projectCompletenessVerified':False,
            'bootInfo':observer._reader.gateway_info(),'sourceIds':list(source_ids),
            'wholeInventoryAcceptedBeforeCandidate':True},check_whole
    except Exception:
        close();raise
