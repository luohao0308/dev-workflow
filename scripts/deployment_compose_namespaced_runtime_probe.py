"""Diagnostic cached-image transfer and runtime probe on an owned private daemon.

Caller first verifies namespace, PID, socket, limits and private containerd.
Only production image inspect/save are allowed here; all workload writes use
the exact private socket. No registry contact or execution authority is proved.
"""
import http.client
import json
import os
from pathlib import Path
import re
import socket
import shutil
import subprocess
import tempfile

from deployment_compose_log_probe import IMAGE, ID
from deployment_compose_runtime_probe import probe

PRODUCTION = 'unix:///var/run/docker.sock'


def environment():
    env = dict(os.environ, DOCKER_API_VERSION='1.45')
    for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        env.pop(name, None)
    return env


class PrivateDaemon:
    def __init__(self, root, info):
        if (not isinstance(root, Path) or root.parent != Path('/var/tmp')
                or not re.fullmatch('dw-engine-[a-f0-9]{16}', root.name)
                or type(info) is not dict or type(info.get('ID')) is not str
                or not 1 <= len(info['ID']) <= 256
                or info.get('DockerRootDir') != str(root/'data')):
            raise ValueError('invalid-private-runtime-scope')
        self.socket = str(root/'docker.sock')
        self.host = 'unix://' + self.socket
        self.daemon_id = info['ID']

    def run(self, *args):
        return subprocess.run(['docker', '--host', self.host, *args], env=environment(),
            capture_output=True, check=True, timeout=30).stdout.decode('utf-8')

    def connection(self):
        path=self.socket
        class UnixConnection(http.client.HTTPConnection):
            def connect(self):
                sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                try:
                    sock.settimeout(25);sock.connect(path)
                except BaseException:
                    sock.close();raise
                self.sock=sock
        connection=UnixConnection('localhost',timeout=25)
        connection.connect()
        return connection

    def post(self, candidate):
        if (type(candidate) is not dict or candidate.get('method') != 'POST'
                or type(candidate.get('path')) is not str
                or not re.fullmatch(r'/v1\.45/containers/create\?name=dw-compose-sample-[a-f0-9]{24}-(?:backend|frontend)',candidate['path'])):
            raise ValueError('invalid-private-create-operation')
        connection = self.connection()
        try:
            connection.request('POST', candidate['path'], json.dumps(candidate['body']),
                               {'Content-Type':'application/json'})
            response = connection.getresponse();body=response.read(1024*1024+1)
            if response.status != 201 or len(body)>1024*1024:
                raise ValueError('unknown-private-create-response')
            return json.loads(body)
        finally:
            connection.close()

    def stop(self, receipt):
        if type(receipt) is not str or not ID.fullmatch(receipt):
            raise ValueError('invalid-private-stop-id')
        connection = self.connection()
        try:
            connection.request('POST','/v1.45/containers/'+receipt+'/stop?t=10')
            response=connection.getresponse();body=response.read(4097)
            if response.status not in (204,304) or body:
                raise ValueError('unknown-private-stop-response')
            return receipt
        finally:
            connection.close()


def production_read(*args):
    if args != ('info','--format','{{json .}}') and args != ('image','inspect',IMAGE):
        raise ValueError('production-read-scope-rejected')
    return subprocess.run(['docker','--host',PRODUCTION,*args],env=environment(),
        capture_output=True,check=True,timeout=30).stdout.decode('utf-8')


def transfer_image(image_id, destination):
    if (type(image_id) is not str or not re.fullmatch('sha256:[a-f0-9]{64}',image_id)
            or type(destination) is not PrivateDaemon
            or not re.fullmatch(r'unix:///var/tmp/dw-engine-[a-f0-9]{16}/docker.sock',destination.host)):
        raise ValueError('invalid-transfer-image-id')
    processes=[]
    try:
        with tempfile.TemporaryFile() as errors:
            source=subprocess.Popen(['docker','--host',PRODUCTION,'image','save',image_id],
                env=environment(),stdout=subprocess.PIPE,stderr=errors)
            processes.append(source)
            target=subprocess.Popen(['docker','--host',destination.host,'image','load'],
                env=environment(),stdin=source.stdout,stdout=errors,stderr=errors)
            processes.append(target)
            source.stdout.close()
            target.wait(timeout=180);source.wait(timeout=15)
            if source.returncode or target.returncode:
                raise ValueError('private-image-transfer-failed')
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
        for process in processes:
            process.wait(timeout=10)


def ensure_capacity(root,image):
    size=image.get('Size');layers=image.get('RootFS',{}).get('Layers')
    if (type(size) is not int or not 0<size<=4*1024**3
            or type(layers) is not list or not 1<=len(layers)<=64):
        raise ValueError('unbounded-source-image-size')
    # Image layer deep copies + two container roots + one import staging copy.
    required=size*(len(layers)+3)+1024**3
    if shutil.disk_usage(root).free<required:
        raise ValueError('insufficient-private-vfs-disk-headroom')
    return required


def run_runtime(root, info):
    destination=PrivateDaemon(root,info)
    fresh=json.loads(destination.run('info','--format','{{json .}}'))
    production=json.loads(production_read('info','--format','{{json .}}'))
    if (fresh.get('ID') != destination.daemon_id or fresh.get('DockerRootDir') != str(root/'data')
            or fresh.get('ID') == production.get('ID')):
        raise ValueError('private-daemon-identity-mismatch')
    if fresh.get('SwapLimit') is not True:
        raise ValueError('private-daemon-swap-limit-unavailable')
    if destination.run('ps','-aq').strip() or destination.run('images','-aq').strip():
        raise ValueError('private-runtime-daemon-not-empty')
    images=json.loads(production_read('image','inspect',IMAGE))
    if len(images)!=1 or IMAGE not in images[0].get('RepoDigests',[]):
        raise ValueError('unexpected-cached-source-image')
    original=images[0]
    required=ensure_capacity(root,original)
    transfer_image(original['Id'],destination)
    result=probe(destination.run,destination.post,stop=destination.stop,image_evidence=original)
    result['importedImageRemoved']=False
    if result.get('success') is True:
        result['unknownWriteResult']=True
        try:
            destination.run('image','rm',original['Id'])
            if destination.run('images','-aq').strip():
                raise ValueError('private-image-cleanup-incomplete')
            result['importedImageRemoved']=True
            result['unknownWriteResult']=False
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            result['success']=False
            result['privateImageCleanupFailure']={'type':type(error).__name__}
    result.update(requiredDiskHeadroomBytes=required,sharedHost=True,independentMachine=False,registryProvenanceVerified=False,
                  productionReady=False,authorityGranted=False,executionAvailable=False)
    return result
