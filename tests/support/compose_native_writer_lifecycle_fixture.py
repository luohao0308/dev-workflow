"""Opt-in root/systemd diagnostic for native checkpoint identity and stopped reads.

The owned unit executes the normal cold SDK against Engine/GitHub doubles only.
The registration, managed-unit identity, original owner stop and fresh stopped
observer use real Linux kernel/systemd APIs. It never contacts Docker production.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import types

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT/path) for path in
    ('scripts','packs/deployment/scripts','packs/release/scripts','tests/support'))]
_RETAINED = []

import deployment_compose_owned_recovery_unit_v3_host as units
from deployment_compose_witness_store import canonical


class NativeDiagnosticUnit(units.OwnedRecoveryUnitV3):
    def __init__(self, directory, source_sha, archive_digest):
        super().__init__(archive_digest,source_sha)
        paths = [str(ROOT), *(str(ROOT/path) for path in
            ('scripts','packs/deployment/scripts','packs/release/scripts','tests/support'))]
        # No import may spawn a helper process before start() establishes that
        # the cgroup contains exactly its actual MainPID.
        self._code = '''import sys,signal
signal.alarm(150)
if sys.stdin.buffer.readline()!=b'GO\\n':raise ValueError('GO required')
sys.path[:0]=PATHS
from pathlib import Path
import json
from tests.support.compose_native_writer_lifecycle_fixture import produce
value=produce(Path(DIRECTORY),SOURCE,ARCHIVE)
print(json.dumps(value),flush=True)
sys.stdin.buffer.readline()
'''.replace('PATHS',repr(paths)).replace('DIRECTORY',repr(str(directory))).replace('SOURCE',repr(source_sha)).replace('ARCHIVE',repr(archive_digest))


def write_private(path, raw):
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw)


def retain_parent_owned_temporaries(owned, temporaries):
    """The diagnostic manager removes these fixtures after its fresh cold read.

    SIGTERM in the fixed loader unwinds Python normally. TemporaryDirectory's
    at-exit cleanup would otherwise remove the retained CAS/signers too early.
    """
    owned = owned.resolve()
    for temporary in temporaries:
        if (type(temporary) is not tempfile.TemporaryDirectory
                or not Path(temporary.name).resolve().is_relative_to(owned)):
            raise ValueError('only parent-owned diagnostic fixtures may outlive producer')
    for temporary in temporaries:
        temporary._finalizer.detach()


def produce(directory, source_sha, archive_digest, *, loaded_source=None):
    from tests import test_deployment_compose_cold_recovery_v3_host as sdk
    from tests.test_deployment_compose_native_writer_lifecycle_v3_host import NativeLifecycleTests
    owned = directory/'owned-temp'
    owned.mkdir(mode=0o700)
    tempfile.tempdir = str(owned)
    sdk.ColdRecoveryTests.setUpClass()
    helper,host,lifecycle,(args,kwargs) = NativeLifecycleTests.partial_host(
        writer_source_sha=source_sha,writer_archive_digest=archive_digest,allowed_engine_root=directory,loaded_source=loaded_source)
    import deployment_compose_native_writer_lifecycle_v3_host as native
    if (type(native._capture_current_origin) is not types.FunctionType
            or native._capture_current_origin.__module__!='deployment_compose_native_writer_lifecycle_v3_host'
            or type(native.cold.observe_stopped_writer) is not types.FunctionType
            or native.cold.observe_stopped_writer.__module__!='deployment_compose_cold_writer_v3_host'
            or not Path(host._socket).is_relative_to(directory)):
        raise ValueError('native functions and isolated test Engine must be original')
    _RETAINED.append((helper,host,lifecycle,args,kwargs))
    descriptor = host.capture_native_checkpoint(**NativeLifecycleTests.checkpoint_maps(host))
    # Extract the original independent witness fixture from this fixed test
    # transport, never from business material or an arbitrary caller origin.
    transport = kwargs['witness_transport']
    scope = dict(zip(transport.__code__.co_freevars,(cell.cell_contents for cell in transport.__closure__)))
    witness = scope['h']
    if loaded_source is not None:
        from tests.test_deployment_compose_recovery_host import _TEMP_ROOTS
        archives = tuple(t for t in _TEMP_ROOTS if Path(t.name).resolve()==Path(host._store._root))
        if len(archives)!=1:
            raise ValueError('original diagnostic CAS temporary owner required')
        retain_parent_owned_temporaries(owned,(helper.temp,witness.temp,sdk.ColdRecoveryTests.temp,*archives))
    record = json.loads(host._store.get(descriptor['recordReference']))
    if record['origin']['mainPid']!=os.getpid():
        raise ValueError('checkpoint did not bind current managed MainPID')
    config = dict(descriptor=descriptor,storeRoot=host._store._root,
        storeKey=base64.b64encode(host._store._key).decode('ascii'),
        witnessRoot=str(witness.store.root),witnessKey=base64.b64encode(witness.store._key).decode('ascii'),
        signingPath=str(witness.key),public=base64.b64encode(witness.public).decode('ascii'),
        dockerSocket=str(kwargs['docker_socket']),daemonVersion=kwargs['daemon_version'],
        dockerRoot=kwargs['expected_docker_root'])
    write_private(directory/'consumer.private.json',canonical(config))
    # Deliberately retain the fixture files under the driver's private directory
    # until that original driver has stopped/reaped this owned service.
    return dict(mainPid=os.getpid(),originDigest=descriptor['originDigest'],writeIndex=record['writeIndex'],
                sourceRevalidated=False,productionReady=False)


def observe(config_path):
    from deployment_compose_recovery_store import ComposeRecoveryStore
    from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
    from deployment_compose_operation_witness_client_v3 import dispatch_request,encode,NAMESPACE
    from deployment_compose_native_writer_lifecycle_v3_host import load_native_checkpoint
    from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
    import deployment_compose_cold_writer_v3_host as native_cold
    if type(native_cold.observe_stopped_writer) is not types.FunctionType or native_cold.observe_stopped_writer.__module__!='deployment_compose_cold_writer_v3_host':
        raise ValueError('native stop checker is patched')
    value = json.loads(config_path.read_bytes())
    store = ComposeRecoveryStore(value['storeRoot'],key=base64.b64decode(value['storeKey']))
    witness = OperationWitnessStoreV3(Path(value['witnessRoot']),key=base64.b64decode(value['witnessKey']))
    public = base64.b64decode(value['public'])
    def transport(method,request):
        if method not in ('read','check','events_after','chain_status'):
            raise ValueError('diagnostic consumer is read-only')
        payload = dispatch_request(witness,method,request)
        result = subprocess.run(['/usr/bin/ssh-keygen','-Y','sign','-f',value['signingPath'],'-n',NAMESPACE],
            input=encode(payload),capture_output=True,check=True,timeout=10)
        return dict(payload=payload,signature=base64.b64encode(result.stdout).decode('ascii'))
    try:
        descriptor = value['descriptor']
        observer = load_native_checkpoint(descriptor,store=store,gate_key=b'g'*32,pub=public,readonly_transport=transport)
        host = ColdRecoveryHostV3(store.get(descriptor['materialReference']),expected_digest=descriptor['materialDigest'],
            expected_context=descriptor['context'],gate_key=b'g'*32,witness_public_key=public,witness_transport=transport,
            store=store,docker_socket=Path(value['dockerSocket']),daemon_version=value['daemonVersion'],
            expected_docker_root=value['dockerRoot'],readiness=lambda *_:False,native_stop_observer=observer)
        try:
            result = observer.observe_for(host)
        except ValueError:
            return dict(nativeRejected=True,writerStoppedObserved=False,consumerPid=os.getpid(),productionReady=False)
        return dict(nativeRejected=False,writerStoppedObserved=result.writerStoppedObserved,
            consumerPid=os.getpid(),originDigest=result.origin_digest,runtimePermit=result.runtimePermit,
            linuxQuiescenceVerified=result.linuxQuiescenceVerified,sourceRevalidated=False,productionReady=False)
    finally:
        witness.close()
        store.close()


def read_ready(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ)
        if not selector.select(120):
            raise TimeoutError('native checkpoint producer did not publish')
    raw = process.stdout.readline(8193)
    if not raw or len(raw)>8192:
        raise ValueError('bounded producer reply required')
    return json.loads(raw)


def run_kernel_diagnostic(source_sha, archive_digest):
    units._environment()
    directory = Path(tempfile.mkdtemp(prefix='dw-native-life-',dir='/var/tmp')).resolve()
    directory.chmod(0o700)
    owner = NativeDiagnosticUnit(directory,source_sha,archive_digest)
    try:
        owner.start(timeout=30)
        original = owner.capture_origin(timeout=5)
        owner._process.stdin.write(b'GO\n')
        owner._process.stdin.flush()
        ready = read_ready(owner._process)
        if ready['mainPid']!=owner._pid[0] or ready['originDigest']!=hashlib.sha256(original).hexdigest():
            raise ValueError('native checkpoint and original manager origin differ')
        command = [sys.executable,'-I',str(Path(__file__).resolve()),'observe',str(directory/'consumer.private.json')]
        active = json.loads(subprocess.run(command,capture_output=True,text=True,check=True,timeout=45).stdout)
        if not active['nativeRejected'] or active['writerStoppedObserved']:
            raise ValueError('active original writer accepted')
        owner.stop(timeout=60)
        stopped = json.loads(subprocess.run(command,capture_output=True,text=True,check=True,timeout=45).stdout)
        if (stopped['nativeRejected'] or not stopped['writerStoppedObserved']
                or stopped['originDigest']!=ready['originDigest'] or stopped['consumerPid']==ready['mainPid']):
            raise ValueError('fresh consumer did not verify original writer stopped')
        return dict(nativeCurrentMainPidBound=True,knownClosedWriteIndex=ready['writeIndex'],
            activeWriterRejected=True,originalOwnedUnitStopped=True,originalProcessReaped=True,
            freshConsumerObservedStopped=True,realDockerWrites=0,businessEngine='double',
            sourceRevalidated=False,linuxQuiescenceVerified=False,runtimePermit=False,productionReady=False)
    finally:
        primary = sys.exc_info()[1]
        try:
            if owner._invocation is not None and not owner._stopped:
                owner.stop(timeout=60)
            if owner._stopped:
                owner.close()
                shutil.rmtree(directory)
        except BaseException as error:
            if primary is None:
                raise
            if hasattr(primary,'add_note'):
                primary.add_note('native diagnostic cleanup failed: '+type(error).__name__)


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=('run','observe'))
    parser.add_argument('config',nargs='?')
    parser.add_argument('--source-sha')
    parser.add_argument('--archive-digest')
    args = parser.parse_args()
    result = observe(Path(args.config)) if args.action=='observe' else run_kernel_diagnostic(args.source_sha,args.archive_digest)
    print(json.dumps(result),flush=True)
