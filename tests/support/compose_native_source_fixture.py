"""Fixed-archive native cold SDK diagnostic; Engine and GitHub are doubles.

The manager owns only its random diagnostic unit and private temporary directory.
Building an archive verifies pinned Git contents without claiming current release
publication. No production Docker endpoint is contacted.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts', 'tests/support'))]
import deployment_compose_native_source_v3_host as source
from deployment_compose_checkpoint_source_v3_host import _verify_archive
from deployment_compose_owned_recovery_unit_v3_host import OwnedRecoveryUnitV3
from deployment_compose_v3_channel_worker import write_frame


def build_archive(repository, source_sha):
    """Build the closed diagnostic profile from pinned Git objects, not files."""
    def git(*args):
        return subprocess.run(['/usr/bin/git', '--no-replace-objects', '-C', str(repository), *args],
                              capture_output=True, check=True, timeout=30).stdout
    names = git('ls-tree', '-r', '--name-only', '-z', source_sha).decode().split('\0')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zipped:
        for name in sorted(name for name in names if name and source.allowed(name)):
            zipped.writestr(name, git('show', source_sha + ':' + name))
    raw = output.getvalue()
    _verify_archive(raw, repository=repository, source_sha=source_sha,
                    archive_digest=hashlib.sha256(raw).hexdigest(), profile=source.PROFILE, timeout=30)
    return raw


def read_frame(process, deadline):
    def exact(size):
        data = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while len(data) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('native source diagnostic reply deadline')
                chunk = os.read(process.stdout.fileno(), size-len(data))
                if not chunk:
                    raise ValueError('native source diagnostic EOF')
                data.extend(chunk)
        return bytes(data)
    size = struct.unpack('!I', exact(4))[0]
    if not 0 < size <= 8192:
        raise ValueError('bounded diagnostic reply required')
    return json.loads(exact(size))


def run(archive, source_sha, archive_digest, *, kill_producer=False):
    if hashlib.sha256(archive).hexdigest() != archive_digest:
        raise ValueError('independent archive pin mismatch')
    source.archive_files(archive)
    directory = Path(tempfile.mkdtemp(prefix='dw-native-source-life-', dir='/var/tmp')).resolve()
    directory.chmod(0o700)
    owner = OwnedRecoveryUnitV3(archive_digest, source_sha, disable_site=True)
    owner._code = source.diagnostic_bootstrap(source_sha, archive_digest)
    nonce = secrets.token_hex(32)
    try:
        owner.start(timeout=30)
        origin = owner.capture_origin(timeout=5)
        write_frame(owner._process.stdin, dict(entrypoint=source.ENTRYPOINT,sourceSha=source_sha,
            archiveDigest=archive_digest,channelNonce=nonce,diagnosticDirectory=str(directory),
            archiveBase64=base64.b64encode(archive).decode('ascii')), timeout=30)
        ready = read_frame(owner._process, time.monotonic()+120)
        result = ready['result']
        if (ready['channelNonce'] != nonce or result['mainPid'] != owner._pid[0]
                or result['originDigest'] != hashlib.sha256(origin).hexdigest()
                or result['loaderArchiveVerified'] is not True):
            raise ValueError('original owner and fixed loader checkpoint differ')
        descriptor = json.loads((directory/'consumer.private.json').read_bytes())['descriptor']
        if (type(descriptor['schemaVersion']) is not int or descriptor['schemaVersion'] != 2
                or descriptor['loadedSource']['sourceSha'] != source_sha
                or descriptor['loadedSource']['archiveDigest'] != archive_digest
                or descriptor['loadedSource']['channelNonce'] != nonce
                or descriptor['loadedSource']['entrypoint'] != source.ENTRYPOINT
                or descriptor['loadedSource']['loaderArchiveVerified'] is not True):
            raise ValueError('checkpoint does not retain original loaded archive')
        # These readers load their code from the independently supplied manager
        # checkout. The producer itself was launched only from the stdin ZIP.
        command = [sys.executable,'-I','-S',str(ROOT/'tests/support/compose_native_writer_lifecycle_fixture.py'),
                   'observe',str(directory/'consumer.private.json')]
        def observe():
            reply = subprocess.run(command,capture_output=True,text=True,timeout=45)
            if reply.returncode:
                raise RuntimeError('isolated consumer failed: '+reply.stderr[-6000:])
            return json.loads(reply.stdout)
        active = observe()
        if not active['nativeRejected'] or active['writerStoppedObserved']:
            raise ValueError('active archive-loaded writer accepted')
        if kill_producer:
            # Hold this exact process across the final owner identity check.
            # A reused numeric PID cannot redirect this diagnostic SIGKILL.
            pidfd = os.pidfd_open(owner._pid[0])
            try:
                if owner.capture_origin(timeout=5) != origin:
                    raise ValueError('original producer changed before SIGKILL')
                signal.pidfd_send_signal(pidfd,signal.SIGKILL)
            finally:
                os.close(pidfd)
        owner.stop(timeout=60)
        stopped = observe()
        if (stopped['nativeRejected'] or not stopped['writerStoppedObserved']
                or stopped['originDigest'] != result['originDigest'] or stopped['consumerPid']==result['mainPid']):
            raise ValueError('fresh reader did not authenticate archive-loaded writer stop')
        return dict(loaderArchiveVerified=True,producerUsedIsolatedArchive=True,siteDisabled=True,
            nativeCurrentMainPidBound=True,activeWriterRejected=True,originalOwnedUnitStopped=True,
            freshConsumerObservedStopped=True,retainedArchiveReverified=True,knownClosedWriteIndex=result['writeIndex'],
            producerSigkill=kill_producer,parentCleanupCompleted=True,
            realDockerWrites=0,businessEngine='double',gitHub='double',currentPublicationVerified=False,
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
                primary.add_note('native source diagnostic cleanup failed: '+type(error).__name__)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=('build','run'))
    parser.add_argument('--source-sha',required=True)
    parser.add_argument('--archive',required=True)
    parser.add_argument('--archive-digest')
    parser.add_argument('--kill-producer',action='store_true')
    args = parser.parse_args()
    if args.action == 'build':
        raw = build_archive(ROOT,args.source_sha)
        fd = os.open(args.archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw)
        print(json.dumps(dict(sourceSha=args.source_sha,archiveDigest=hashlib.sha256(raw).hexdigest())))
    else:
        print(json.dumps(run(Path(args.archive).read_bytes(),args.source_sha,args.archive_digest,
                             kill_producer=args.kill_producer)))
