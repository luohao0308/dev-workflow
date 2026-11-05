"""Fixed read-only attachment to the scene's original independently owned daemon.

Distribution equality authenticates runtime bytes under the trusted embedding;
it is not business-source revalidation, approval, dispatch or a writer permit.
"""
import base64
import hashlib
import io
import os
from pathlib import Path,PurePosixPath
import secrets
import selectors
import stat
import time
import zipfile

from deployment_compose_owned_recovery_unit_v3_host import OwnedRecoveryUnitV3
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_profile3_prepare_ssh_probe import _allowed
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical
from deployment_compose_v3_channel_worker import write_frame
from deployment_compose_daemon_owner_v3_host import _receive,_finish

ROOT=Path(__file__).resolve().parents[1]
ENTRYPOINT='deployment_compose_scene_attach_read_v3_host.run'
_FALSE=('authorityGranted','runtimePermit','recoveryAuthorized','productionReady','writerQuiescenceVerified','executionAvailable')


def reject():raise ValueError('compose-scene-attach-read-v3-rejected') from None


def digest(raw):return hashlib.sha256(raw).hexdigest()


def _left(end):
    left=end-time.monotonic()
    if left<=0:reject()
    return left


def validate_distribution_archive(raw,expected_digest):
    try:
        if type(raw) is not bytes or not 0<len(raw)<=2*1024*1024 or digest(raw)!=expected_digest:reject()
        files={p.relative_to(ROOT).as_posix():p for p in ROOT.rglob('*.py') if _allowed(p.relative_to(ROOT).as_posix())}
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names=archive.namelist()
            if len(names)!=len(set(names)) or set(names)!=set(files) or len(names)>1024:reject()
            if sum(info.file_size for info in archive.infolist())>16*1024*1024:reject()
            for info in archive.infolist():
                path=PurePosixPath(info.filename);mode=info.external_attr>>16
                if (path.is_absolute() or '..' in path.parts or str(path)!=info.filename
                        or info.is_dir() or info.flag_bits&1 or stat.S_IFMT(mode) not in (0,stat.S_IFREG)):reject()
                local=files[info.filename]
                if not stat.S_ISREG(local.lstat().st_mode) or archive.read(info)!=local.read_bytes():reject()
        return raw
    except Exception:reject()


class AttachReadUnitV3(OwnedRecoveryUnitV3):
    def __init__(self,archive_digest,source_sha):
        super().__init__(archive_digest,source_sha)
        module='deployment_compose_owned_recovery_worker_v3_host'
        if self._code.count(module)!=2:reject()
        self._code=self._code.replace(module,'deployment_compose_scene_attach_read_v3_host')


def run(config,stdin,stdout):
    observer=None
    try:
        end=time.monotonic()+15
        if (type(config) is not dict or set(config)!={'entrypoint','sourceSha','archiveDigest','channelNonce','daemonBinding'}
                or config['entrypoint']!=ENTRYPOINT):reject()
        for key,size in (('sourceSha',40),('archiveDigest',64),('channelNonce',64)):
            if type(config[key]) is not str or len(config[key])!=size or any(c not in '0123456789abcdef' for c in config[key]):reject()
        binding=decode(canonical(config['daemonBinding']))
        with selectors.DefaultSelector() as selector:
            selector.register(stdin,selectors.EVENT_READ)
            if not selector.select(min(5,_left(end))) or os.read(stdin.fileno(),1):reject()
        observer=ObservedRecoveryDaemonV3(binding['root'],binding['daemonId'],kernel_boot=binding['kernelBoot'],timeout=min(10,_left(end)))
        if canonical(observer.binding())!=canonical(binding):reject()
        inventory=observer._resources(end)
        if canonical(observer.binding())!=canonical(binding):reject()
        value=dict(kind='scene-attach-read-v3',channelNonce=config['channelNonce'],sourceSha=config['sourceSha'],
            archiveDigest=config['archiveDigest'],bindingDigest=digest(canonical(binding)),inventoryDigest=digest(inventory),
            readOnly=True,**{key:False for key in _FALSE})
        observer.close();observer=None
        write_frame(stdout,value,timeout=_left(end))
    except Exception:reject()
    finally:
        if observer is not None:observer.close()


def run_attached_read(unit,raw_archive,daemon_binding,*,source_sha,archive_digest,timeout=15):
    try:
        if type(unit) is not AttachReadUnitV3 or type(raw_archive) is not bytes or digest(raw_archive)!=archive_digest:reject()
        unit._check()
        if unit._source_sha!=source_sha or unit._archive_digest!=archive_digest:reject()
        process=unit._process
        if process is None or process.poll() is not None:reject()
        end=time.monotonic()+timeout;nonce=secrets.token_hex(32)
        binding=decode(canonical(daemon_binding))
        config=dict(entrypoint=ENTRYPOINT,sourceSha=source_sha,archiveDigest=archive_digest,
                    channelNonce=nonce,daemonBinding=binding)
        write_frame(process.stdin,dict(config,archiveBase64=base64.b64encode(raw_archive).decode('ascii')),timeout=_left(end))
        process.stdin.close()
        record=dict(process=process,stderr_eof=False,stderr_bytes=0)
        value=_receive(record,end);_finish(record,end)
        expected=dict(kind='scene-attach-read-v3',channelNonce=nonce,sourceSha=source_sha,archiveDigest=archive_digest,
            bindingDigest=digest(canonical(binding)),readOnly=True,**{key:False for key in _FALSE})
        if (type(value) is not dict or set(value)!=set(expected)|{'inventoryDigest'}
                or any(canonical(value[k])!=canonical(v) for k,v in expected.items())
                or type(value['inventoryDigest']) is not str or len(value['inventoryDigest'])!=64
                or any(c not in '0123456789abcdef' for c in value['inventoryDigest'])):reject()
        _left(end)
        return value
    except Exception:reject()
