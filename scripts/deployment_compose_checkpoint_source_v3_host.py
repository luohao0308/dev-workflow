"""Compare the retained published loader ZIP to pinned Git object contents.

This is not current-ref authentication, business-source validation or a permit.
Only the original dev-workflow publication subset is checked. No fetch, checkout,
source execution, filters or archive reconstruction occurs.
"""
from dataclasses import dataclass, field
import hashlib
import io
import math
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import time
import zipfile

from deployment_compose_profile3_prepare_ssh_probe import ORIGIN, MAX_ARCHIVE, MAX_SOURCE, _allowed
from deployment_compose_witness_store import canonical

MAX_ENTRIES=4096
MAX_TREES=1024
REQUIRED={'scripts/deployment_compose_profile3_prepare_ssh_probe.py',
          'scripts/deployment_compose_isolated_daemon_probe.py',
          'scripts/deployment_gateway_host.py','tests/support/compose_profile3_prepare_fixture.py'}


def reject():raise ValueError('compose-checkpoint-published-source-v3-rejected') from None


def digest(raw):return hashlib.sha256(raw).hexdigest()


class _Git:
    def __init__(self,repository,end):
        if os.name!='posix' or not isinstance(repository,Path) or not repository.is_absolute():reject()
        self.repository=repository.resolve(strict=True);self.end=end
        self.env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
            'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null',
            'GIT_NO_REPLACE_OBJECTS':'1','GIT_NO_LAZY_FETCH':'1','GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0'}
        self.entries=0;self.trees=0;self.total=0
        if self.run(['rev-parse','--show-toplevel'],4096).decode().strip()!=str(self.repository):reject()
        # Older Git versions may ignore GIT_NO_LAZY_FETCH. Refuse partial/promisor
        # repositories, including settings supplied through local includes.
        configuration=self.run(['config','--includes','--null','--name-only','--list'],65536)
        for item in configuration.split(b'\0'):
            key=item.lower()
            if key==b'extensions.partialclone' or (key.startswith(b'remote.') and key.endswith(b'.promisor')):reject()

    def left(self):
        value=self.end-time.monotonic()
        if value<=0:reject()
        return value

    def run(self,args,limit):
        self.left()
        command=['/usr/bin/git','--no-replace-objects','-c','core.fsmonitor=false',
            '-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-C',str(self.repository),*args]
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=self.env,close_fds=True)
        output=bytearray();errors=bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ,output)
                selector.register(process.stderr,selectors.EVENT_READ,errors)
                while selector.get_map():
                    ready=selector.select(self.left())
                    if not ready:reject()
                    for key,_ in ready:
                        target=key.data;bound=limit if target is output else 4096
                        raw=os.read(key.fileobj.fileno(),min(65536,bound+1-len(target)))
                        if not raw:selector.unregister(key.fileobj);continue
                        target.extend(raw)
                        if len(target)>bound:reject()
            if process.wait(timeout=self.left()) or errors:reject()
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill();process.wait(timeout=2)
            process.stdout.close();process.stderr.close()

    def origin(self):
        if self.run(['config','--no-includes','--local','--get-all','remote.origin.url'],4096)!=ORIGIN.encode()+b'\n':reject()

    def object(self,kind,oid,limit):
        if re.fullmatch('[0-9a-f]{40}',oid) is None:reject()
        size=self.run(['cat-file','-s',oid],32).strip()
        if not size.isdigit() or int(size)>limit:reject()
        raw=self.run(['cat-file',kind,oid],int(size))
        if len(raw)!=int(size) or hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=oid:reject()
        return raw

    def files(self,source_sha):
        commit=self.object('commit',source_sha,1024*1024)
        first=commit.split(b'\n',1)[0]
        if re.fullmatch(rb'tree [0-9a-f]{40}',first) is None:reject()
        files={}
        def tree(oid,prefix,depth):
            self.trees+=1
            if depth>32 or self.trees>MAX_TREES:reject()
            raw=self.object('tree',oid,1024*1024);position=0;names=set()
            while position<len(raw):
                space=raw.index(b' ',position);zero=raw.index(b'\0',space+1)
                mode=raw[position:space];name=raw[space+1:zero].decode('utf-8')
                if not name or name in ('.','..') or '/' in name or '\\' in name or name in names:reject()
                names.add(name);oid_bytes=raw[zero+1:zero+21]
                if len(oid_bytes)!=20:reject()
                child=oid_bytes.hex();path=prefix+name;position=zero+21
                self.entries+=1
                if self.entries>MAX_ENTRIES:reject()
                if mode==b'40000':tree(child,path+'/',depth+1)
                elif _allowed(path):
                    if mode not in (b'100644',b'100755') or path in files:reject()
                    payload=self.object('blob',child,MAX_SOURCE-self.total)
                    self.total+=len(payload)
                    files[path]=(payload,mode.decode(),child)
        tree(first[5:].decode(),'',0)
        if not REQUIRED<=files.keys() or not 0<len(files)<=1024:reject()
        return files


def _verify_archive(raw,*,repository,source_sha,archive_digest,timeout=15):
    if (type(raw) is not bytes or not 0<len(raw)<=MAX_ARCHIVE or digest(raw)!=archive_digest
            or type(source_sha) is not str or re.fullmatch('[0-9a-f]{40}',source_sha) is None
            or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=30):reject()
    git=_Git(repository,time.monotonic()+timeout);git.origin();files=git.files(source_sha)
    manifest=[];total=0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members=archive.infolist();names=[info.filename for info in members]
        if len(members)>1024 or len(names)!=len(set(names)) or set(names)!=set(files):reject()
        for info in sorted(members,key=lambda item:item.filename):
            git.left();path=PurePosixPath(info.filename)
            if (info.orig_filename!=info.filename or path.is_absolute() or any(p in ('.','..') for p in info.filename.split('/'))
                    or str(path)!=info.filename or not _allowed(info.filename) or info.is_dir()
                    or info.flag_bits&(1|64) or stat.S_IFMT(info.external_attr>>16) not in (0,stat.S_IFREG)
                    or info.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)
                    or not 0<=info.file_size<=MAX_SOURCE-total):reject()
            expected,mode,oid=files[info.filename]
            if info.file_size!=len(expected):reject()
            with archive.open(info) as stream:payload=stream.read(info.file_size+1)
            if payload!=expected:reject()
            total+=len(payload)
            manifest.append(dict(path=info.filename,mode=mode,blob=oid,size=len(payload),sha256=digest(payload)))
    git.origin();git.left()
    return canonical(manifest)


@dataclass(frozen=True)
class VerifiedCheckpointPublishedSourceV3:
    manifest_bytes: bytes = field(repr=False)
    source_sha: str
    archive_digest: str
    material_digest: str
    manifest_digest: str
    file_count: int
    publishedSourceArchiveVerified: bool = field(default=True,init=False)
    gitObjectContentsVerified: bool = field(default=True,init=False)
    currentPublicationVerified: bool = field(default=False,init=False)
    sourceRevalidated: bool = field(default=False,init=False)
    approvalReady: bool = field(default=False,init=False)
    authorityGranted: bool = field(default=False,init=False)
    runtimePermit: bool = field(default=False,init=False)
    recoveryAuthorized: bool = field(default=False,init=False)
    productionReady: bool = field(default=False,init=False)

    def public_summary(self):
        return {name:getattr(self,name) for name in self.__dataclass_fields__ if name!='manifest_bytes'}


def verify_checkpoint_published_source(reader,*,repository,timeout=15):
    """Bound Git/ZIP reads; pre/post custody authentication keeps crypto/flock limits."""
    from deployment_compose_checkpoint_archive_v3_host import read_bound_source_archive
    try:
        raw,source,pins,material=read_bound_source_archive(reader)
        if source.origin!=ORIGIN or source.provider_id!='github.com' or source.source_sha!=pins['sourceSha']:reject()
        manifest=_verify_archive(raw,repository=repository,source_sha=source.source_sha,
            archive_digest=pins['archiveDigest'],timeout=timeout)
        again=read_bound_source_archive(reader)
        if again!=(raw,source,pins,material):reject()
        import json
        return VerifiedCheckpointPublishedSourceV3(manifest,source.source_sha,pins['archiveDigest'],material,
            digest(manifest),len(json.loads(manifest)))
    except Exception:reject()
