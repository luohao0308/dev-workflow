"""Fixed diagnostic archive loader and process-local loaded-source receipt.

This proves the bytes loaded by the bounded diagnostic, not production source
provenance, global writer exclusion, or authorization to execute a deployment.
"""
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import threading
import weakref
from types import MappingProxyType
import zipfile

from deployment_compose_profile3_prepare_ssh_probe import _BOOTSTRAP, _allowed, MAX_ARCHIVE, MAX_SOURCE
from deployment_compose_witness_store import canonical

ENTRYPOINT = 'deployment_compose_native_source_v3_host.run_diagnostic'
PROFILE = 'native-diagnostic-v1'
_ISSUED = weakref.WeakKeyDictionary()


def reject():
    raise ValueError('compose-native-source-v3-rejected') from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def allowed(name):
    return _allowed(name) or name=='tests/__init__.py' or (name.startswith('tests/test_') and len(PurePosixPath(name).parts)==2 and name.endswith('.py'))


def archive_files(raw):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_ARCHIVE:
        reject()
    files = {}; total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
        if not 0<len(zipped.infolist())<=1024:
            reject()
        for info in zipped.infolist():
            name = info.filename
            if (name in files or name!=info.orig_filename or not allowed(name)
                    or PurePosixPath(name).is_absolute() or any(p in ('','.','..') for p in name.split('/'))
                    or '\\' in name or info.is_dir() or info.flag_bits&(1|64)
                    or stat.S_IFMT(info.external_attr>>16) not in (0,stat.S_IFREG)
                    or info.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)
                    or not 0<=info.file_size<=MAX_SOURCE-total):
                reject()
            with zipped.open(info) as stream:
                value = stream.read(info.file_size+1)
            if len(value)!=info.file_size:
                reject()
            files[name]=value; total+=len(value)
    required = {'scripts/deployment_compose_native_source_v3_host.py',
                'tests/support/compose_native_writer_lifecycle_fixture.py','tests/__init__.py',
                'tests/test_deployment_compose_native_writer_lifecycle_v3_host.py'}
    if not required<=files.keys():
        reject()
    return files


def diagnostic_bootstrap(source_sha, archive_digest):
    if (type(source_sha) is not str or re.fullmatch('[a-f0-9]{40}',source_sha) is None
            or type(archive_digest) is not str or re.fullmatch('[a-f0-9]{64}',archive_digest) is None):
        reject()
    code = _BOOTSTRAP.replace('deployment_compose_profile3_prepare_ssh_probe._remote_main',ENTRYPOINT)
    code = code.replace(' from deployment_compose_profile3_prepare_ssh_probe import _remote_main',
                        ' from deployment_compose_native_source_v3_host import run_diagnostic')
    code = code.replace(' result=_remote_main(config)',' result=run_diagnostic(config,archive,r)')
    # Validate metadata before extraction using only fixed stdlib code.
    original = "  for name in zipped.namelist():"
    replacement = """  members=zipped.infolist()
  if not 0<len(members)<=1024 or len({i.filename for i in members})!=len(members):raise ValueError('package-members')
  import stat
  for i in members:
   if i.flag_bits&(1|64) or stat.S_IFMT(i.external_attr>>16) not in (0,stat.S_IFREG) or i.compress_type not in (0,8) or i.is_dir():raise ValueError('package-mode')
  for name in zipped.namelist():"""
    replacement += ''
    # The fixed diagnostic profile is checked before any archive module import.
    from deployment_compose_profile3_prepare_ssh_probe import EXTRA_SCRIPTS
    replacement = replacement.replace('  for name in zipped.namelist():',
        "  extras="+repr(tuple(sorted(EXTRA_SCRIPTS)))+"\n  for name in zipped.namelist():\n   if not (name.startswith(('core/scripts/','packs/deployment/scripts/','packs/release/scripts/','tests/support/')) or name.startswith('scripts/deployment_compose_') and len(name.split('/'))==2 or name in extras or name=='tests/__init__.py' or name.startswith('tests/test_') and len(name.split('/'))==2):raise ValueError('package-profile')")
    code = code.replace(original,replacement).replace("or not name.endswith('.py')","or '\\\\' in name or any(x in ('','.','..') for x in name.split('/')) or not name.endswith('.py')")
    code = code.replace("[str(r/'scripts')","[str(r),str(r/'scripts')")
    code = code.replace("r=pathlib.Path(tempfile.mkdtemp(prefix='dw-profile3-published-')).resolve()", """parent=pathlib.Path(config['diagnosticDirectory'])
if not parent.is_absolute() or any(p.is_symlink() for p in (parent,*parent.parents)) or not parent.is_dir() or parent.stat().st_uid!=os.geteuid() or parent.stat().st_mode&511!=448:raise ValueError('diagnostic-parent')
r=pathlib.Path(tempfile.mkdtemp(prefix='dw-native-source-',dir=parent)).resolve()""")
    code = code.replace('limit=4*1024*1024','sys.dont_write_bytecode=True\nlimit=4*1024*1024')
    return code.replace('ARCHIVE_DIGEST',repr(archive_digest)).replace('SOURCE_SHA',repr(source_sha))


class LoadedNativeSourceV3:
    __slots__ = ('__weakref__',)

    def __init__(self):
        reject()


def _actual_command():
    if sys.platform!='linux':
        reject()
    raw = Path('/proc/self/cmdline').read_bytes()
    if not raw.endswith(b'\0') or len(raw)>1024*1024:
        reject()
    return [part.decode('utf-8') for part in raw[:-1].split(b'\0')][1:]


def _start_ticks():
    raw = Path('/proc/self/stat').read_text()
    return int(raw[raw.rfind(')')+2:].split()[19])


def _issue(config, archive, root):
    import __main__
    expected = diagnostic_bootstrap(config['sourceSha'],config['archiveDigest'])
    if (sys.orig_argv[1:]!=['-I','-S','-u','-c',expected] or _actual_command()!=['-I','-S','-u','-c',expected] or not sys.flags.isolated or not sys.flags.no_site
            or __main__.__dict__.get('archive') is not archive or __main__.__dict__.get('r') is not root
            or __main__.__dict__.get('config') is not config or digest(archive)!=config['archiveDigest']):
        reject()
    files = archive_files(archive)
    root = root.resolve(strict=True)
    for name,value in files.items():
        path = root/name
        if _read_bound(root,name)!=value:
            reject()
    result = object.__new__(LoadedNativeSourceV3)
    _ISSUED[result] = MappingProxyType(dict(owner=(os.getpid(),threading.get_ident()),start_ticks=_start_ticks(),command=_actual_command(),archive=archive,root=root,
        source=config['sourceSha'],archive_digest=config['archiveDigest'],nonce=config['channelNonce'],files=MappingProxyType(files),root_seal=_root_seal(root)))
    check_loaded_source(result)
    return result


def _state(receipt):
    state = _ISSUED.get(receipt)
    if type(receipt) is not LoadedNativeSourceV3 or state is None or state['owner']!=(os.getpid(),threading.get_ident()) or state['start_ticks']!=_start_ticks() or state['command']!=_actual_command():
        reject()
    root,files = state['root'],state['files']
    if _root_seal(root)!=state['root_seal']:
        reject()
    for name,expected in files.items():
        if _read_bound(root,name)!=expected:
            reject()
    names = {PurePosixPath(name).stem for name in files}
    for module in tuple(sys.modules.values()):
        filename = getattr(module,'__file__',None)
        if not filename:
            continue
        path = Path(filename).resolve()
        module_name = getattr(module,'__name__','')
        if (module_name.rsplit('.',1)[-1] in names or module_name=='tests' or module_name.startswith('tests.')) and not path.is_relative_to(root):
            reject()
        if path.is_relative_to(root):
            name = path.relative_to(root).as_posix()
            if name not in files or _read_bound(root,name)!=files[name]:
                reject()
    return state


def check_loaded_source(receipt):
    state = _state(receipt)
    return dict(source=state['source'],archive_digest=state['archive_digest'])


def _root_seal(root):
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
        reject()
    return info.st_dev,info.st_ino,info.st_uid,info.st_mode


def _read_bound(root,name):
    directory = os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in PurePosixPath(name).parts[:-1]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory);directory=child
        fd = os.open(PurePosixPath(name).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:
                reject()
            with os.fdopen(os.dup(fd),'rb') as stream:
                return stream.read(MAX_SOURCE+1)
        finally:os.close(fd)
    finally:os.close(directory)


def retain_loaded_source(receipt, store):
    state = _state(receipt)
    reference = store.put(state['archive'])
    if store.get(reference)!=state['archive']:
        reject()
    check_loaded_source(receipt)
    return dict(profile=PROFILE,sourceSha=state['source'],archiveDigest=state['archive_digest'],
        archiveReference=reference,channelNonce=state['nonce'],entrypoint=ENTRYPOINT,loaderArchiveVerified=True)


def verify_retained_source(facts, store):
    if (type(facts) is not dict or set(facts)!={'profile','sourceSha','archiveDigest','archiveReference','channelNonce','entrypoint','loaderArchiveVerified'}
            or facts['profile']!=PROFILE or facts['entrypoint']!=ENTRYPOINT or facts['loaderArchiveVerified'] is not True
            or any(type(facts[k]) is not str or re.fullmatch(pattern,facts[k]) is None for k,pattern in
                (('sourceSha','[a-f0-9]{40}'),('archiveDigest','[a-f0-9]{64}'),('channelNonce','[a-f0-9]{64}')))):
        reject()
    raw = store.get(facts['archiveReference'])
    if digest(raw)!=facts['archiveDigest']:
        reject()
    archive_files(raw)
    return raw


def run_diagnostic(config, archive, root):
    if (type(config) is not dict or set(config)!={'entrypoint','sourceSha','archiveDigest','channelNonce','diagnosticDirectory'}
            or config['entrypoint']!=ENTRYPOINT or type(config['channelNonce']) is not str
            or re.fullmatch('[a-f0-9]{64}',config['channelNonce']) is None):
        reject()
    receipt = _issue(config,archive,root)
    from tests.support.compose_native_writer_lifecycle_fixture import produce
    result = produce(Path(config['diagnosticDirectory']),config['sourceSha'],config['archiveDigest'],loaded_source=receipt)
    result['loaderArchiveVerified']=True
    # Keep all source/fixture files alive until the original manager stops us.
    from deployment_compose_v3_channel_worker import write_frame
    write_frame(sys.stdout.buffer,dict(channelNonce=config['channelNonce'],result=result),timeout=30)
    sys.stdin.buffer.read(1)
    return result
