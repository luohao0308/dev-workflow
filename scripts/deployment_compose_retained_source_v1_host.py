"""Fixed production source archive and process-local native origin proof."""

import hashlib
import io
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import threading
import time
from types import MappingProxyType
import weakref
import zipfile
import zlib

from deployment_compose_native_source_v3_host import (
    _actual_command, _read_bound, _root_seal, _start_ticks,
)
from deployment_compose_native_writer_lifecycle_v3_host import _capture_current_origin
from deployment_compose_profile3_prepare_ssh_probe import _BOOTSTRAP, MAX_ARCHIVE, MAX_SOURCE
from deployment_compose_witness_store import canonical

PROFILE = 'production-retained-v2'
ENTRYPOINT = 'deployment_compose_retained_native_entry_v1_host.run_production'
CHANNEL_MEMBER = 'scripts/deployment_compose_retained_native_channel_v1_host.py'
NAME = (
    r'(?:core/scripts/|packs/deployment/scripts/|packs/release/scripts/)[A-Za-z0-9_]+\.py'
    r'|scripts/(?:deployment_compose_[A-Za-z0-9_]+|deployment_gateway_host)\.py'
)
REQUIRED = frozenset({
    'scripts/deployment_compose_retained_source_v1_host.py',
    'scripts/deployment_compose_retained_native_entry_v1_host.py',
    'scripts/deployment_compose_retained_frontend_worker_v1_host.py',
    'scripts/deployment_gateway_host.py',
})
CONFIG_FIELDS = frozenset({
    'entrypoint', 'sourceSha', 'archiveDigest', 'channelNonce', 'scope', 'mode', 'workDirectory',
})
_ISSUED = weakref.WeakKeyDictionary()


def reject():
    raise ValueError('retained-production-source-rejected') from None


def _hex(value, length):
    return type(value) is str and re.fullmatch(f'[0-9a-f]{{{length}}}', value) is not None


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def archive_files(raw):
    """Validate the complete production archive before trusting any members."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ARCHIVE:
        reject()
    files = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
            members = zipped.infolist()
            if not 0 < len(members) <= 1024:
                reject()
            for info in members:
                name = info.filename
                if (not re.fullmatch(NAME, name) or name != info.orig_filename or name in files
                        or info.is_dir() or info.flag_bits & 65
                        or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG)
                        or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or not 0 <= info.file_size <= MAX_SOURCE - total):
                    reject()
                with zipped.open(info) as stream:
                    value = stream.read(info.file_size + 1)
                if len(value) != info.file_size:
                    reject()
                files[name] = value
                total += len(value)
    except (OSError, EOFError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error):
        reject()
    if not REQUIRED <= files.keys():
        reject()
    return files


def production_archive(repository, source_sha, *, timeout=15):
    """Construct deterministic bytes from a pinned local Git tree, without fetch."""
    from deployment_compose_checkpoint_source_v3_host import _Git

    if not _hex(source_sha, 40) or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        reject()
    git = _Git(repository, time.monotonic() + timeout)
    git.origin()
    with git.batch():
        tracked = git.files(source_sha)
    files = {name: item[0] for name, item in tracked.items() if re.fullmatch(NAME, name)}
    if not REQUIRED <= files.keys():
        reject()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in sorted(files.items()):
            git.left()
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            zipped.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    raw = output.getvalue()
    if archive_files(raw) != files:
        reject()
    return raw


# Reuse the distribution's deadline-bounded frame reader. The rest of this
# program validates the whole ZIP using stdlib before importing project code.
_BOOTSTRAP_TAIL = r'''
import re,stat
sys.dont_write_bytecode=True
def unique(items):
 result={}
 for k,v in items:
  if k in result:raise ValueError('duplicate-config-field')
  result[k]=v
 return result
config=json.loads(exact(size),object_pairs_hook=unique)
archive=base64.b64decode(config.pop('archiveBase64'),validate=True)
if (set(config)!=CONFIG_FIELDS or config['entrypoint']!=ENTRYPOINT
    or config['sourceSha']!=SOURCE_SHA or config['archiveDigest']!=ARCHIVE_DIGEST
    or config['mode'] not in ('startup-check','channel')
    or type(config['channelNonce']) is not str or not re.fullmatch('[0-9a-f]{64}',config['channelNonce'])
    or not 0<len(archive)<=MAX_ARCHIVE or hashlib.sha256(archive).hexdigest()!=ARCHIVE_DIGEST):
 raise ValueError('production-package-pins')
if type(config['workDirectory']) is not str or len(config['workDirectory'])>4096:
 raise ValueError('production-work-directory')
parent=pathlib.Path(config['workDirectory'])
if (not parent.is_absolute() or parent.resolve(strict=True)!=parent or not parent.is_dir()
    or parent.stat().st_uid!=os.geteuid() or stat.S_IMODE(parent.stat().st_mode)!=0o700):
 raise ValueError('production-work-directory')
r=pathlib.Path(tempfile.mkdtemp(prefix='dw-retained-source-',dir=parent))
try:
 files={};total=0
 with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
  members=zipped.infolist()
  if not 0<len(members)<=1024:raise ValueError('production-package-count')
  for info in members:
   name=info.filename
   if (not re.fullmatch(NAME,name) or name!=info.orig_filename or name in files
       or info.is_dir() or info.flag_bits&65 or stat.S_IFMT(info.external_attr>>16) not in (0,stat.S_IFREG)
       or info.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)
       or not 0<=info.file_size<=MAX_SOURCE-total):raise ValueError('production-package-member')
   with zipped.open(info) as stream:value=stream.read(info.file_size+1)
   if len(value)!=info.file_size:raise ValueError('production-package-size')
   files[name]=value
   total+=len(value)
 if not REQUIRED<=files.keys() or config['mode']=='channel' and CHANNEL_MEMBER not in files:
  raise ValueError('production-package-incomplete')
 for name,value in files.items():
  path=r/name
  path.parent.mkdir(mode=448,parents=True,exist_ok=True)
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,384)
  with os.fdopen(fd,'wb') as stream:stream.write(value)
 sys.path[:0]=[str(r/path) for path in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
 from deployment_compose_retained_native_entry_v1_host import run_production
 run_production(config,archive,r)
finally:
 shutil.rmtree(r)
'''


def production_bootstrap(source_sha, archive_digest):
    if not _hex(source_sha, 40) or not _hex(archive_digest, 64):
        reject()
    prefix, delimiter, _ = _BOOTSTRAP.partition('config=json.loads(exact(size))')
    if not delimiter:
        reject()
    pins = dict(SOURCE_SHA=source_sha, ARCHIVE_DIGEST=archive_digest, ENTRYPOINT=ENTRYPOINT,
                CHANNEL_MEMBER=CHANNEL_MEMBER,
                MAX_ARCHIVE=MAX_ARCHIVE, MAX_SOURCE=MAX_SOURCE, NAME=NAME)
    definitions = ''.join(f'{key}={value!r}\n' for key, value in pins.items())
    definitions += f'CONFIG_FIELDS=set({sorted(CONFIG_FIELDS)!r})\nREQUIRED=set({sorted(REQUIRED)!r})\n'
    return definitions + prefix + _BOOTSTRAP_TAIL


class ProductionLoadedSourceV1:
    __slots__ = ('__weakref__',)

    def __init__(self):
        reject()

    def __copy__(self):
        reject()

    def __deepcopy__(self, memo):
        reject()

    def __reduce_ex__(self, protocol):
        reject()


def issue_loaded_source(config, archive, root):
    """Issue only inside the exact Linux loader with its original objects."""
    import __main__

    if (type(config) is not dict or set(config) != CONFIG_FIELDS or config['entrypoint'] != ENTRYPOINT
            or config['mode'] not in ('startup-check', 'channel')
            or not _hex(config['channelNonce'], 64) or type(archive) is not bytes
            or not isinstance(root, Path)):
        reject()
    expected = ['-I', '-S', '-u', '-c', production_bootstrap(config['sourceSha'], config['archiveDigest'])]
    if (sys.orig_argv[1:] != expected or _actual_command() != expected
            or not sys.flags.isolated or not sys.flags.no_site
            or __main__.__dict__.get('archive') is not archive
            or __main__.__dict__.get('config') is not config or __main__.__dict__.get('r') is not root
            or _digest(archive) != config['archiveDigest']):
        reject()
    if root.resolve(strict=True) != root or str(root.parent) != config['workDirectory']:
        reject()
    parent_seal = _root_seal(root.parent)
    files = archive_files(archive)
    origin = _capture_current_origin(config['sourceSha'], config['archiveDigest'])
    result = object.__new__(ProductionLoadedSourceV1)
    _ISSUED[result] = MappingProxyType(dict(
        owner=(os.getpid(), threading.current_thread()), command=tuple(expected), ticks=_start_ticks(),
        root=root, root_seal=_root_seal(root), parent_seal=parent_seal, files=MappingProxyType(files),
        source=config['sourceSha'], archive=config['archiveDigest'], nonce=config['channelNonce'], origin=origin,
        scope=canonical(config['scope']),
    ))
    check_loaded_source(result)
    return result


def check_loaded_source(receipt, *, scope=None):
    if type(receipt) is not ProductionLoadedSourceV1:
        reject()
    state = _ISSUED.get(receipt)
    if (state is None or state['owner'] != (os.getpid(), threading.current_thread())
            or state['ticks'] != _start_ticks() or state['command'] != tuple(_actual_command())):
        reject()
    if scope is not None and canonical(scope) != state['scope']:
        reject()
    root, files = state['root'], state['files']
    if _root_seal(root) != state['root_seal'] or _root_seal(root.parent) != state['parent_seal']:
        reject()
    for name, expected in files.items():
        if _read_bound(root, name) != expected:
            reject()
    stems = {PurePosixPath(name).stem for name in files}
    for name, module in tuple(sys.modules.items()):
        filename = getattr(module, '__file__', None)
        if name == 'tests' or name.startswith('tests.'):
            reject()
        if not filename:
            if name.rsplit('.', 1)[-1] in stems:
                reject()
            continue
        path = Path(filename).resolve()
        if path.is_relative_to(root):
            relative = path.relative_to(root).as_posix()
            if relative not in files:
                reject()
        elif name.rsplit('.', 1)[-1] in stems:
            reject()
    if (_root_seal(root) != state['root_seal'] or _root_seal(root.parent) != state['parent_seal']
            or _capture_current_origin(state['source'], state['archive']) != state['origin']):
        reject()
    return dict(profile=PROFILE, sourceSha=state['source'], archiveDigest=state['archive'],
                channelNonce=state['nonce'], originDigest=_digest(state['origin']))
