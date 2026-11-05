"""Fixed-source SSH delivery of read-only stopped-writer observations."""
import base64
from dataclasses import dataclass, field
import hashlib
import io
import json
import math
import os
import re
import secrets
import selectors
import shlex
import struct
import subprocess
import threading
import time
import zipfile

import deployment_compose_live_ssh_v3_host as live
import deployment_compose_cold_writer_v3_host as cold
from deployment_compose_operation_witness_client_v3 import encode, hex_value
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_v3_channel_worker import write_frame

ENTRYPOINT = 'deployment_compose_cold_writer_ssh_v3_host.run'
REQUEST = {'entrypoint','sourceSha','archiveDigest','hostId','channelNonce','origin','originDigest',
           'producerSourceSha','producerArchiveDigest','checkpointBinding'}
_FALSE = {'daemonStoppedVerified','historyFreshnessVerified','linuxQuiescenceVerified',
          'authorityGranted','runtimePermit','recoveryAuthorized','productionReady'}
REPLY = {'kind','channelNonce','hostId','verifierSourceSha','verifierArchiveDigest','producerSourceSha',
         'producerArchiveDigest','originDigest','requestDigest','checkpointBinding','checkpointBound',
         'observations','observationDigest','writerStoppedObserved'} | _FALSE


def reject():
    raise ValueError('compose-cold-writer-ssh-v3-rejected') from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _left(deadline):
    left = deadline-time.monotonic()
    if left <= 0:reject()
    return left


def _binding(value):
    if value is not None and (type(value) is not dict or set(value) != {'materialDigest','originMaterialDigest','historyDigest'}
                              or any(not hex_value(v) for v in value.values())):reject()
    return decode(encode(value))


def _request(config):
    if (type(config) is not dict or set(config) != REQUEST or config['entrypoint'] != ENTRYPOINT
            or any(type(config[k]) is not str or re.fullmatch('[0-9a-f]{40}',config[k]) is None for k in ('sourceSha','producerSourceSha'))
            or any(not hex_value(config[k]) for k in ('archiveDigest','producerArchiveDigest','channelNonce','originDigest'))
            or type(config['hostId']) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',config['hostId']) is None):reject()
    origin = cold.validate_origin(encode(config['origin']))
    if (digest(encode(origin)) != config['originDigest'] or origin['sourceSha'] != config['producerSourceSha']
            or origin['archiveDigest'] != config['producerArchiveDigest']):reject()
    _binding(config['checkpointBinding'])
    return origin


def cold_bootstrap(archive_digest, source_sha):
    code = live.live_bootstrap(archive_digest,source_sha)
    module = 'deployment_compose_live_worker_v3_host'
    if code.count(module) != 2 or code.count('config=json.loads(exact(size))') != 1:reject()
    code = code.replace(module,'deployment_compose_cold_writer_ssh_v3_host')
    strict = '''raw_config=exact(size)
def unique_pairs(items):
 result={}
 for key,value in items:
  if key in result:raise ValueError('cold-bootstrap-rejected')
  result[key]=value
 return result
def invalid_constant(value):raise ValueError('cold-bootstrap-rejected')
config=json.loads(raw_config,object_pairs_hook=unique_pairs,parse_constant=invalid_constant)
if json.dumps(config,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')!=raw_config:raise ValueError('cold-bootstrap-rejected')'''
    return code.replace('config=json.loads(exact(size))',strict)


def ssh_argv(alias, archive_digest, source_sha):
    argv = live.ssh_argv(alias,archive_digest,source_sha)
    argv[-1] = 'exec python3 -I -u -c ' + shlex.quote(cold_bootstrap(archive_digest,source_sha))
    return argv


def published_cold_archive(source_sha):
    raw = live.published_live_archive(source_sha)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if not {'scripts/deployment_compose_cold_writer_ssh_v3_host.py','scripts/deployment_compose_cold_writer_v3_host.py',
                'scripts/deployment_compose_owned_recovery_unit_v3_host.py'} <= set(archive.namelist()):reject()
    return raw


def _eof(stream, deadline):
    with selectors.DefaultSelector() as selector:
        selector.register(stream,selectors.EVENT_READ)
        if not selector.select(_left(deadline)) or os.read(stream.fileno(),1):reject()


def run(config, stdin, stdout):
    try:
        deadline = time.monotonic()+10
        origin = _request(config)
        _eof(stdin,deadline)
        observed = cold.observe_stopped_writer(encode(origin),expected_digest=config['originDigest'],
            expected_source_sha=config['producerSourceSha'],expected_archive_digest=config['producerArchiveDigest'],
            timeout=min(5,_left(deadline)))
        value = dict(kind='cold-writer-result-v3',channelNonce=config['channelNonce'],hostId=config['hostId'],
            verifierSourceSha=config['sourceSha'],verifierArchiveDigest=config['archiveDigest'],
            producerSourceSha=config['producerSourceSha'],producerArchiveDigest=config['producerArchiveDigest'],
            originDigest=config['originDigest'],requestDigest=digest(encode(config)),
            checkpointBinding=config['checkpointBinding'],checkpointBound=config['checkpointBinding'] is not None,
            observations=decode(observed.observations),observationDigest=observed.observation_digest,
            writerStoppedObserved=True,**{k:False for k in _FALSE})
        if len(encode(value)) > 65536:reject()
        write_frame(stdout,value,timeout=_left(deadline))
        _left(deadline)
    except Exception:reject()


def _tree(value, origin, budget, depth=0):
    budget[0] += 1
    if (depth > 16 or budget[0] > 128 or type(value) is not dict
            or set(value) != {'device','inode','files','children'}
            or type(value['device']) is not int or not 0 <= value['device'] < 2**64
            or type(value['inode']) is not int or not 0 < value['inode'] < 2**64
            or type(value['files']) is not dict or set(value['files']) != {'cgroup.type','cgroup.events','cgroup.procs'}
            or any(type(v) is not str for v in value['files'].values())
            or value['files']['cgroup.type'].strip() != 'domain' or value['files']['cgroup.procs'].strip()
            or cold.units.events(value['files']['cgroup.events'])['populated'] != 0
            or type(value['children']) is not list or len(value['children']) > 256):reject()
    if depth == 0 and (value['device'],value['inode']) != (origin['cgroupDevice'],origin['cgroupInode']):reject()
    names = []
    for child in value['children']:
        if (type(child) is not list or len(child) != 2 or type(child[0]) is not str
                or not child[0] or child[0] in ('.','..') or '/' in child[0] or '\0' in child[0]):reject()
        names.append(child[0]);_tree(child[1],origin,budget,depth+1)
    if names != sorted(set(names)):reject()


def _observations(values, origin):
    if type(values) is not list or len(values) != 2 or encode(values[0]) != encode(values[1]):reject()
    for value in values:
        if (type(value) is not dict or set(value) != {'namespace','boot','unit','tree'}
                or type(value['namespace']) is not list or len(value['namespace']) != 2
                or any(type(v) is not int for v in value['namespace'])
                or value['namespace'] != [origin['pidNamespaceDevice'],origin['pidNamespaceInode']]
                or value['boot'] != origin['kernelBoot'] or type(value['unit']) is not dict
                or set(value['unit']) != set(cold.units.PROPERTIES)
                or any(type(v) is not str for v in value['unit'].values())):reject()
        state = value['unit'];group = '/system.slice/'+origin['unit']
        if state['LoadState'] == 'not-found':
            if not cold.units.OwnedRecoveryUnitV3._absent(state) or state['SubState'] != 'dead':reject()
        elif (state['LoadState'] != 'loaded' or state['ActiveState'] not in ('inactive','failed')
                or state['SubState'] not in ('dead','failed') or state['MainPID'] != '0'
                or state['InvocationID'] not in ('',origin['invocationId']) or state['ControlGroup'] not in ('',group)):reject()
        if value['tree'] is not None:_tree(value['tree'],origin,[0])


@dataclass(frozen=True)
class RemoteWriterStopObservationV3:
    host_id: str
    producer_source_sha: str
    producer_archive_digest: str
    verifier_source_sha: str
    verifier_archive_digest: str
    origin_digest: str
    request_digest: str
    observation_digest: str
    observations: bytes = field(repr=False)
    checkpoint_binding: bytes = field(repr=False)
    checkpointBound: bool
    sshDeliveryVerified: bool = field(default=True,init=False)
    writerStoppedObserved: bool = field(default=True,init=False)
    daemonStoppedVerified: bool = field(default=False,init=False)
    historyFreshnessVerified: bool = field(default=False,init=False)
    linuxQuiescenceVerified: bool = field(default=False,init=False)
    authorityGranted: bool = field(default=False,init=False)
    runtimePermit: bool = field(default=False,init=False)
    recoveryAuthorized: bool = field(default=False,init=False)
    productionReady: bool = field(default=False,init=False)

    def public_summary(self):
        return {k:getattr(self,k) for k in self.__dataclass_fields__ if k not in ('observations','checkpoint_binding')}


def _private_spawn(argv):
    return subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,close_fds=True)


def _reply(stream, deadline, errors):
    def exact(size):
        result = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(stream,selectors.EVENT_READ)
            while len(result) < size:
                if errors or not selector.select(min(.1,_left(deadline))):
                    if errors:reject()
                    continue
                chunk = os.read(stream.fileno(),size-len(result))
                if not chunk:reject()
                result.extend(chunk)
        return bytes(result)
    size = struct.unpack('!I',exact(4))[0]
    if not 0 < size <= 65536:reject()
    return decode(exact(size))


def observe_origin_over_ssh(origin, *, expected_origin_digest, host_id, producer_source_sha,
                            producer_archive_digest, verifier_source_sha, checkpoint_binding=None, timeout=30):
    process = thread = None
    errors = []
    stop_drain = threading.Event()
    stderr_eof = threading.Event()
    try:
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 60:reject()
        if type(origin) is not bytes:reject()
        request = dict(entrypoint=ENTRYPOINT,sourceSha=verifier_source_sha,archiveDigest='0'*64,
            hostId=host_id,channelNonce=secrets.token_hex(32),origin=cold.validate_origin(origin),
            originDigest=expected_origin_digest,producerSourceSha=producer_source_sha,
            producerArchiveDigest=producer_archive_digest,checkpointBinding=_binding(checkpoint_binding))
        _request(request)
        archive = published_cold_archive(verifier_source_sha)
        request['archiveDigest'] = digest(archive)
        argv = ssh_argv(host_id,request['archiveDigest'],verifier_source_sha)
        deadline = time.monotonic()+timeout
        process = _private_spawn(argv)
        if type(process) is not subprocess.Popen or process.text_mode or any(x is None for x in (process.stdin,process.stdout,process.stderr)):reject()
        def drain():
            total = 0
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stderr,selectors.EVENT_READ)
                    while not stop_drain.is_set():
                        if not selector.select(.05):continue
                        raw = os.read(process.stderr.fileno(),65536)
                        if not raw:
                            stderr_eof.set()
                            return
                        total += len(raw);errors.append('stderr')
                        if total > 65536:return
            except Exception:errors.append('stderr-io')
        thread = threading.Thread(target=drain,daemon=True);thread.start()
        write_frame(process.stdin,dict(request,archiveBase64=base64.b64encode(archive).decode('ascii')),timeout=_left(deadline))
        process.stdin.close()
        reply = _reply(process.stdout,deadline,errors)
        _eof(process.stdout,deadline)
        if process.wait(timeout=_left(deadline)) != 0:reject()
        thread.join(timeout=_left(deadline))
        if thread.is_alive() or not stderr_eof.is_set() or errors:reject()
        if (type(reply) is not dict or set(reply) != REPLY or reply['kind'] != 'cold-writer-result-v3'
                or reply['requestDigest'] != digest(encode(request))
                or reply['writerStoppedObserved'] is not True or any(reply[k] is not False for k in _FALSE)
                or reply['checkpointBound'] is not (request['checkpointBinding'] is not None)) :reject()
        for key, expected in dict(channelNonce=request['channelNonce'],hostId=host_id,
                verifierSourceSha=verifier_source_sha,verifierArchiveDigest=request['archiveDigest'],
                producerSourceSha=producer_source_sha,producerArchiveDigest=producer_archive_digest,
                originDigest=expected_origin_digest,checkpointBinding=request['checkpointBinding']).items():
            if encode(reply[key]) != encode(expected):reject()
        _observations(reply['observations'],request['origin'])
        raw = encode(reply['observations'])
        if reply['observationDigest'] != digest(raw):reject()
        result = RemoteWriterStopObservationV3(host_id,producer_source_sha,producer_archive_digest,
            verifier_source_sha,request['archiveDigest'],expected_origin_digest,reply['requestDigest'],digest(raw),
            raw,encode(request['checkpointBinding']),request['checkpointBinding'] is not None)
        _left(deadline)
        return result
    except Exception:reject()
    finally:
        primary = __import__('sys').exc_info()[1]
        if process is not None:
            failed = False
            actions = []
            if process.poll() is None:
                actions.extend((process.kill, lambda: process.wait(timeout=5)))
            # Stop and join the reader before closing its descriptor, even if a
            # foreign descendant still holds the writer. Never kill that peer.
            stop_drain.set()
            if thread is not None:
                actions.append(lambda: thread.join(timeout=1))
            def close_stream(stream):
                if stream is process.stderr and thread is not None and thread.is_alive():reject()
                stream.close()
            actions.extend(lambda stream=stream: close_stream(stream)
                           for stream in (process.stdin,process.stdout,process.stderr)
                           if stream is not None and not stream.closed)
            for action in actions:
                try:action()
                except Exception:failed=True
            if thread is not None and thread.is_alive():failed=True
            if failed:
                if primary is None:reject()
                try:
                    if hasattr(primary,'add_note'):primary.add_note('cold writer SSH cleanup incomplete')
                except Exception:pass
