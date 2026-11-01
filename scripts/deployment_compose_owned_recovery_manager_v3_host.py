"""Fixed trusted Linux SSH manager channel; not a recovery permit.

Manager envelopes originate in this process; worker frames are always nested.
The consumer still needs an owned, authenticated fixed-source SSH session.
This module does not acquire gateway observer pins or attest daemon cleanup.
"""
import base64
import hashlib
import json
import math
import os
import re
import selectors
import struct
import threading
import time

from deployment_compose_history_v3_host import pairs
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_owned_recovery_ssh_v3_host import (ENTRYPOINT, MANAGER_ENTRYPOINT,
    RESPONSE_LOSS_ENTRYPOINT, RESPONSE_LOSS_MANAGER_ENTRYPOINT)
from deployment_compose_owned_recovery_unit_v3_host import OwnedRecoveryUnitV3, ResponseLossUnitV3
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_host_snapshot_v3_host import HostSnapshotV3
from deployment_compose_v3_channel_worker import LIMIT, write_frame

import deployment_compose_recovery_profiles_v3_host as profiles

from deployment_compose_response_loss_observation_v3_host import KIND, validate_observation, observation_digest

INNER_LIMIT = LIMIT-1024


def reject():
    raise ValueError('compose-owned-recovery-manager-v3-rejected') from None


class _Frames:
    """Incremental bounded input; partial frames never monopolize the relay."""
    def __init__(self):
        self.buffer = bytearray()
        self.size = None
        self.partial_since = None

    def feed(self,raw):
        self.buffer.extend(raw)
        frames = []
        while True:
            if self.size is None:
                if len(self.buffer)<4:break
                self.size = struct.unpack('!I',self.buffer[:4])[0]
                del self.buffer[:4]
                if not 0<self.size<=LIMIT:reject()
            if len(self.buffer)<self.size:break
            body = bytes(self.buffer[:self.size]);del self.buffer[:self.size]
            value = json.loads(body,object_pairs_hook=pairs,parse_constant=lambda _:reject())
            if type(value) is not dict or encode(value)!=body:reject()
            frames.append(value);self.size = None;self.partial_since = None
        if self.buffer or self.size is not None:
            if self.partial_since is None:self.partial_since=time.monotonic()
        else:self.partial_since=None
        return frames

    def eof(self):
        if self.buffer or self.size is not None:reject()


def run(config, stdin, stdout, archive, *, timeout=3600):
    return _run(config,stdin,stdout,archive,timeout=timeout,_profile=profiles.NORMAL)


def _run(config,stdin,stdout,archive,*,timeout=3600,_profile):
    """One wrapper, one start command, no protocol/consumption retry.

    manager-stop terminates only the bound wrapper. A terminal envelope is
    lifecycle data for the owned channel, never business completion or authority.
    """
    profile_marker=profiles.marker(_profile)
    diagnostic=_profile is profiles.RESPONSE_LOSS
    expected_manager=RESPONSE_LOSS_MANAGER_ENTRYPOINT if diagnostic else MANAGER_ENTRYPOINT
    expected_worker=RESPONSE_LOSS_ENTRYPOINT if diagnostic else ENTRYPOINT
    verify_daemon=type(config) is dict and 'verifyDaemonStop' in config
    verify_resources=type(config) is dict and 'verifyResourceInventory' in config
    verify_host=type(config) is dict and 'verifyHostSnapshot' in config
    if (type(config) is not dict
            or set(config)!={'entrypoint','channelNonce','sourceSha','archiveDigest','hostId'}|(
                {'verifyDaemonStop'} if verify_daemon else set())|({'verifyResourceInventory'} if verify_resources else set())|(
                {'verifyHostSnapshot'} if verify_host else set())
            or verify_daemon and config['verifyDaemonStop'] is not True
            or verify_resources and (config['verifyResourceInventory'] is not True or not verify_daemon)
            or verify_host and (config['verifyHostSnapshot'] is not True or not verify_resources or not verify_daemon)
            or config['entrypoint']!=expected_manager
            or type(config['channelNonce']) is not str or not re.fullmatch('[0-9a-f]{64}',config['channelNonce'])
            or type(config['sourceSha']) is not str or not re.fullmatch('[0-9a-f]{40}',config['sourceSha'])
            or type(config['archiveDigest']) is not str or not re.fullmatch('[0-9a-f]{64}',config['archiveDigest'])
            or type(config['hostId']) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',config['hostId'])
            or type(archive) is not bytes or not 0<len(archive)<=2097152
            or hashlib.sha256(archive).hexdigest()!=config['archiveDigest']
            or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=3600):reject()
    # Freeze before the owner is created; an embedding cannot mutate later sends.
    config = json.loads(encode(config))
    owner_type=ResponseLossUnitV3 if diagnostic else OwnedRecoveryUnitV3
    owner = owner_type(config['archiveDigest'],config['sourceSha'])
    process = thread = None
    daemon=None
    host=None;host_before=None;host_after=None
    resource_before=resource_after=None
    resource_final_seen=False
    observation=None;hello_identity=None;consume_hash=None
    stop_drain = threading.Event()
    errors = []
    stop_attempted = False
    deadline = time.monotonic()+timeout
    nonce = config['channelNonce']
    total = count = 0
    start_requested = False
    flags = []
    queues = {'client':bytearray(),'worker':bytearray()}
    def remaining(limit=30):
        left = deadline-time.monotonic()
        if left<=0 or errors:reject()
        return min(left,limit)
    def emit(kind,**data):
        write_frame(stdout,dict(kind=kind,channelNonce=nonce,**data),timeout=remaining())
    def queue(side,frame):
        raw=encode(frame)
        if not 0<len(raw)<=LIMIT or len(queues[side])+len(raw)+4>2*LIMIT:reject()
        queues[side].extend(struct.pack('!I',len(raw))+raw)
    try:
        if verify_host:
            # Capture before the waiting loader starts its fixed 30s input clock.
            host=HostSnapshotV3(timeout=remaining(20));host_before=host.descriptor()
        process = owner.start(timeout=min(15,remaining()))
        for stream in (stdout,process.stdin):
            flags.append((stream,os.get_blocking(stream.fileno())))
            os.set_blocking(stream.fileno(),False)
        binding = dict(unit=owner.unit,kernelBoot=owner._boot_id,invocationId=owner._invocation,
            sourceSha=config['sourceSha'],archiveDigest=config['archiveDigest'],hostId=config['hostId'])
        if diagnostic:binding['diagnosticProfile']=profile_marker
        def drain():
            size=0
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stderr,selectors.EVENT_READ)
                    while not stop_drain.is_set():
                        if not selector.select(.1):continue
                        raw=os.read(process.stderr.fileno(),65536)
                        if not raw:return
                        size+=len(raw)
                        if size>1024*1024:errors.append('stderr-bound');return
            except Exception:errors.append('stderr-io')
        thread=threading.Thread(target=drain,daemon=True);thread.start()
        queue('client',dict(kind='manager-bound',channelNonce=nonce,binding=binding,
            **({'verifyDaemonStop':True} if verify_daemon else {}),
            **({'verifyResourceInventory':True} if verify_resources else {}),
            **({'verifyHostSnapshot':True,'hostSnapshotBaseline':host_before} if verify_host else {})))
        client,worker = _Frames(),_Frames()
        reason = None
        with selectors.DefaultSelector() as selector:
            selector.register(stdin,selectors.EVENT_READ,('client-read',client))
            selector.register(process.stdout,selectors.EVENT_READ,('worker-read',worker))
            writers={'client':stdout,'worker':process.stdin}
            registered=set()
            while reason is None:
                remaining()
                for decoder in (client,worker):
                    if decoder.partial_since is not None and time.monotonic()-decoder.partial_since>30:reject()
                for side,stream in writers.items():
                    if queues[side] and side not in registered:
                        selector.register(stream,selectors.EVENT_WRITE,('write',side));registered.add(side)
                    elif not queues[side] and side in registered:
                        selector.unregister(stream);registered.remove(side)
                ready=selector.select(min(.1,remaining()))
                # Stop/control input wins over pending output to a stalled peer.
                ready.sort(key=lambda event:event[0].data[0]!='client-read')
                for key,_ in ready:
                    side,decoder=key.data
                    if side=='write':
                        try:n=os.write(key.fd,queues[decoder])
                        except BlockingIOError:continue
                        if n<=0:reject()
                        del queues[decoder][:n]
                        continue
                    raw=os.read(key.fd,65536)
                    if not raw:
                        decoder.eof()
                        if side=='client-read':reject()
                        reason='worker-eof';break
                    total+=len(raw)
                    if total>64*1024*1024:reject()
                    for frame in decoder.feed(raw):
                        count+=1
                        if count>4096 or frame.get('channelNonce')!=nonce:reject()
                        if side=='worker-read':
                            if not start_requested or len(encode(frame))>INNER_LIMIT:reject()
                            if frame.get('kind')==KIND:
                                if (not diagnostic or observation is not None or resource_after is not None or hello_identity is None
                                        or consume_hash is None or queues['worker']
                                        or set(frame)!={'kind','channelNonce','observation'}):reject()
                                candidate=validate_observation(frame['observation'])
                                expected=dict(sourceSha=config['sourceSha'],archiveDigest=config['archiveDigest'],
                                    hostId=config['hostId'],root=hello_identity[0],daemonId=hello_identity[1],requestHash=consume_hash)
                                if any(candidate[k]!=v for k,v in expected.items()):reject()
                                observation=candidate
                                queue('client',dict(kind=KIND,channelNonce=nonce,binding=binding,observation=observation))
                                continue
                            if frame.get('kind')=='hello':
                                if hello_identity is not None:reject()
                                hello_identity=(frame.get('root'),frame.get('daemonId'))
                            if verify_resources and resource_after is not None:
                                if frame.get('kind')!='final' or resource_final_seen:reject()
                                resource_final_seen=True
                            if verify_daemon:
                                if daemon is None:
                                    if frame.get('kind')!='hello':reject()
                                    daemon=ObservedRecoveryDaemonV3(frame.get('root'),frame.get('daemonId'),
                                        kernel_boot=owner._boot_id,timeout=remaining(15))
                                    if verify_resources:resource_before=daemon.begin_resource_observation(timeout=remaining(15))
                                    queue('client',dict(kind='daemon-bound',channelNonce=nonce,
                                        binding=binding,daemonBinding=daemon.binding(),
                                        **({'resourceBaselineDigest':resource_before} if verify_resources else {})))
                                elif frame.get('kind')=='hello':reject()
                            if verify_resources and frame.get('kind')=='cleanup-ready':
                                if (resource_after is not None or daemon is None
                                        or queues['worker']
                                        or set(frame)!={'kind','channelNonce','root','daemonId'}
                                        or frame['root']!=daemon.binding()['root']
                                        or frame['daemonId']!=daemon.binding()['daemonId']):reject()
                                resource_after=daemon.verify_resources_restored(timeout=remaining(15))
                                if resource_after!=resource_before:reject()
                                queue('worker',dict(kind='cleanup-checked',channelNonce=nonce))
                                continue
                            if verify_resources and frame.get('kind')=='final' and resource_after is None:reject()
                            queue('client',dict(kind='worker-frame',channelNonce=nonce,frame=frame))
                            continue
                        kind=frame.get('kind')
                        if kind=='manager-stop' and set(frame)=={'kind','channelNonce'}:
                            reason='requested-stop';break
                        if kind=='manager-start' and set(frame)=={'kind','channelNonce'} and not start_requested:
                            initial=dict({k:v for k,v in config.items() if k not in ('verifyDaemonStop','verifyResourceInventory','verifyHostSnapshot')},
                                entrypoint=expected_worker,archiveBase64=base64.b64encode(archive).decode('ascii'))
                            queue('worker',initial)
                            start_requested=True
                        elif kind=='worker-frame' and set(frame)=={'kind','channelNonce','frame'} and start_requested:
                            payload=frame['frame']
                            if (type(payload) is not dict or payload.get('channelNonce')!=nonce
                                    or type(payload.get('kind')) is not str or len(encode(payload))>INNER_LIMIT):reject()
                            if payload['kind']==KIND:reject()
                            if verify_resources and payload['kind']=='cleanup-checked':reject()
                            if verify_resources and resource_after is not None:reject()
                            if diagnostic and payload['kind']=='consume-intent':
                                if (consume_hash is not None or set(payload)!={'kind','channelNonce','requestHash','receiptHash','firstBinding'}
                                        or type(payload['requestHash']) is not str or not re.fullmatch('[0-9a-f]{64}',payload['requestHash'])):reject()
                                consume_hash=payload['requestHash']
                            queue('worker',payload)
                        else:reject()
                    if reason is not None:break
        if verify_host:
            # One shared terminal budget, below the negotiated client's 60s wait.
            deadline=min(deadline,time.monotonic()+50)
        stop_timeout=remaining(30)
        stop_attempted=True
        owner.stop(timeout=stop_timeout)
        if daemon is not None:daemon.verify_stopped(timeout=remaining(30))
        if host is not None:host_after=host.verify_unchanged(timeout=remaining(20))
        thread.join(timeout=1)
        if thread.is_alive() or errors:reject()
        # The service is already stopped. Drain previously queued worker frames
        # before the terminal envelope, under a finite output deadline.
        with selectors.DefaultSelector() as selector:
            selector.register(stdout,selectors.EVENT_WRITE)
            flush_deadline=time.monotonic()+remaining()
            while queues['client']:
                left=flush_deadline-time.monotonic()
                if left<=0 or not selector.select(left):reject()
                try:n=os.write(stdout.fileno(),queues['client'])
                except BlockingIOError:continue
                if n<=0:reject()
                del queues['client'][:n]
        # Binding stays manager-created. A nested worker kind can never emit this.
        if daemon is not None:daemon.verify_stopped(timeout=remaining(10))
        if host is not None:host_after=host.verify_unchanged(timeout=remaining(20))
        emit('manager-stopped',binding=binding,workerStartRequested=start_requested,reason=reason,
            **({'diagnosticObservationDigest':observation_digest(observation) if observation is not None else None} if diagnostic else {}),
            wrapperStopped=True,transportReturncode=owner.transport_returncode,
            daemonCleanupVerified=False,productionReady=False,
            **({'daemonBinding':daemon.binding() if daemon is not None else None,
                'daemonStoppedVerified':daemon is not None} if verify_daemon else {}),
            **({'resourceBaselineDigest':resource_before,'resourceAfterDigest':resource_after,
                'resourceInventoryRestored':resource_before is not None and resource_after==resource_before}
                if verify_resources else {}),
            **({'hostSnapshotBaseline':host_before,'hostSnapshotAfterDigest':host_after,
                'hostSnapshotUnchangedVerified':host_after==host_before['beforeDigest']} if verify_host else {}))
    finally:
        import sys
        primary=sys.exc_info()[1]
        cleanup_error=None
        if process is not None and not stop_attempted:
            try:owner.stop(timeout=30)
            except Exception as error:cleanup_error=error
        stop_drain.set()
        if thread is not None:thread.join(timeout=1)
        try:
            if owner._stopped:owner.close()
            else:owner._discard_local()
        except Exception as error:
            if cleanup_error is None:cleanup_error=error
        if daemon is not None:
            try:daemon.close()
            except Exception as error:
                if cleanup_error is None:cleanup_error=error
        if host is not None:
            try:host.close()
            except Exception as error:
                if cleanup_error is None:cleanup_error=error
        for stream,blocking in flags:
            try:
                if not stream.closed:os.set_blocking(stream.fileno(),blocking)
            except Exception as error:
                if cleanup_error is None:cleanup_error=error
        if primary is None and cleanup_error is not None:raise cleanup_error
