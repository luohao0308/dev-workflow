"""Mac-owned fixed SSH manager session. Caller JSON/Popen cannot issue a session.

One calling thread owns the session; stderr has its own bounded reader. The
kernel boot in manager bindings is never used as gateway observer identity.
"""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import threading
import time
import weakref

import deployment_compose_owned_recovery_ssh_v3_host as loader
import deployment_compose_recovery_profiles_v3_host as profiles
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_profile3_prepare_ssh_probe import _private_root
from deployment_compose_v3_channel_worker import write_frame

from deployment_compose_response_loss_observation_v3_host import KIND, validate_observation, observation_digest

_ISSUED = weakref.WeakKeyDictionary()


def reject():
    raise ValueError('compose-owned-recovery-session-v3-rejected') from None


def _note_cleanup_failure(error):
    """Diagnostics must not replace even an immutable original exception."""
    try:error.owned_recovery_cleanup_failed=True
    except Exception:pass
    try:
        if hasattr(error,'add_note'):error.add_note('owned recovery cleanup incomplete; inspect private cleanup report')
    except Exception:pass


def _spawn(argv):
    return subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,bufsize=0,close_fds=True)


def _profile_type(cls):
    if cls is OwnedRecoverySSHSessionV3:return profiles.NORMAL
    if cls is ResponseLossSSHSessionV3:return profiles.RESPONSE_LOSS
    reject()


def issued(session,process=None):
    profile=_profile_type(type(session))
    record=_ISSUED.get(session)
    if (record is None or record[:2]!=(os.getpid(),threading.get_ident())
            or record[2] is not session._process or (process is not None and process is not record[2])
            or type(session.verify_daemon_stop) is not bool
            or type(session.verify_resource_inventory) is not bool
            or type(session.verify_host_snapshot) is not bool
            or record[3:]!=(session.nonce,session.source_sha,session.archive_digest,session.host_id,
                session.verify_daemon_stop,session.verify_resource_inventory,session.verify_host_snapshot,type(session),profile)
            or session._profile is not profile):reject()
    return session


class OwnedRecoverySSHSessionV3:
    def __init__(self,private_root,ssh_alias,source_sha,*,timeout=30,verify_daemon_stop=False,
            verify_resource_inventory=False,verify_host_snapshot=False):
        profile=_profile_type(type(self))
        if (os.name!='posix' or type(ssh_alias) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',ssh_alias)
                or type(source_sha) is not str or not re.fullmatch('[0-9a-f]{40}',source_sha)
                or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60
                or type(verify_daemon_stop) is not bool or type(verify_resource_inventory) is not bool
                or verify_resource_inventory and not verify_daemon_stop or type(verify_host_snapshot) is not bool
                or verify_host_snapshot and (not verify_daemon_stop or not verify_resource_inventory or timeout<45)):reject()
        root=_private_root(private_root)
        self._profile=profile;self._diagnostic_consumed=False
        self._diagnostic_expected=None;self._diagnostic_fact=None;self._hello_identity=None
        self._hello_canonical=None
        self.diagnostic_observation_verified=False
        archive=(loader.published_manager_archive(source_sha) if profile is profiles.NORMAL
                 else loader.published_response_loss_manager_archive(source_sha))
        self.source_sha,self.host_id=source_sha,ssh_alias
        self.archive_digest=hashlib.sha256(archive).hexdigest()
        self.nonce=secrets.token_hex(32)
        self.verify_daemon_stop=verify_daemon_stop
        self.verify_resource_inventory=verify_resource_inventory
        self.verify_host_snapshot=verify_host_snapshot
        self._host_baseline=None;self._pending_host=False;self.host_snapshot_unchanged_verified=False
        self._resource_baseline=None;self._pending_resources=False;self.resource_inventory_restored=False
        self._daemon_binding=None;self._awaiting_daemon_hello=False
        self._pending_daemon_stop=False;self.daemon_stopped_verified=False
        self._pid,self._thread=os.getpid(),threading.get_ident()
        self._process=None;self._reader=None
        self._errors=[];self._stop_reader=threading.Event()
        self._started=self._finished=self._closed=False
        self._early_terminal=None
        self._completion_path_succeeded=False
        self._cleanup_error_codes=[];self._cleanup_snapshot=None
        self._cleanup_mode=False
        self._binding=None;self._count=self._bytes=0
        self._deadline=time.monotonic()+timeout
        self._maximum=time.monotonic()+3600
        case=root/('managed-ssh-'+secrets.token_hex(12));case.mkdir(mode=0o700)
        self._case=case
        fd=os.open(case/'stderr.private.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            argv=(loader.manager_ssh_argv(ssh_alias,self.archive_digest,source_sha) if profile is profiles.NORMAL
                  else loader.response_loss_manager_ssh_argv(ssh_alias,self.archive_digest,source_sha))
            self._process=_spawn(argv)
            if type(self._process) is not subprocess.Popen:reject()
            _ISSUED[self]=(self._pid,self._thread,self._process,self.nonce,source_sha,self.archive_digest,
                ssh_alias,verify_daemon_stop,verify_resource_inventory,verify_host_snapshot,type(self),profile)
            def drain(stderr_fd=fd):
                size=0
                try:
                    with os.fdopen(stderr_fd,'wb',buffering=0) as output,selectors.DefaultSelector() as selector:
                        selector.register(self._process.stderr,selectors.EVENT_READ)
                        while not self._stop_reader.is_set():
                            if not selector.select(.1):continue
                            raw=os.read(self._process.stderr.fileno(),65536)
                            if not raw:return
                            if size<1024*1024:output.write(raw[:1024*1024-size])
                            size+=len(raw)
                            if size>1024*1024:self._errors.append('stderr-bound');return
                except Exception:self._errors.append('stderr-io')
            self._reader=threading.Thread(target=drain,daemon=True);self._reader.start();fd=None
            self._send('initial',dict(entrypoint=loader.MANAGER_ENTRYPOINT if profile is profiles.NORMAL else loader.RESPONSE_LOSS_MANAGER_ENTRYPOINT,sourceSha=source_sha,
                archiveDigest=self.archive_digest,hostId=ssh_alias,channelNonce=self.nonce,
                archiveBase64=base64.b64encode(archive).decode('ascii'),
                **({'verifyDaemonStop':True} if verify_daemon_stop else {}),
                **({'verifyResourceInventory':True} if verify_resource_inventory else {}),
                **({'verifyHostSnapshot':True} if verify_host_snapshot else {})))
            bound=self._receive(60 if verify_host_snapshot else 30)
            if (set(bound)!={'kind','channelNonce','binding'}|({'verifyDaemonStop'} if verify_daemon_stop else set())|(
                    {'verifyResourceInventory'} if verify_resource_inventory else set())|(
                    {'verifyHostSnapshot','hostSnapshotBaseline'} if verify_host_snapshot else set())
                    or bound['kind']!='manager-bound' or verify_daemon_stop and bound['verifyDaemonStop'] is not True
                    or verify_resource_inventory and bound['verifyResourceInventory'] is not True
                    or verify_host_snapshot and bound['verifyHostSnapshot'] is not True):reject()
            if verify_host_snapshot:
                descriptor=bound['hostSnapshotBaseline']
                if (type(descriptor) is not dict or set(descriptor)!={'profile','beforeDigest','endpointDigest'}
                        or descriptor['profile']!='linux-docker-host-projection-v1'
                        or any(type(descriptor[k]) is not str or not re.fullmatch('[0-9a-f]{64}',descriptor[k])
                            for k in ('beforeDigest','endpointDigest'))):reject()
                self._host_baseline=encode(descriptor)
            binding=bound['binding']
            if (type(binding) is not dict or set(binding)!={'unit','kernelBoot','invocationId','sourceSha','archiveDigest','hostId'}|(
                    {'diagnosticProfile'} if profile is profiles.RESPONSE_LOSS else set())
                    or profile is profiles.RESPONSE_LOSS and binding['diagnosticProfile']!=profiles.RESPONSE_LOSS_MARKER
                    or binding['sourceSha']!=source_sha or binding['archiveDigest']!=self.archive_digest or binding['hostId']!=ssh_alias
                    or type(binding['unit']) is not str or not re.fullmatch('dw-writer-host-[0-9a-f]{16}\\.service',binding['unit'])
                    or type(binding['invocationId']) is not str or not re.fullmatch('[0-9a-f]{32}',binding['invocationId'])
                    or type(binding['kernelBoot']) is not str or not re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',binding['kernelBoot'])):reject()
            self._binding=encode(binding)
        except BaseException as primary:
            self._cleanup_error_codes.append('startup')
            if fd is not None:
                try:os.close(fd)
                except Exception:self._cleanup_error_codes.append('stderr-file-close')
            try:self._dispose_local()
            except Exception:self._cleanup_error_codes.append('local-dispose')
            self._closed=True
            _ISSUED.pop(self,None)
            try:self._save_cleanup_report()
            except Exception:
                self._cleanup_error_codes.append('report-write')
                try:self._capture_cleanup_report()
                except Exception:pass
                _note_cleanup_failure(primary)
            raise

    @property
    def diagnostic_profile(self):
        return profiles.marker(self._profile)

    def _capture_cleanup_report(self):
        process=self._process
        self._cleanup_snapshot=encode(dict(schemaVersion=1,sourceSha=self.source_sha,
            **({'diagnosticProfile':self.diagnostic_profile,
                'diagnosticObservationVerified':self.diagnostic_observation_verified,
                'diagnosticObservation':self.diagnostic_observation()} if self._profile is profiles.RESPONSE_LOSS else {}),
            archiveDigest=self.archive_digest,hostId=self.host_id,closed=self._closed,
            completionPathSucceeded=self._completion_path_succeeded,
            managerReceiptVerified=self._finished,
            daemonStoppedVerified=self.daemon_stopped_verified,
            resourceInventoryRestored=self.resource_inventory_restored,
            hostSnapshotUnchangedVerified=self.host_snapshot_unchanged_verified,
            localProcessReaped=process is not None and process.poll() is not None,
            localStreamsClosed=process is not None and all(s is None or s.closed
                for s in (process.stdin,process.stdout,process.stderr)),
            stderrReaderStopped=self._reader is not None and not self._reader.is_alive(),
            cleanupErrors=list(self._cleanup_error_codes),authorityGranted=False,
            runtimePermit=False,daemonCleanupVerified=False,productionReady=False))

    def cleanup_report(self):
        """Descriptive snapshot only; serialized reports never issue authority."""
        if (os.getpid(),threading.get_ident())!=(self._pid,self._thread):reject()
        if self._cleanup_snapshot is None:self._capture_cleanup_report()
        return json.loads(self._cleanup_snapshot)

    def _save_cleanup_report(self):
        self._capture_cleanup_report()
        temporary=self._case/('cleanup-report-'+secrets.token_hex(8)+'.new')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as output:output.write(self._cleanup_snapshot+b'\n')
            os.link(temporary,self._case/'cleanup-report.private.json')
        finally:temporary.unlink()

    def _left(self,limit=30):
        issued(self)
        left=self._deadline-time.monotonic()
        if self._closed or left<=0 or (self._errors and not self._cleanup_mode):reject()
        return min(limit,left)

    def _send(self,kind,initial=None,**data):
        frame=initial if initial is not None else dict(kind=kind,channelNonce=self.nonce,**data)
        write_frame(self._process.stdin,frame,timeout=self._left())

    def _receive(self,limit=30):
        from deployment_compose_owned_recovery_controller_v3_host import _receive
        value=_receive(self._process.stdout,time.monotonic()+self._left(limit),[] if self._cleanup_mode else self._errors)
        self._count+=1;self._bytes+=len(encode(value))
        if (self._count>4096 or self._bytes>64*1024*1024 or type(value) is not dict
                or value.get('channelNonce')!=self.nonce):reject()
        return value

    def begin(self,timeout):
        issued(self)
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=3600 or self._started:reject()
        self._left();self._deadline=min(self._maximum,time.monotonic()+timeout)
        self._started=True
        self._send('manager-start')

    def bind_diagnostic_request(self,bundle,request):
        from deployment_compose_bundle_v3 import ExecutionBundleV3
        from deployment_contract_v2 import RequestV2
        from deployment_compose_coordinator_v3_host import canonical
        issued(self)
        if (self._profile is not profiles.RESPONSE_LOSS or not self._started or self._diagnostic_consumed
                or self._diagnostic_expected is not None or self._hello_identity is None
                or type(bundle) is not ExecutionBundleV3 or type(request) is not RequestV2
                or request.operation!='deploy' or request.plan_hash!=bundle.digest
                or request.host_id!=self.host_id or request.source.source_sha!=self.source_sha
                or request.daemon_id!=self._hello_identity[1]):reject()
        operations=bundle.creation_operations()
        if len(operations)!=1 or operations[0]['method']!='POST':reject()
        op=operations[0]
        self._diagnostic_expected=dict(requestHash=request.digest(),method=op['method'],
            pathSha256=hashlib.sha256(op['path'].encode('ascii')).hexdigest(),
            bodySha256=hashlib.sha256(canonical(op['body'])).hexdigest())

    def diagnostic_observation(self):
        if (os.getpid(),threading.get_ident())!=(self._pid,self._thread):reject()
        return json.loads(self._diagnostic_fact) if self.diagnostic_observation_verified else None

    def _accept_observation(self,value):
        if (self._profile is not profiles.RESPONSE_LOSS or self._diagnostic_fact is not None
                or not self._diagnostic_consumed or self._diagnostic_expected is None
                or self._hello_identity is None or self._awaiting_daemon_hello
                or set(value)!={'kind','channelNonce','binding','observation'}
                or value['kind']!=KIND or encode(value['binding'])!=self._binding):reject()
        fact=validate_observation(value['observation'])
        expected=dict(self._diagnostic_expected,sourceSha=self.source_sha,archiveDigest=self.archive_digest,
            hostId=self.host_id,root=self._hello_identity[0],daemonId=self._hello_identity[1])
        if any(fact[k]!=v for k,v in expected.items()):reject()
        self._diagnostic_fact=encode(fact)

    def send_worker(self,frame):
        issued(self)
        if self._early_terminal is not None or not self._started or type(frame) is not dict or frame.get('channelNonce')!=self.nonce:reject()
        if self._profile is profiles.RESPONSE_LOSS and frame.get('kind')=='consume-intent':
            if (self._diagnostic_consumed or self._diagnostic_expected is None
                    or frame.get('requestHash')!=self._diagnostic_expected['requestHash']):reject()
            self._diagnostic_consumed=True  # Partial sends cannot be retried.
        self._send('worker-frame',frame=frame)

    def receive_worker(self,limit=900):
        if not self._started or self._early_terminal is not None:reject()
        def next_frame():
            value=self._receive(limit)
            while value.get('kind')==KIND:
                self._accept_observation(value);value=self._receive(limit)
            if value.get('kind')=='manager-stopped':
                # Business failed. Preserve this one bounded frame only for
                # close's full binding/terminal/EOF/SSH verification.
                self._early_terminal=encode(value)
                reject()
            return value
        value=next_frame()
        first_daemon=self.verify_daemon_stop and self._daemon_binding is None
        if first_daemon:
            self._accept_daemon(value)
            value=next_frame()
        if set(value)!={'kind','channelNonce','frame'} or value['kind']!='worker-frame':reject()
        frame=value['frame']
        if type(frame) is not dict or frame.get('channelNonce')!=self.nonce or type(frame.get('kind')) is not str:reject()
        if self._awaiting_daemon_hello:self._match_daemon_hello(frame)
        if frame['kind']=='hello':
            if self._hello_identity is not None:reject()
            self._hello_identity=(frame.get('root'),frame.get('daemonId'))
            self._hello_canonical=encode({k:v for k,v in frame.items() if k not in ('kind','channelNonce')})
        if self._profile is profiles.RESPONSE_LOSS and frame['kind'] in ('recovery-prepared-private','final'):reject()
        return frame

    def _match_daemon_hello(self,frame):
        binding=json.loads(self._daemon_binding)
        if (type(frame) is not dict or frame.get('channelNonce')!=self.nonce or frame.get('kind')!='hello'
                or frame.get('root')!=binding['root'] or frame.get('daemonId')!=binding['daemonId']):reject()
        self._awaiting_daemon_hello=False

    def _accept_daemon(self,value):
        if (set(value)!={'kind','channelNonce','binding','daemonBinding'}|(
                    {'resourceBaselineDigest'} if self.verify_resource_inventory else set()) or value['kind']!='daemon-bound'
                or encode(value['binding'])!=self._binding):reject()
        if self.verify_resource_inventory:
            digest=value['resourceBaselineDigest']
            if type(digest) is not str or not re.fullmatch('[0-9a-f]{64}',digest):reject()
            self._resource_baseline=digest
        binding=value['daemonBinding']
        names={'root','daemonId','unit','kernelBoot','invocationId','cgroupDevice','cgroupInode',
            'mainPid','mainStartTicks','daemonPid','daemonStartTicks'}
        if (type(binding) is not dict or set(binding)!=names
                or type(binding['root']) is not str or not re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}',binding['root'])
                or type(binding['daemonId']) is not str or not 0<len(binding['daemonId'])<=256
                or binding['unit']!=binding['root'].rsplit('/',1)[1]+'.service'
                or binding['kernelBoot']!=json.loads(self._binding)['kernelBoot']
                or type(binding['invocationId']) is not str or not re.fullmatch('[0-9a-f]{32}',binding['invocationId'])
                or any(type(binding[k]) is not int or not 0<binding[k]<2**64 for k in
                    ('cgroupInode','mainPid','mainStartTicks','daemonPid','daemonStartTicks'))
                or type(binding['cgroupDevice']) is not int or not 0<=binding['cgroupDevice']<2**64):reject()
        self._daemon_binding=encode(binding)
        self._awaiting_daemon_hello=True

    def _terminal(self,value,*,business):
        if (set(value)!={'kind','channelNonce','binding','workerStartRequested','reason','wrapperStopped',
                'transportReturncode','daemonCleanupVerified','productionReady'}|({'diagnosticObservationDigest'} if self._profile is profiles.RESPONSE_LOSS else set())|(
                    {'daemonBinding','daemonStoppedVerified'} if self.verify_daemon_stop else set())|(
                    {'resourceBaselineDigest','resourceAfterDigest','resourceInventoryRestored'}
                    if self.verify_resource_inventory else set())|(
                    {'hostSnapshotBaseline','hostSnapshotAfterDigest','hostSnapshotUnchangedVerified'}
                    if self.verify_host_snapshot else set())
                or value['kind']!='manager-stopped' or encode(value['binding'])!=self._binding
                or value['workerStartRequested'] is not self._started or value['wrapperStopped'] is not True
                or value['daemonCleanupVerified'] is not False or value['productionReady'] is not False
                or type(value['transportReturncode']) is not int
                or value['reason'] not in ('worker-eof','requested-stop')):reject()
        if self._profile is profiles.RESPONSE_LOSS:
            expected_digest=observation_digest(json.loads(self._diagnostic_fact)) if self._diagnostic_fact is not None else None
            if value['diagnosticObservationDigest']!=expected_digest:reject()
        if business and (value['reason']!='worker-eof' or value['transportReturncode']!=0):reject()
        self._pending_daemon_stop=False
        if self.verify_daemon_stop:
            if self._awaiting_daemon_hello:reject()
            if self._daemon_binding is None:
                if business or value['daemonBinding'] is not None or value['daemonStoppedVerified'] is not False:reject()
            elif encode(value['daemonBinding'])!=self._daemon_binding or value['daemonStoppedVerified'] is not True:reject()
            self._pending_daemon_stop=self._daemon_binding is not None
        self._pending_resources=False
        if self.verify_resource_inventory:
            if value['resourceBaselineDigest']!=self._resource_baseline:reject()
            if self._resource_baseline is None:
                if business or value['resourceAfterDigest'] is not None or value['resourceInventoryRestored'] is not False:reject()
            elif value['resourceInventoryRestored'] is True:
                if value['resourceAfterDigest']!=self._resource_baseline:reject()
                self._pending_resources=True
            elif business or value['resourceInventoryRestored'] is not False or value['resourceAfterDigest'] is not None:reject()
        self._pending_host=False
        if self.verify_host_snapshot:
            if (encode(value['hostSnapshotBaseline'])!=self._host_baseline
                    or value['hostSnapshotAfterDigest']!=json.loads(self._host_baseline)['beforeDigest']
                    or value['hostSnapshotUnchangedVerified'] is not True):reject()
            self._pending_host=True

    def _exit(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self._process.stdout,selectors.EVENT_READ)
            if not selector.select(self._left()):reject()
            if os.read(self._process.stdout.fileno(),1):reject()
        if self._process.wait(timeout=self._left())!=0:reject()
        self._reader.join(timeout=self._left(5))
        if self._reader.is_alive() or self._errors:reject()
        self.daemon_stopped_verified=self._pending_daemon_stop
        self.resource_inventory_restored=self._pending_resources
        self.host_snapshot_unchanged_verified=self._pending_host
        self.diagnostic_observation_verified=self._diagnostic_fact is not None
        self._finished=True

    def complete(self):
        issued(self)
        if self._profile is profiles.RESPONSE_LOSS or not self._started or self._finished or self._early_terminal is not None:reject()
        self._terminal(self._receive(60 if self.verify_host_snapshot else 30),business=True)
        self._exit()
        self._completion_path_succeeded=True

    def _dispose_local(self):
        failure=None
        def cleanup(action):
            nonlocal failure
            try:action()
            except Exception as error:
                if failure is None:failure=error
        if self._process is not None:
            if self._process.poll() is None:
                cleanup(self._process.kill);cleanup(lambda:self._process.wait(timeout=5))
        self._stop_reader.set()
        if self._reader is not None and self._reader.ident is not None:cleanup(lambda:self._reader.join(timeout=1))
        if self._reader is not None and self._reader.is_alive():
            self._cleanup_error_codes.append('stderr-reader-alive')
            cleanup(reject)
        if self._process is not None:
            for stream in (self._process.stdin,self._process.stdout,self._process.stderr):
                if stream is not None:cleanup(stream.close)
        if failure is not None:raise failure

    def close(self):
        if (os.getpid(),threading.get_ident())!=(self._pid,self._thread):reject()
        if self._closed:return
        issued(self)
        failure=None
        try:
            if not self._finished and self._binding is not None:
                # Cleanup has its own finite budget; it cannot resume business.
                self._deadline=time.monotonic()+(90 if self.verify_host_snapshot else 30)
                self._cleanup_mode=True
                if self._process.poll() is None and self._early_terminal is None:
                    try:self._send('manager-stop')
                    except BrokenPipeError:pass  # Exit may race with the stop send; still verify queued receipt.
                for _ in range(4096):
                    if self._early_terminal is not None:
                        value=json.loads(self._early_terminal);self._early_terminal=None
                    else:value=self._receive(90 if self.verify_host_snapshot else 30)
                    if value['kind']==KIND:
                        self._accept_observation(value);continue
                    if value['kind']=='daemon-bound' and self.verify_daemon_stop and self._daemon_binding is None:
                        self._accept_daemon(value);continue
                    if value['kind']=='worker-frame':
                        if self._awaiting_daemon_hello:
                            if set(value)!={'kind','channelNonce','frame'}:reject()
                            self._match_daemon_hello(value['frame'])
                        if value.get('frame',{}).get('kind')=='hello':
                            self._hello_identity=(value['frame'].get('root'),value['frame'].get('daemonId'))
                        continue
                    self._terminal(value,business=False);self._exit();break
                else:reject()
        except Exception as error:
            self._cleanup_error_codes.append('manager-close');failure=error
        finally:
            try:self._dispose_local()
            except Exception as error:
                self._cleanup_error_codes.append('local-dispose')
                if failure is None:failure=error
            finally:self._closed=True;_ISSUED.pop(self,None)
            try:self._save_cleanup_report()
            except Exception as error:
                self._cleanup_error_codes.append('report-write')
                try:self._capture_cleanup_report()
                except Exception:pass
                if failure is None:failure=error
                else:_note_cleanup_failure(failure)
        if failure is not None:raise failure


class ResponseLossSSHSessionV3(OwnedRecoverySSHSessionV3):
    """Issued fixed diagnostic profile; never completes business or recovery."""
