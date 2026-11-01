"""Fixed private response-unobserved diagnostic leaf; not a normal manager entry.

Only the distinct profile-bound diagnostic session/manager launches this leaf.
The normal route cannot select it. Request return means dispatch, not commit.
"""
import hashlib
import http.client
import os
import re
import threading
import time

import deployment_compose_owned_recovery_worker_v3_host as worker
import deployment_compose_write_gateway_v3_host as gateway

ENTRYPOINT = 'deployment_compose_response_loss_worker_v3_host.run'
_PID = os.getpid()
_USED = False
_LOCK = threading.Lock()
_CREATE = re.compile(r'/v1\.45/containers/create\?name=dwc-[0-9a-f]{24}-backend')


def reject():
    raise ValueError('compose-response-loss-worker-v3-rejected') from None


def _connector(original, observer=None):
    """One write attempt, including partial-send failures; no retry authority."""
    state = dict(attempts=0, dispatched=False, suppressed=False)
    lock = threading.Lock()

    class ResponseUnobserved(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._drop_response = False

        def request(self, method, url, body=None, headers={}, *, encode_chunked=False):
            if method == 'GET':
                return super().request(method, url, body, headers, encode_chunked=encode_chunked)
            with lock:
                if method != 'POST' or type(url) is not str or not _CREATE.fullmatch(url) or type(body) is not bytes or state['attempts']:
                    reject()
                state['attempts'] = 1
                self._drop_response = True
                self._observation = dict(method=method,pathSha256=hashlib.sha256(url.encode('utf-8')).hexdigest(),
                    bodySha256=hashlib.sha256(body if body is not None else b'').hexdigest())
            try:
                result = super().request(method, url, body, headers, encode_chunked=encode_chunked)
            except BaseException:
                try:self.close()
                except Exception:pass
                raise
            with lock:state['dispatched'] = True
            return result

        def getresponse(self):
            if not self._drop_response:
                return super().getresponse()
            notify=None
            with lock:
                if state['dispatched'] and not state['suppressed']:
                    state['suppressed']=True
                    notify=dict(self._observation)
            try:self.close()
            except Exception:pass
            if notify is not None and observer is not None:observer(notify)
            raise http.client.RemoteDisconnected('fixed-diagnostic-response-unobserved')

    return ResponseUnobserved, state


def _channel_class(base, config, channels):
    from deployment_compose_response_loss_observation_v3_host import KIND, validate_observation
    from deployment_compose_recovery_profiles_v3_host import RESPONSE_LOSS_MARKER
    class ObservedChannel(base):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            if channels:reject()
            self._hello=None;self._request_hash=None
            channels.append(self)

        def emit(self,kind,**payload):
            deadline=time.monotonic()+min(30,self.timeout())
            acquired=False
            try:
                acquired=self._rpc_lock.acquire(timeout=max(0,deadline-time.monotonic()))
                if not acquired:reject()
                hello=None
                if kind=='hello':
                    if self._hello is not None:reject()
                    hello=dict(root=payload['root'],daemonId=payload['daemonId'])
                left=min(deadline-time.monotonic(),self.timeout())
                if left<=0:reject()
                worker.live.write_frame(self.stdout,worker.live.private_json(dict(
                    kind=kind,channelNonce=self.config['channelNonce'],**payload)),timeout=left)
                if hello is not None:self._hello=hello
            except BaseException:
                self.failed=True
                raise
            finally:
                if acquired:self._rpc_lock.release()

        def receive(self,kind):
            result=super().receive(kind)
            if kind=='consume-intent':
                value=result.get('requestHash')
                if self._request_hash is not None or type(value) is not str or not re.fullmatch('[0-9a-f]{64}',value):reject()
                self._request_hash=value
            return result

        def observe(self,details):
            if self._hello is None or self._request_hash is None:reject()
            observation=validate_observation(dict(schemaVersion=1,
                diagnosticProfile=RESPONSE_LOSS_MARKER,sourceSha=config['sourceSha'],
                archiveDigest=config['archiveDigest'],hostId=config['hostId'],
                **self._hello,requestHash=self._request_hash,**details,attempts=1,
                requestReturned=True,responseSuppressed=True,originalResponseRead=False,
                engineOutcome='unknown',authorityGranted=False,runtimePermit=False,productionReady=False))
            self.emit(KIND,observation=observation)
    return ObservedChannel


def run(config, stdin, stdout):
    if type(config) is not dict or config.get('entrypoint') != ENTRYPOINT:reject()
    adapted = dict(config, entrypoint=worker.ENTRYPOINT)
    worker.Channel(adapted, None, None)  # Full fixed shape before any provisioning.
    global _USED
    if os.getpid() != _PID or threading.current_thread() is not threading.main_thread() or _USED:reject()
    if not _LOCK.acquire(blocking=False):reject()
    original = gateway._UnixDocker
    original_channel=worker.Channel
    channels=[]
    try:
        _USED = True
        def observe(details):
            if len(channels)!=1:reject()
            channels[0].observe(details)
        connector, _ = _connector(original,observe)
        worker.Channel=_channel_class(original_channel,config,channels)
        gateway._UnixDocker = connector
        worker.run(adapted, stdin, stdout)
        reject()  # This diagnostic cannot report successful business completion.
    finally:
        gateway._UnixDocker = original
        worker.Channel=original_channel
        _LOCK.release()
