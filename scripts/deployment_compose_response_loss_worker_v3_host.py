"""Fixed private response-unobserved diagnostic leaf; not a normal manager entry.

Only the distinct profile-bound diagnostic session/manager launches this leaf.
The normal route cannot select it. Request return means dispatch, not commit.
"""
import http.client
import os
import re
import threading

import deployment_compose_owned_recovery_worker_v3_host as worker
import deployment_compose_write_gateway_v3_host as gateway

ENTRYPOINT = 'deployment_compose_response_loss_worker_v3_host.run'
_PID = os.getpid()
_USED = False
_LOCK = threading.Lock()
_CREATE = re.compile(r'/v1\.45/containers/create\?name=dwc-[0-9a-f]{24}-backend')


def reject():
    raise ValueError('compose-response-loss-worker-v3-rejected') from None


def _connector(original):
    """One write attempt, including partial-send failures; no retry authority."""
    state = dict(attempts=0, dispatched=False)
    lock = threading.Lock()

    class ResponseUnobserved(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._drop_response = False

        def request(self, method, url, body=None, headers={}, *, encode_chunked=False):
            if method == 'GET':
                return super().request(method, url, body, headers, encode_chunked=encode_chunked)
            with lock:
                if method != 'POST' or type(url) is not str or not _CREATE.fullmatch(url) or state['attempts']:
                    reject()
                state['attempts'] = 1
                self._drop_response = True
            try:
                result = super().request(method, url, body, headers, encode_chunked=encode_chunked)
            except BaseException:
                try:self.close()
                except Exception:pass
                raise
            state['dispatched'] = True
            return result

        def getresponse(self):
            if not self._drop_response:
                return super().getresponse()
            try:self.close()
            except Exception:pass
            raise http.client.RemoteDisconnected('fixed-diagnostic-response-unobserved')

    return ResponseUnobserved, state


def run(config, stdin, stdout):
    if type(config) is not dict or config.get('entrypoint') != ENTRYPOINT:reject()
    adapted = dict(config, entrypoint=worker.ENTRYPOINT)
    worker.Channel(adapted, None, None)  # Full fixed shape before any provisioning.
    global _USED
    if os.getpid() != _PID or threading.current_thread() is not threading.main_thread() or _USED:reject()
    if not _LOCK.acquire(blocking=False):reject()
    original = gateway._UnixDocker
    try:
        _USED = True
        connector, _ = _connector(original)
        gateway._UnixDocker = connector
        worker.run(adapted, stdin, stdout)
        reject()  # This diagnostic cannot report successful business completion.
    finally:
        gateway._UnixDocker = original
        _LOCK.release()
