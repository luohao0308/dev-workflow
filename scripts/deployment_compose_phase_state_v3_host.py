"""Private, host-only raw Docker baseline producer for v3 preparation.

The embedding supplies the trusted local Unix socket and pinned identity. This
object is never attached to the TLS reader gateway: its output contains secrets.
Exact types enforce the embedding contract; they do not authenticate a machine.
"""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import re
import json
import hashlib
import time
import deployment_runtime as runtime

from deployment_compose_reader_host import _UnixDocker, _complete_json_response
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, protected_state_digest, baseline_state_bytes


class TrustedPhaseStateProducerV3:
    def __init__(self, *, socket_path, project, daemon_id, container_ids, timeout=5):
        if (type(socket_path) is not str or not Path(socket_path).is_absolute()
                or type(project) is not str or not re.fullmatch(r'dw-[A-Za-z0-9_.-]+', project)
                or type(daemon_id) is not str or not daemon_id
                or type(container_ids) is not tuple or not container_ids
                or container_ids != tuple(sorted(set(container_ids)))
                or any(type(cid) is not str or not re.fullmatch(r'[0-9a-f]{64}', cid) for cid in container_ids)
                or type(timeout) not in (int, float) or not 0 < timeout <= 30):
            raise ValueError('compose-phase-state-v3-rejected')
        self.project, self.daemon_id, self.container_ids = project, daemon_id, container_ids
        self._socket_path, self._timeout = socket_path, timeout
        self._deadline = None

    @contextmanager
    def operation_scope(self, deadline):
        if (self._deadline is not None or type(deadline) not in (int, float)
                or not time.monotonic() < deadline <= time.monotonic()+180):
            raise ValueError('compose-phase-state-v3-rejected')
        self._deadline = deadline
        try:
            yield
        finally:
            self._deadline = None

    def _get(self, path):
        deadline = time.monotonic()+self._timeout
        if self._deadline is not None: deadline = min(deadline,self._deadline)
        remaining = deadline-time.monotonic()
        if remaining <= 0: raise ValueError('compose-phase-state-v3-rejected')
        connection = _UnixDocker(self._socket_path, remaining)
        watchdog = None
        try:
            connection.connect()
            watchdog = runtime.deadline_watchdog(connection.sock, deadline)
            connection.request('GET', path, headers={'Accept': 'application/json'})
            return _complete_json_response(connection.getresponse())[1]
        finally:
            if watchdog is not None: watchdog.cancel()
            connection.close()

    def capture(self):
        """Return private original rows; preparation authenticates their HMACs."""
        try:
            if self._get('/v1.45/info')['ID'] != self.daemon_id:
                raise ValueError()
            rows = {}
            for cid in self.container_ids:
                row = self._get('/v1.45/containers/' + cid + '/json')
                if (row['Id'] != cid or row['Config']['Labels']['com.docker.compose.project'] != self.project):
                    raise ValueError()
                PhaseGuardV3._healthy(row)
                protected_state_digest(row)
                rows[cid] = row
            return deepcopy(rows)
        except Exception:
            raise ValueError('compose-phase-state-v3-rejected') from None

    @staticmethod
    def reload(store, bundle, *, read_json, daemon_version, expected_docker_root=None):
        """Load the signed bundle's original private baseline, never recapture it.

        The exact recovery store verifies its immutable CAS envelope and HMAC.
        PhaseGuard checks the signed baseline digest, identities and create bodies.
        The embedding authenticates the bundle and the phase-time GET transport.
        """
        from deployment_compose_recovery_store import ComposeRecoveryStore
        from deployment_compose_bundle_v3 import ExecutionBundleV3
        try:
            if type(store) is not ComposeRecoveryStore or type(bundle) is not ExecutionBundleV3:
                raise ValueError()
            value=bundle.to_dict()
            raw=store.get(value['baselineStateReference'])
            if hashlib.sha256(raw).hexdigest() != value['baselineStateDigest']:
                raise ValueError()
            rows=json.loads(raw)
            for row in rows.values():
                row['State']['Health']={'Status':row.pop('Health')}
            if baseline_state_bytes(rows) != raw:
                raise ValueError()
            PhaseGuardV3(bundle, rows, read_json=read_json, daemon_version=daemon_version,
                         expected_docker_root=expected_docker_root)
            return rows
        except Exception:
            raise ValueError('compose-phase-state-v3-rejected') from None
