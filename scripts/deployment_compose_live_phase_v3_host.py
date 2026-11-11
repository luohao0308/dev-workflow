"""Live applicability reads for a reauthenticated prefix, never recovery authority."""
from dataclasses import asdict, dataclass, field
import hashlib
import math
import time

from deployment_compose_restart_material_v3_host import _root, _prefix, _baseline
from deployment_compose_recovery_phase_capsule_v3_host import decode, inflate
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_witness_store import canonical


def reject():raise ValueError('compose-live-recovery-phase-v3-rejected') from None


def digest(raw):return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class LiveRecoveryPhaseV3:
    phase_bytes: bytes = field(repr=False)
    endpoint_binding: bytes = field(repr=False)
    history_digest: str
    baseline_digest: str
    endpoint_binding_digest: str
    phase_digest: str
    phaseApplicabilityVerified: bool = field(default=True,init=False)
    liveReadsVerified: bool = field(default=True,init=False)
    currentDaemonIdentityVerified: bool = field(default=True,init=False)
    daemonContinuityVerified: bool = field(default=False,init=False)
    phaseFreshnessVerified: bool = field(default=False,init=False)
    writerQuiescenceVerified: bool = field(default=False,init=False)
    authorityGranted: bool = field(default=False,init=False)
    executionAvailable: bool = field(default=False,init=False)
    runtimePermit: bool = field(default=False,init=False)
    recoveryAuthorized: bool = field(default=False,init=False)
    productionReady: bool = field(default=False,init=False)

    def public_summary(self):
        return {k:getattr(self,k) for k in self.__dataclass_fields__ if k not in ('phase_bytes','endpoint_binding')}


class LiveRecoveryPhaseCaptureV3:
    def __copy__(self):
        reject()

    def __deepcopy__(self,memo):
        reject()

    def __reduce_ex__(self,protocol):
        reject()

    def __init__(self,*,original_history,baseline_bytes,daemon,expected_version):
        try:
            _root(original_history)
            _baseline(baseline_bytes,original_history._bundle)
            if (type(daemon) is not ObservedRecoveryDaemonV3 or daemon.daemon_id!=original_history._request.daemon_id
                    or type(expected_version) is not dict or set(expected_version)!={'Version','GitCommit'}
                    or any(type(v) is not str or not v for v in expected_version.values())):reject()
            self._history=original_history;self._baseline=baseline_bytes;self._daemon=daemon
            self._version=canonical(expected_version)
            self._seal=self._identity()
        except Exception:reject()

    def _identity(self):
        history=self._history;daemon=self._daemon
        return (history,daemon,self._baseline,self._version,history._bundle.canonical_bytes,history._request.canonical_json(),canonical(asdict(history._policy)),
                history._key,history._receipt,history._client,history._factory,daemon.root,daemon.daemon_id,
                canonical(daemon.binding()))

    def capture(self,timeout=15):
        try:
            if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=30:reject()
            deadline=time.monotonic()+timeout
            if self._identity()!=self._seal:reject()
            history=self._history;before=history.capture();value=_prefix(history,before)
            baseline=inflate(decode(self._baseline));bundle=history._bundle
            ops=bundle.resolve_operations(value['receiptMap']);writes=[op for op in ops if op['method']!='GET']
            following=writes[1]
            context=dict(phase_index=1,operation=following,receipts=value['receiptMap'],completed_operations=ops[:ops.index(following)])
            left=deadline-time.monotonic()
            if left<=0:reject()
            phase,endpoint=self._daemon.capture_recovery_phase(bundle,baseline,context,
                expected_version=decode(self._version),timeout=left)
            decode(phase);decode(endpoint)
            if history.capture().canonical!=before.canonical or self._identity()!=self._seal:reject()
            result=LiveRecoveryPhaseV3(phase,endpoint,before.digest,digest(self._baseline),digest(endpoint),digest(phase))
            if time.monotonic()>=deadline:reject()
            return result
        except Exception:reject()
