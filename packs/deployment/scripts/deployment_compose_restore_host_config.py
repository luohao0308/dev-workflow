"""Fixed-profile private HostConfig fragment, not an Engine create request.

Every observed field has an explicit local policy. Matching this policy does
not prove daemon defaults, bind source types, network semantics, or write safety.
"""
from copy import deepcopy
import hashlib

from deployment_compose_host_config import REQUIRED
from deployment_compose_snapshot import _encode, prepare_snapshot

POLICY = 'compose-sample-host-config-v1'
DOMAIN = b'dev-workflow:compose-restore-host-config-fragment:v1\0'
MASKED_PATHS = ('/proc/acpi', '/proc/asound', '/proc/interrupts', '/proc/kcore',
                '/proc/keys', '/proc/latency_stats', '/proc/sched_debug', '/proc/scsi',
                '/proc/timer_list', '/proc/timer_stats', '/sys/devices/virtual/powercap', '/sys/firmware')
READONLY_PATHS = ('/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger')


def _fail():
    raise ValueError('invalid-compose-restore-host-config-fragment')


def _fixed_policy():
    # Independent closed policy: do not generate these groups from the mapper.
    # A future mapper field must also receive an explicit policy here.
    fixed = {k: False for k in ('AutoRemove', 'Privileged', 'PublishAllPorts')}
    fixed.update({k: '' for k in ('Cgroup', 'CgroupParent', 'ContainerIDFile',
        'CpusetCpus', 'CpusetMems', 'Isolation', 'PidMode', 'UTSMode', 'UsernsMode', 'VolumeDriver')})
    fixed.update({k: 0 for k in ('BlkioWeight', 'CpuCount', 'CpuPercent', 'CpuPeriod',
        'CpuQuota', 'CpuRealtimePeriod', 'CpuRealtimeRuntime', 'CpuShares',
        'IOMaximumBandwidth', 'IOMaximumIOps', 'MemoryReservation', 'OomScoreAdj')})
    fixed.update({k: None for k in ('Binds', 'CapAdd', 'CapDrop', 'DeviceCgroupRules',
        'Dns', 'DnsOptions', 'DnsSearch', 'GroupAdd', 'Links', 'SecurityOpt', 'VolumesFrom',
        'BlkioDeviceReadBps', 'BlkioDeviceReadIOps', 'BlkioDeviceWriteBps',
        'BlkioDeviceWriteIOps', 'BlkioWeightDevice', 'DeviceRequests', 'Devices', 'Ulimits',
        'MemorySwappiness', 'OomKillDisable')})
    fixed.update(ReadonlyRootfs=True, CgroupnsMode='private', IpcMode='private', Runtime='runc',
                 ConsoleSize=[0, 0], ExtraHosts=[], MaskedPaths=list(MASKED_PATHS),
                 ReadonlyPaths=list(READONLY_PATHS), Memory=67108864, MemorySwap=67108864,
                 NanoCpus=100000000, ShmSize=67108864, PidsLimit=32, PortBindings={},
                 Tmpfs={'/tmp': 'size=4m'},
                 LogConfig={'Type': 'json-file', 'Config': {'max-file': '3', 'max-size': '10m'}},
                 RestartPolicy={'Name': 'unless-stopped', 'MaximumRetryCount': 0})
    return fixed


def compile_restore_host_config(raw, identity, artifact, private_key, network_ids,
                                expected_mounts, *, policy):
    """Authenticate the full original snapshot and match an explicit fixed profile.

    Artifact, identity and topology must be independently pinned by the host.
    This does not authenticate their origin or grant execution authority.
    """
    try:
        if type(policy) is not str or policy != POLICY:
            _fail()
        snapshot = prepare_snapshot(raw, identity, artifact, private_key,
                                    network_ids, expected_mounts)
        host = snapshot['hostConfig']['rawHostConfig']
        fixed = _fixed_policy()
        if set(fixed) | {'NetworkMode'} != REQUIRED or set(fixed) & {'NetworkMode'}:
            _fail()
        # Canonical comparison preserves exact types: False != 0, null != [].
        if any(_encode(host[k]) != _encode(value) for k, value in fixed.items()):
            _fail()
        if len(network_ids) != 1:
            _fail()
        name, network_id = next(iter(network_ids.items()))
        if host['NetworkMode'] not in (name, network_id):
            _fail()
        # Current profile deliberately covers the historical sample's two
        # destinations only. Snapshot already requires matching declarations,
        # RO binds and volume NoCopy; unknown destinations cannot widen policy.
        for target, mount in expected_mounts.items():
            if ((target == '/sample-data' and mount['type'] == 'volume')
                    or (target == '/sample-config' and mount['type'] == 'bind'
                        and mount['readOnly'] is True)):
                continue
            _fail()
        result = {
            'schemaVersion': 1, 'kind': 'compose-restore-host-config-fragment',
            'policy': policy,
            'policyDigest': hashlib.sha256(_encode({'policy': policy, 'fixedValues': fixed,
                'networkMode': 'one-pinned-network-name-or-id',
                'mountDestinations': {'/sample-data': 'volume-nocopy', '/sample-config': 'bind-readonly'}})).hexdigest(),
            'sourceSnapshotDigest': hashlib.sha256(_encode(snapshot)).hexdigest(),
            'sourceConfigHmac': artifact.config_hmac,
            'hostConfigFragment': deepcopy(host),
            'networkModeBinding': {'observed': host['NetworkMode'], 'networkName': name,
                                   'networkId': network_id, 'createSemanticsValidated': False},
            'daemonEffectiveDefaultsVerified': False, 'bindSourceTypesVerified': False,
            'blockers': ['daemon-effective-defaults-required', 'fresh-bind-source-type-and-identity-required',
                         'network-create-semantics-and-config-composition-required',
                         'hostname-and-lifecycle-metadata-policy-required',
                         'independent-engine-reconstruction-required',
                         'trusted-approval-writer-and-independent-anchor-required'],
            'completeCreatePayloadAvailable': False, 'authorityGranted': False,
            'executionAvailable': False, 'reconstructionValidated': False, 'productionReady': False,
        }
        result['fragmentDigest'] = hashlib.sha256(DOMAIN + _encode(result)).hexdigest()
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()
