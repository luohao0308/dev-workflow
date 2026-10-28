"""Shared-host, separate network/mount namespace daemon startup diagnostic.

Default probe creates no workloads; only a trusted explicit callback may run them.
Never use the production containerd socket.
Only the unique transient systemd unit is stopped; private evidence is retained.
"""
import json
import hashlib
import shutil
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


def run(*args, timeout=20):
    return subprocess.run(args, capture_output=True, timeout=timeout, check=True).stdout


def configuration(root, unit, *, storage_driver="vfs"):
    if (not isinstance(root, Path) or root.parent != Path('/var/tmp')
            or not re.fullmatch(r'dw-engine-[a-f0-9]{16}', root.name)
            or unit != root.name + '.service'):
        raise ValueError('invalid-isolated-daemon-scope')
    if storage_driver not in ('vfs','overlayfs'):
        raise ValueError('unsupported-isolated-storage-driver')
    return {'data-root': str(root/'data'), 'exec-root': str(root/'exec'),
            'pidfile': str(root/'daemon.pid'), 'hosts': ['unix://' + str(root/'docker.sock')],
            'bridge': 'none', 'iptables': False, 'ip6tables': False, 'ip-forward': False,
            'ip-masq': False, 'userland-proxy': False, 'storage-driver': storage_driver,
            'features': {'containerd-snapshotter': storage_driver=='overlayfs'},
            'containerd': str(root/'containerd.sock'),
            'containerd-namespace': root.name, 'containerd-plugins-namespace': root.name+'-plugins',
            'exec-opts': ['native.cgroupdriver=cgroupfs'],
            'cgroup-parent': '/system.slice/' + unit}


def firewall_digest(*, evidence_path=None):
    result={};captured={}
    for tool in ('iptables-save','ip6tables-save'):
        if shutil.which(tool):
            raw=run(tool)
            if evidence_path is not None:captured[tool]=raw.decode('utf-8')
            lines=raw.splitlines()
            material=b'\n'.join(x for x in lines if x and not x.startswith(b'#'))
            material=re.sub(rb'(?m)^(:[^\n]+ )\[[0-9]+:[0-9]+\]$',rb'\1[COUNTERS]',material)
            result[tool]=hashlib.sha256(material).hexdigest()
    if evidence_path is not None:
        path=Path(evidence_path);root=path.parent
        if (root.parent!=Path('/var/tmp') or not re.fullmatch(r'dw-engine-[a-f0-9]{16}',root.name)
                or path.name not in ('firewall-before.private.json','firewall-after.private.json')
                or root.is_symlink() or root.stat().st_uid!=os.getuid()
                or root.stat().st_mode & 0o777 != 0o700):
            raise ValueError('invalid-private-firewall-evidence-path')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as output:json.dump(captured,output)
    return result


def production_snapshot(*, firewall_evidence=None):
    prefix = ['docker', '--host', 'unix:///var/run/docker.sock']
    ids = run(*prefix, 'ps', '-aq', '--no-trunc').decode().split()
    items = json.loads(run(*prefix, 'inspect', *ids)) if ids else []
    return {'daemonId':run(*prefix,'info','--format','{{.ID}}').decode().strip(),
            'images':sorted(set(run(*prefix,'images','-aq','--no-trunc').decode().split())),
            'containers': sorted([{'id': x['Id'], 'startedAt': x['State']['StartedAt'],
              'status': x['State']['Status'], 'restartCount': x['RestartCount']} for x in items], key=lambda x:x['id']),
            'networks': sorted(run(*prefix, 'network', 'ls', '-q', '--no-trunc').decode().split()),
            'volumes': sorted(run(*prefix, 'volume', 'ls', '-q').decode().split()),
            'routes': run('ip', '-json', 'route', 'show').decode(),
            'ipForward': Path('/proc/sys/net/ipv4/ip_forward').read_text(),
            'netns': os.readlink('/proc/self/ns/net'), 'mountns': os.readlink('/proc/self/ns/mnt'), 'firewallDigest':firewall_digest(evidence_path=firewall_evidence)}


def cgroup_empty(group):
    if not group.exists():
        return True
    try:
        events=dict(line.split() for line in (group/'cgroup.events').read_text().splitlines())
        return events.get('populated')=='0'
    except FileNotFoundError:
        return not group.exists()


def probe(workload=None, *, storage_driver="vfs"):
    if workload is not None and not callable(workload):
        raise ValueError('trusted-diagnostic-callback-required')
    if os.getuid() != 0:
        raise ValueError('root-required-for-bounded-namespace-probe')
    if workload is not None:
        available=next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                       if line.startswith('MemAvailable:'))
        if available<1024*1024:
            raise ValueError('insufficient-host-memory-headroom')
    root = Path('/var/tmp')/('dw-engine-' + uuid.uuid4().hex[:16])
    root.mkdir(mode=0o700)
    unit = root.name + '.service'
    cfg = configuration(root, unit, storage_driver=storage_driver)
    path = root/'daemon.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
    containerd_config=root/'containerd.toml'
    containerd_config.write_text('version = 2\nroot = '+json.dumps(str(root/'containerd-data'))+
        '\nstate = '+json.dumps(str(root/'containerd-state'))+
        '\ndisabled_plugins = ["io.containerd.grpc.v1.cri", "io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]\n'+
        '[grpc]\naddress = '+json.dumps(str(root/'containerd.sock'))+'\n')
    containerd_config.chmod(0o600)
    supervisor=root/'supervisor.py'
    supervisor.write_text("""import pathlib,signal,subprocess,sys,time,json
root=pathlib.Path(sys.argv[1]);children=[]
def interrupted(*args):raise SystemExit(143)
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
try:
 unit=root.name+'.service';group=pathlib.Path('/sys/fs/cgroup/system.slice')/unit
 expected='0::/system.slice/'+unit+'/supervisor'
 if pathlib.Path('/proc/self/cgroup').read_text().strip()!=expected:raise RuntimeError('unexpected-private-cgroup')
 if (group/'cgroup.procs').read_text().strip():raise RuntimeError('private-cgroup-parent-not-empty')
 if (group/'memory.swap.max').read_text().strip()!='0':raise RuntimeError('private-parent-swap-not-capped')
 if not {'cpu','memory','pids'}<=set((group/'cgroup.controllers').read_text().split()):raise RuntimeError('private-controllers-unavailable')
 preflight={'processCgroup':expected,'parentSubtreeBefore':(group/'cgroup.subtree_control').read_text(),'swapFileBefore':(group/'supervisor/memory.swap.max').exists()}
 (group/'cgroup.subtree_control').write_text('+cpu +memory +pids')
 if not (group/'supervisor/memory.swap.max').is_file():raise RuntimeError('private-swap-controller-not-enabled')
 preflight.update(parentSubtreeAfter=(group/'cgroup.subtree_control').read_text(),swapFileAfter=True,parentSwapMax=(group/'memory.swap.max').read_text())
 evidence=root/'cgroup-preflight.private.json';evidence.write_text(json.dumps(preflight));evidence.chmod(0o600)
 c=subprocess.Popen(['containerd','--config',str(root/'containerd.toml')]);children.append(c)
 deadline=time.monotonic()+20
 while not (root/'containerd.sock').exists():
  if c.poll() is not None or time.monotonic()>deadline:raise RuntimeError('private-containerd-not-ready')
  time.sleep(.1)
 d=subprocess.Popen(['dockerd','--config-file='+str(root/'daemon.json')]);children.append(d)
 raise SystemExit(d.wait())
finally:
 for child in reversed(children):
  if child.poll() is None:child.terminate()
 for child in reversed(children):
  try:child.wait(timeout=15)
  except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
""")
    supervisor.chmod(0o600)
    before = production_snapshot(firewall_evidence=root/'firewall-before.private.json')
    result = {'kind': 'shared-host-isolated-daemon-startup', 'root':str(root), 'unit':unit,
              'independentMachine':False,'productionReady':False,'before':before,'config':cfg,
              'completed':False,'startupReady':False,'stopped':False,'unitCreationOutcomeUnknown':False,
              'workloadRequested':workload is not None}
    started = False
    try:
        if run('systemctl','show',unit,'--property=LoadState','--value').strip() != b'not-found':
            raise ValueError('transient-unit-already-exists')
        run('dockerd', '--validate', '--config-file='+str(path))
        # Limits cover the supervisor, daemon, private containerd and any
        # explicitly selected diagnostic callback workload.
        memory='768M' if workload is not None else '512M'
        tasks='384' if workload is not None else '256'
        lifetime='600' if workload is not None else '120'
        result['unitCreationOutcomeUnknown']=True
        run('systemd-run', '--unit='+unit, '--collect', '--service-type=exec',
            '--property=MemoryMax='+memory, '--property=MemorySwapMax=0', '--property=CPUQuota=50%', '--property=TasksMax='+tasks,
            '--property=Delegate=yes', '--property=DelegateSubgroup=supervisor',
            '--property=KillMode=control-group', '--property=RuntimeMaxSec='+lifetime,
            '--property=TimeoutStopSec=30', '--property=SendSIGKILL=yes', '--property=StandardOutput=append:'+str(root/'daemon.log'),
            '--property=StandardError=append:'+str(root/'daemon.log'),
            'unshare','--mount','--net','--propagation','private','--',
            'sh','-c','ip link set lo up && exec python3 "$1" "$2"','sh',str(supervisor),str(root))
        started=True
        result['unitCreationOutcomeUnknown']=False
        prefix = ['docker','--host','unix://'+str(root/'docker.sock')]
        deadline = time.monotonic()+60
        info = None
        while time.monotonic()<deadline:
            value = subprocess.run([*prefix,'info','--format','{{json .}}'],capture_output=True,timeout=5)
            if value.returncode==0:
                info=json.loads(value.stdout);break
            time.sleep(1)
        if (info is None or info['DockerRootDir'] != str(root/'data') or info['Driver'] != storage_driver
                or info['ID']==before['daemonId']):
            raise ValueError('isolated-daemon-not-ready')
        supervisor_pid=int(run('systemctl','show',unit,'--property=MainPID','--value'))
        pid=int((root/'daemon.pid').read_text())
        if ('--config-file='+str(path)).encode() not in Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0'):
            raise ValueError('daemon-pid-ownership-mismatch')
        netns=os.readlink('/proc/'+str(pid)+'/ns/net');mountns=os.readlink('/proc/'+str(pid)+'/ns/mnt')
        limits=run('systemctl','show',unit,'--property=MemoryMax','--property=TasksMax','--property=ControlGroup').decode()
        if netns==before['netns'] or mountns==before['mountns'] or ('MemoryMax='+str(768*1024*1024 if workload is not None else 512*1024*1024)) not in limits:
            raise ValueError('namespace-or-resource-boundary-mismatch')
        if run(*prefix,'ps','-aq').strip() or run(*prefix,'images','-aq').strip():
            raise ValueError('isolated-daemon-not-empty')
        children=set()
        for task in Path('/proc/'+str(supervisor_pid)+'/task').iterdir():
            try:
                children.update((task/'children').read_text().split())
            except FileNotFoundError:
                continue  # Thread exited; remaining children still must prove ownership.
        managed=[]
        for child in children:
            argv=Path('/proc/'+child+'/cmdline').read_bytes().split(b'\0')
            if argv and Path(os.fsdecode(argv[0])).name=='containerd':
                if str(containerd_config).encode() not in argv:
                    raise ValueError('managed-containerd-config-outside-isolated-root')
                if (os.readlink('/proc/'+child+'/ns/net')!=netns or
                        os.readlink('/proc/'+child+'/ns/mnt')!=mountns):
                    raise ValueError('managed-containerd-namespace-mismatch')
                managed.append([os.fsdecode(a) for a in argv if a])
        if len(managed)!=1:
            raise ValueError('isolated-managed-containerd-not-proven')
        result.update(startupReady=True,daemonId=info['ID'],pid=pid,netns=netns,mountns=mountns,limits=limits,
                      managedContainerd=managed,cgroupPreflight=json.loads((root/'cgroup-preflight.private.json').read_text()),
                      daemonSwapLimit=info.get('SwapLimit'))
        if workload is not None:
            result['workload']=workload(root,info)
            if type(result['workload']) is not dict or result['workload'].get('success') is not True:
                raise ValueError('diagnostic-workload-or-cleanup-failed')
    except Exception as error:
        result['failureType']=type(error).__name__
        if isinstance(error,ValueError):result['failureReason']=str(error)
    finally:
        if started:
            try:
                stopped=subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=45)
                status=subprocess.run(['systemctl','show',unit,'--property=LoadState','--property=ActiveState',
                    '--property=MainPID'],capture_output=True,timeout=10)
                state=dict(line.split('=',1) for line in status.stdout.decode().splitlines() if '=' in line)
                cgroup=Path('/sys/fs/cgroup/system.slice')/unit
                no_processes=cgroup_empty(cgroup)
                result['stopState']=state
                result['stopped']=(stopped.returncode==0 and no_processes and
                    (state.get('LoadState')=='not-found' or
                     state.get('ActiveState') in ('inactive','failed') and state.get('MainPID')=='0'))
            except Exception as error:
                result['cleanupFailureType']=type(error).__name__
        try:
            result['after']=production_snapshot(firewall_evidence=root/'firewall-after.private.json')
            result['productionSnapshotUnchanged']=result['after']==before
        except Exception as error:
            result['afterSnapshotFailureType']=type(error).__name__
            result['productionSnapshotUnchanged']=False
        result['completed']=(result['startupReady'] and result['stopped']
                             and result['productionSnapshotUnchanged'] and not result['unitCreationOutcomeUnknown']
                             and (workload is None or result.get('workload',{}).get('success') is True))
        report=root/'report.private.json';report.write_text(json.dumps(result,indent=2));report.chmod(0o600)
    return result


if __name__=='__main__':
    if sys.platform!='linux':sys.exit('linux-required')
    print(json.dumps(probe()))
