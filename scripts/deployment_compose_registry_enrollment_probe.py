"""Genuine anonymous registry pull into an owned private containerd namespace.

The ctr --local resolver uses the caller's network; daemon network/firewall
settings stay isolated. No synthetic RepoDigests or credential registration.
"""
from copy import deepcopy
import json
import hashlib
import urllib.request
import os
from pathlib import Path
import re
import stat
import subprocess

from deployment_compose_namespaced_runtime_probe import PrivateDaemon, ensure_capacity
from deployment_compose_log_probe import IMAGE
from deployment_prepare import registry_reference

REFERENCE = 'registry-1.docker.io/library/' + IMAGE
LIMIT = 8 * 1024 * 1024
REGISTRIES = {
    'dockerhub': ('registry-1.docker.io/library/python', 'https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fpython%3Apull', 'https://registry-1.docker.io/v2/library/python/manifests/'),
    'ecr-public': ('public.ecr.aws/docker/library/python', 'https://public.ecr.aws/token/?service=public.ecr.aws&scope=repository%3Adocker%2Flibrary%2Fpython%3Apull', 'https://public.ecr.aws/v2/docker/library/python/manifests/'),
}

def registry_settings(registry):
    if type(registry) is not str or registry not in REGISTRIES:
        raise ValueError('registry-source-policy-rejected')
    repository,token_url,manifest_url = REGISTRIES[registry]
    return repository+'@'+IMAGE.rsplit('@',1)[1], token_url, manifest_url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('registry-redirect-rejected')


def verify_registry_manifest(*, registry='dockerhub'):
    """Anonymous fixed-origin HTTPS plus content hash; token stays in memory."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    reference, token_url, manifest_base = registry_settings(registry)
    try:
        with opener.open(token_url,timeout=15) as response:
            if response.status != 200 or response.geturl() != token_url:
                raise ValueError()
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError()
        token_value = json.loads(raw)
        token = token_value.get('token') or token_value.get('access_token')
        if type(token) is not str or not 1 <= len(token) <= 32768 or any(ord(c)<33 or ord(c)>126 for c in token):
            raise ValueError()
        digest = IMAGE.rsplit('@',1)[1]
        url = manifest_base + digest
        accept = ','.join(('application/vnd.oci.image.index.v1+json','application/vnd.oci.image.manifest.v1+json',
            'application/vnd.docker.distribution.manifest.list.v2+json','application/vnd.docker.distribution.manifest.v2+json'))
        request = urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'Accept':accept})
        with opener.open(request,timeout=15) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError()
            manifest = response.read(1024*1024+1)
        if len(manifest) > 1024*1024 or 'sha256:'+hashlib.sha256(manifest).hexdigest() != digest:
            raise ValueError()
        return {'registryTLSOriginVerified':True,'registryManifestDigest':digest,'registryPolicy':registry,
                'anonymousTokenLoggedOrSaved':False}
    except Exception:
        raise ValueError('registry-origin-manifest-not-verified') from None


def pull_command(root, namespace, *, registry='dockerhub'):
    if (not isinstance(root, Path) or root.parent != Path('/var/tmp')
            or not re.fullmatch(r'dw-engine-[0-9a-f]{16}', root.name) or namespace != root.name):
        raise ValueError('registry-enrollment-scope-rejected')
    reference, _, _ = registry_settings(registry)
    return ['ctr', '--address', str(root/'containerd.sock'), '--namespace', namespace,
            'images', 'pull', '--local', '--snapshotter', 'overlayfs',
            '--hosts-dir', str(root/'registry-hosts'), '--platform', 'linux/amd64',
            '--skip-metadata', reference]


def verify_enrollment(cached, observed, *, registry='dockerhub'):
    reference, _, _ = registry_settings(registry)
    if (type(cached) is not dict or type(observed) is not dict
            or any(json.dumps(cached.get(k),sort_keys=True) != json.dumps(observed.get(k),sort_keys=True)
                   for k in ('Id','Os','Architecture','Config','RootFS'))
            or cached.get('Os') != 'linux' or cached.get('Architecture') != 'amd64'
            or type(observed.get('RepoDigests')) is not list or reference not in observed['RepoDigests']
            or any(not registry_reference(ref) for ref in observed['RepoDigests'])):
        raise ValueError('live-registry-enrollment-mismatch')
    return deepcopy(observed)


def scope_stopped(fields, *, query_returncode, expected_group, cgroup_empty):
    if (type(fields) is not dict or cgroup_empty is not True
            or fields.get('ControlGroup') not in ('', expected_group)):
        return False
    if fields.get('LoadState') == 'not-found':
        return query_returncode in (0, 1) and fields.get('ActiveState') == 'inactive'
    return (query_returncode == 0 and fields.get('LoadState') == 'loaded'
            and fields.get('ActiveState') in ('inactive', 'failed'))


def registry_capacity_required(private_limit, anon_before, anon_after):
    if (type(private_limit) is not int or private_limit != 768*1024*1024
            or any(type(value) is not int or not 0 <= value <= private_limit for value in (anon_before,anon_after))):
        raise ValueError('registry-private-memory-budget-unverified')
    # Only resident anon is already counted against current available memory.
    # Never credit file/cache/kernel statistics. Reserve controller and host slack.
    return private_limit-min(anon_before,anon_after)+192*1024*1024+256*1024*1024


def enroll_image(root, target, cached, *, registry='dockerhub'):
    if (type(target) is not PrivateDaemon or target.host != 'unix://'+str(root/'docker.sock')
            or root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700
            or root.stat().st_uid != os.getuid()
            or (root/'containerd.sock').is_symlink() or (root/'docker.sock').is_symlink()
            or (root/'daemon.json').is_symlink()):
        raise ValueError('registry-enrollment-scope-rejected')
    command = pull_command(root, root.name, registry=registry)
    reference, _, _ = registry_settings(registry)
    ensure_capacity(root, cached)
    if cached.get('Os') != 'linux' or cached.get('Architecture') != 'amd64' or cached.get('Id') != IMAGE.rsplit('@',1)[1]:
        raise ValueError('registry-enrollment-platform-or-manifest-identity-rejected')
    def check_capacity():
        group=Path('/sys/fs/cgroup/system.slice')/(root.name+'.service')
        limit=int((group/'memory.max').read_text().strip())
        if (group/'memory.swap.max').read_text().strip()!='0':
            raise ValueError('registry-private-memory-budget-unverified')
        def anon():return int(dict(line.split() for line in (group/'memory.stat').read_text().splitlines())['anon'])
        first_anon=anon()
        available = next(int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
        second_anon=anon();required=registry_capacity_required(limit,first_anon,second_anon)
        evidence=root/'registry-memory-admission.private.json'
        evidence.write_text(json.dumps({'privateLimit':limit,'anonBefore':first_anon,'anonAfter':second_anon,
            'availableBytes':available,'requiredBytes':required,'clientLimit':192*1024*1024,'reserve':256*1024*1024}));evidence.chmod(0o600)
        if available < required:
            raise ValueError('registry-client-memory-headroom-insufficient')
    config = json.loads((root/'daemon.json').read_text())
    if (config.get('containerd') != str(root/'containerd.sock')
            or config.get('containerd-namespace') != root.name
            or config.get('data-root') != str(root/'data')
            or not stat.S_ISSOCK((root/'containerd.sock').stat().st_mode)):
        raise ValueError('registry-enrollment-scope-rejected')
    before = json.loads(target.run('image','inspect',cached['Id']))
    if len(before) != 1 or any(json.dumps(before[0].get(k),sort_keys=True) != json.dumps(cached.get(k),sort_keys=True)
                              for k in ('Id','Os','Architecture','Config','RootFS')):
        raise ValueError('registry-enrollment-import-drift')
    origin = verify_registry_manifest(registry=registry)
    (root/'registry-hosts').mkdir(mode=0o700)
    client = root/'registry-client'; client.mkdir(mode=0o700)
    (client/'config.json').write_text('{}')
    env = dict(os.environ, DOCKER_CONFIG=str(client))
    for name in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy',
                 'CONTAINERD_ADDRESS','CONTAINERD_NAMESPACE','CONTAINERD_SNAPSHOTTER'):
        env.pop(name, None)
    log = root/'registry-pull.private.log'
    fd = os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    unit = root.name + '-registry-pull.scope'
    existing = subprocess.run(['systemctl','show',unit,'--property=LoadState','--value'],
        capture_output=True,timeout=10)
    if existing.stdout.strip() != b'not-found':
        os.close(fd)
        raise ValueError('registry-client-scope-already-exists')
    launcher = root/'registry-client-launcher.py'
    launcher.write_text("""import json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);unit=root.name+'-registry-pull.scope'
expected='0::/system.slice/'+unit
if Path('/proc/self/cgroup').read_text().strip()!=expected:raise RuntimeError('registry-client-cgroup-mismatch')
group=Path('/sys/fs/cgroup/system.slice')/unit
values={k:(group/f).read_text().strip() for k,f in {'memoryMax':'memory.max','swapMax':'memory.swap.max','cpuMax':'cpu.max','pidsMax':'pids.max'}.items()}
if values!={'memoryMax':str(192*1024*1024),'swapMax':'0','cpuMax':'25000 100000','pidsMax':'128'}:raise RuntimeError('registry-client-limits-mismatch')
evidence=root/'registry-client-limits.private.json';evidence.write_text(json.dumps(values));evidence.chmod(0o600)
os.execvpe(sys.argv[2],sys.argv[2:],os.environ)
""")
    launcher.chmod(0o600)
    wrapped = ['systemd-run','--system','--scope','--collect','--quiet','--slice=system.slice','--unit='+unit,
        '--property=MemoryMax=192M','--property=MemorySwapMax=0','--property=CPUQuota=25%',
        '--property=CPUQuotaPeriodSec=100ms','--property=TasksMax=128','--property=RuntimeMaxSec=180',
        '/usr/bin/python3','-I','-B',str(launcher),str(root),*command]
    stopped = False
    try:
        with os.fdopen(fd,'wb') as output:
            check_capacity()
            process = subprocess.run(wrapped,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=200)
    finally:
        subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=30)
        state = subprocess.run(['systemctl','show',unit,'--property=LoadState','--property=ActiveState',
            '--property=ControlGroup'],capture_output=True,text=True,timeout=10)
        fields = dict(line.split('=',1) for line in state.stdout.splitlines() if '=' in line)
        group = Path('/sys/fs/cgroup/system.slice')/unit
        empty = not group.exists() or dict(line.split() for line in (group/'cgroup.events').read_text().splitlines()).get('populated') == '0'
        stopped = scope_stopped(fields, query_returncode=state.returncode,
            expected_group='/system.slice/'+unit, cgroup_empty=empty)
        evidence = root/'registry-client-scope.private.json'
        evidence.write_text(json.dumps({'unit':unit,'stopped':stopped,'state':fields}));evidence.chmod(0o600)
    if not stopped:
        raise ValueError('registry-client-scope-not-stopped')
    if process.returncode or log.stat().st_size > LIMIT:
        raise ValueError('genuine-registry-pull-not-verified')
    rows = json.loads(target.run('image','inspect',reference))
    if len(rows) != 1:
        raise ValueError('live-registry-enrollment-mismatch')
    enrolled = verify_enrollment(cached, rows[0], registry=registry)
    raw_evidence = root/'registry-image-evidence.private.json'
    raw_evidence.write_text(json.dumps({'cached':cached,'live':enrolled},indent=2));raw_evidence.chmod(0o600)
    return enrolled, {**origin,'kind':'genuine-private-containerd-registry-enrollment',
        'reference':reference,'anonymousPull':True,'localResolver':True,'clientScopeStopped':stopped,
        'clientLimitsVerified':json.loads((root/'registry-client-limits.private.json').read_text()) ==
            {'memoryMax':str(192*1024*1024),'swapMax':'0','cpuMax':'25000 100000','pidsMax':'128'},
        'imageIdConfigAndRootFSUnchanged':True,'liveRepoDigestVerified':True,
        'hostNetworkConfigurationChanged':False,'productionDockerWrites':0,
        'buildProvenanceVerified':False,'productionReady':False}


def probe_registry(root, info, *, registry='dockerhub'):
    """No applications: enroll one cached image, verify it live, remove known names."""
    from deployment_compose_namespaced_transition_probe import source_image
    from deployment_compose_namespaced_runtime_probe import transfer_image
    target = PrivateDaemon(root, info)
    reference, _, _ = registry_settings(registry)
    result = {'kind':'private-registry-enrollment-diagnostic','success':False,
        'unknownWriteResult':False,'productionReady':False,'applicationsCreated':0}
    def write(fn):
        if result['unknownWriteResult']:
            raise ValueError('registry-write-blocked-after-unknown')
        result['unknownWriteResult'] = True
        value = fn()
        result['unknownWriteResult'] = False
        return value
    try:
        fresh = json.loads(target.run('info','--format','{{json .}}'))
        if (fresh.get('ID') != info['ID'] or fresh.get('DockerRootDir') != str(root/'data')
                or target.run('ps','-aq').strip() or target.run('images','-aq').strip()):
            raise ValueError('registry-daemon-not-private-and-empty')
        image = source_image(IMAGE); ensure_capacity(root,image)
        write(lambda:transfer_image(image['Id'],target))
        enrolled,evidence = write(lambda:enroll_image(root,target,image,registry=registry))
        result['enrollment'] = evidence
        if evidence['clientLimitsVerified'] is not True or evidence['clientScopeStopped'] is not True:
            raise ValueError('registry-client-boundary-unverified')
        write(lambda:target.run('image','rm',reference))
        remaining = set(target.run('images','-aq','--no-trunc').split())
        if remaining - {image['Id']}:
            raise ValueError('unexpected-private-image-after-enrollment')
        if remaining:
            write(lambda:target.run('image','rm',image['Id']))
        if target.run('images','-aq').strip() or target.run('ps','-aq').strip():
            raise ValueError('registry-private-image-cleanup-incomplete')
        result['cleanupComplete'] = True
        result['success'] = True
    except Exception as error:
        result['failureType'] = type(error).__name__
        if type(error) is ValueError: result['failureReason'] = str(error)
    return result
