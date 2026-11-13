"""Opt-in Docker Desktop rehearsal with a diagnostic process from the blog image.

Only the desktop-linux Unix socket is accepted. Containers have no published
ports and use a fresh private bridge. Cleanup uses only IDs created here.
The diagnostic maps the fixed production name to a fresh local name and uses
Engine's negotiated API version. It does not exercise production approval.
"""
import json


def run_diagnostic():
    import hashlib
    from pathlib import Path
    import re
    import secrets
    import subprocess
    import sys
    import time
    import tempfile
    repo = Path(__file__).resolve().parents[2]
    sys.path[:0] = [str(repo / 'scripts'), str(repo / 'packs/deployment/scripts'), str(repo / 'packs/release/scripts')]
    from deployment_compose_reader_host import _UnixDocker
    from deployment_compose_host_snapshot_v3_host import _frontend_projection
    from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
    from deployment_compose_production_scope_v1_host import acquire_scope, provision_scope
    from deployment_compose_retained_phase_v1_host import _endpoint_config

    def docker(*args):
        return subprocess.run(
            ['docker', '--context', 'desktop-linux', *args],
            check=True, capture_output=True, text=True, timeout=25,
        ).stdout.strip()

    sock = Path.home() / '.docker/run/docker.sock'
    endpoint = docker('context', 'inspect', 'desktop-linux', '--format', '{{.Endpoints.docker.Host}}')
    if endpoint != 'unix://' + str(sock) or sock.is_symlink() or not sock.is_socket():
        raise RuntimeError('The local Docker Desktop Unix socket is required')
    if docker('info', '--format', '{{.OperatingSystem}}') != 'Docker Desktop':
        raise RuntimeError('The local Docker Desktop Engine is required')
    version = docker('version', '--format', '{{.Server.Version}} {{.Server.APIVersion}}').split()
    assert re.fullmatch('1\\.[0-9]+', version[1])
    daemon_id = docker('info', '--format', '{{.ID}}')
    image = docker('image', 'inspect', '--format', '{{.Id}}', 'luohao-blog-frontend-hotfix:26aae695e02cbbf8584039f75b8387fe67a90e57')
    assert re.fullmatch('sha256:[0-9a-f]{64}', image)

    def api(method, path, body=b'', expected=(200,)):
        c = _UnixDocker(str(sock), 15)
        try:
            c.request(method, '/v' + version[1] + path.removeprefix('/v1.45'), body=body, headers={'Content-Type': 'application/json'})
            r = c.getresponse()
            raw = r.read(1048576)
            if r.status not in expected:
                raise RuntimeError(f"{method} {path.split('?')[0]} returned {r.status}")
            return json.loads(raw) if raw else None
        finally:
            c.close()

    def inventory():
        return [sorted(docker(*args).splitlines()) for args in (('ps', '-aq', '--no-trunc'), ('network', 'ls', '-q', '--no-trunc'), ('volume', 'ls', '-q'), ('image', 'ls', '-aq', '--no-trunc'))]
    node = "require('node:http').createServer((q,r)=>{r.statusCode=process.env.DW_HEALTH_FAIL==='1'?503:200;r.end(require('node:os').hostname())}).listen(3000,'0.0.0.0')"
    probe = "const d=require('node:dns').promises; (async()=>{const a=await d.lookup('frontend',{all:true});const r=await fetch('http://frontend:3000/health');console.log(JSON.stringify({ips:a.map(x=>x.address),status:r.status,owner:await r.text()}))})().catch(()=>process.exit(1));"

    def run(scenario):
        fail = scenario == 'failed-http-probe'
        nonce = secrets.token_hex(32)
        prefix = 'dw-local-cutover-' + nonce[:16]
        final = prefix + '-front'
        owned = []
        network = None
        before = inventory()
        try:
            network_id = docker('network', 'create', '--internal', '--label', 'dev-workflow.cutover=' + nonce, prefix)
            if not re.fullmatch('[0-9a-f]{64}', network_id):
                raise RuntimeError('Missing definitive local network receipt')
            network = network_id
            base = {
                'Image': image, 'Entrypoint': ['node'], 'Cmd': ['-e', node],
                'Labels': {'dev-workflow.cutover': nonce},
                'HostConfig': {'NetworkMode': prefix, 'RestartPolicy': {'Name': 'unless-stopped'}},
                'NetworkingConfig': {
                    'EndpointsConfig': {prefix: {'NetworkID': network, 'Aliases': ['frontend']}}
                },
            }

            def encode(value):
                return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

            def create(name, body):
                if not (name.startswith(prefix) or name.startswith('dwc-' + nonce[:24])):
                    raise RuntimeError('Container name is outside this rehearsal')
                response = api('POST', '/v1.45/containers/create?name=' + name, encode(body), expected=(201,))
                cid = response['Id']
                if not re.fullmatch('[0-9a-f]{64}', cid):
                    raise RuntimeError('Missing definitive local container receipt')
                owned.append(cid)
                return cid
            old = create(final, base)
            api('POST', '/v1.45/containers/' + old + '/start', expected=(204,))
            probe_id = create(prefix + '-probe', {'Image': image, 'Entrypoint': ['node'], 'Cmd': ['-e', 'setInterval(()=>{},1000)'], 'Labels': {'dev-workflow.cutover': nonce}, 'HostConfig': {'NetworkMode': prefix}})
            api('POST', '/v1.45/containers/' + probe_id + '/start', expected=(204,))

            def row(cid):
                return api('GET', '/v1.45/containers/' + cid + '/json')

            def verify(cid, status):
                expected = row(cid)['NetworkSettings']['Networks'][prefix]['IPAddress']
                deadline = time.monotonic() + 18
                while time.monotonic() < deadline:
                    try:
                        p = json.loads(docker('exec', probe_id, 'node', '-e', probe))
                    except subprocess.CalledProcessError:
                        time.sleep(0.2)
                        continue
                    if p == {'ips': [expected], 'status': status, 'owner': cid[:12]}:
                        return p
                    time.sleep(0.2)
                raise RuntimeError('local network probe did not resolve expected single endpoint and HTTP status')
            verify(old, 200)
            candidate_body = dict(base, Env=['DW_HEALTH_FAIL=' + ('1' if fail else '0')])
            review = {'identity': {'containerId': old, 'project': 'luohao-blog-prod', 'service': 'frontend', 'containerName': 'blog-frontend', 'imageId': image}, 'selectedServices': ['frontend'], 'protectedContainerIds': [probe_id], 'sameImage': True, 'authorityGranted': False, 'executionAvailable': False, 'runtimePermit': False, 'productionReady': False, 'bodyDigest': hashlib.sha256(encode(candidate_body)).hexdigest()}
            plan = prepare_retained_frontend_cutover({'privateBody': candidate_body, 'publicReview': review}, operation_nonce=nonce)
            with tempfile.TemporaryDirectory(prefix='dw-scope-cutover-') as scope_dir:
                registration = provision_scope(Path(scope_dir).resolve(), host_id='docker-desktop-local', project=prefix, daemon_id=daemon_id)
                with acquire_scope(registration, plan.digest) as lease:
                    lease.check()
                    candidate = create(plan.candidate_name, json.loads(plan.create().body))
                    assert not row(candidate)['State']['Running']
                    verify(old, 200)
                    old_before_stop = row(old)

                    def network_projection():
                        definition = json.loads(docker('network', 'inspect', network))[0]
                        return _frontend_projection({
                            'resources': {'containers': [old, candidate, probe_id],
                                          'networkDefinitions': {network: definition}},
                            'containers': [{'id': cid} for cid in (old, candidate, probe_id)],
                            'endpointDigest': daemon_id,
                            'network': {},
                        }, old, (probe_id,), candidate)

                    def perform(op):
                        path = op.path.replace('name=blog-frontend', 'name=' + final)
                        assert re.search('/containers/(?:' + old + '|' + candidate + ')/', path)
                        lease.check()
                        api('POST', path, op.body, expected=(204,))
                    switch_prefix = {'stopped-after-original-stop': 1, 'stopped-before-start': 3}.get(scenario, 4)
                    before_stop_projection = network_projection() if switch_prefix == 1 else None
                    for op in plan.switch(candidate)[:switch_prefix]:
                        perform(op)
                    stopped = row(old)
                    expected_original_name = final if switch_prefix == 1 else plan.retained_name
                    assert stopped['Name'] == '/' + expected_original_name and not stopped['State']['Running']
                    if switch_prefix == 1:
                        assert stopped['State']['Status'] == 'exited' and stopped['State']['Pid'] == 0
                        assert stopped['State']['StartedAt'] == old_before_stop['State']['StartedAt']
                        assert all(stopped[key] == old_before_stop[key]
                                   for key in ('Image', 'Config', 'HostConfig', 'Mounts', 'RestartCount'))
                        assert _endpoint_config(stopped) == _endpoint_config(old_before_stop)
                        assert network_projection() == before_stop_projection
                        assert row(candidate)['State']['Status'] == 'created'
                    running = row(candidate)['State']['Running']
                    assert running == (switch_prefix == 4)
                    after = verify(candidate, 503 if fail else 200) if running else None
                    restoration = plan.restore(candidate, switch_prefix=switch_prefix, candidate_running=running)
                    if switch_prefix == 1:
                        assert tuple(op.phase for op in restoration) == ('start-original',)
                    for op in restoration:
                        perform(op)
                    verify(old, 200)
                    assert row(old)['Name'] == '/' + final and (not row(candidate)['State']['Running'])
                    result = {'scenario': scenario, 'switchHTTP': after['status'] if after else None, 'closedSwitchPrefix': switch_prefix, 'originalRetained': True, 'restoredHTTP': 200, 'singleAliasEndpointVerified': True}
                    if switch_prefix == 1:
                        result['changedOriginalNetworkFields'] = sorted(
                            key for key in stopped['NetworkSettings']
                            if stopped['NetworkSettings'][key] != old_before_stop['NetworkSettings'].get(key)
                        )
                        result['restorationOperations'] = [op.phase for op in restoration]
                        result['protectedNetworkMembershipUnchanged'] = True
                    lease.complete(hashlib.sha256(encode(result)).hexdigest())
        finally:
            for cid in reversed(owned):
                docker('rm', '-f', cid)
            if network:
                docker('network', 'rm', network)
            assert inventory() == before, 'local inventory differs after scoped cleanup'
        result['cleanupVerified'] = True
        return result
    scenarios = ('healthy-switch', 'failed-http-probe', 'stopped-after-original-stop', 'stopped-before-start')
    return {'engineVersion': version[0], 'engineApi': version[1], 'imageId': image, 'usesRealFrontendImage': True, 'diagnosticProcess': True, 'scopeLeaseCheckedBeforeWrites': True, 'scenarios': [run(scenario) for scenario in scenarios]}
if __name__ == '__main__':
    print(json.dumps(run_diagnostic()), flush=True)
