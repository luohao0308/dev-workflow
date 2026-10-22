#!/usr/bin/env python3
"""Independent Linux-only executor fixture; never install into a consumer.

Bootstrap and teardown own the disposable environment. Changes between the
initial and final observations are performed by the product DockerExecutor.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import ssl
import sys
import threading
import time
import traceback
from urllib.parse import parse_qs, urlsplit

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(1, str(Path(__file__).resolve().parent))
import deployment_host as host
import deployment_authorize as sdk
import deployment_execute as execution
import deployment_runtime as runtime
import deployment_spec as specs
import deployment_verify as verification
from p1_runtime_live import run, save, UnixDocker, oidc, expect_rejected
from release_github import GitHubClient
from release_host import bundle_digest
from release_host_runner import bootstrap


class FixtureDocker(UnixDocker):
    def connect(self):
        super().connect()
        # Docker stop(t=10) can legitimately need slightly more than 10 seconds.
        self.sock.settimeout(45)


def docker(method, path, value=None):
    connection = FixtureDocker('localhost')
    try:
        body = None if value is None else json.dumps(value).encode()
        connection.request(method, path, body=body, headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(runtime.MAX_RESPONSE + 1)
        if len(raw) > runtime.MAX_RESPONSE:
            raise ValueError('Fixture Docker response too large')
        return response.status, raw
    finally:
        connection.close()


def bridge(directory, project, allowed_images):
    def openssl(*args):
        run('openssl', *args, cwd=directory)
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
            '-days', '1', '-subj', '/CN=P14 isolated CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    for name in ('server', 'reader', 'writer'):
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr',
                '-subj', '/CN=' + name)
        (directory / (name + '.ext')).write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n'
                'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='
                + ('serverAuth' if name == 'server' else 'clientAuth') + '\n')
        openssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
                '-days', '1', '-out', name + '.pem', '-extfile', name + '.ext')
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def handle_api(self):
            method, path = self.command, self.path
            parsed = urlsplit(path)
            principal = dict(item for group in self.connection.getpeercert()['subject'] for item in group)['commonName']
            allowed = False
            body = None
            if method == 'GET':
                allowed = (path == '/v1.45/info' or path.startswith('/v1.45/containers/json?')
                    or re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/json', path)
                    or re.fullmatch(r'/v1\.45/images/sha256:[0-9a-f]{64}/json', path)
                    or re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/archive\?path=%2Fetc%2F(?:hosts|hostname|resolv\.conf)', path))
            elif principal == 'writer':
                if method == 'POST' and parsed.path == '/v1.45/containers/create':
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 65536:
                        self.send_error(403)
                        return
                    body = json.loads(self.rfile.read(length))
                    labels = body.get('Labels', {})
                    hostconfig = body.get('HostConfig', {})
                    allowed = (labels.get('com.docker.compose.project') == project
                        and labels.get('com.docker.compose.service') == 'web'
                        and body.get('Image') in allowed_images
                        and hostconfig.get('ReadonlyRootfs') is True
                        and hostconfig.get('CapDrop') == ['ALL']
                        and not any(hostconfig.get(field) for field in ('Binds', 'Mounts', 'Devices', 'DeviceRequests', 'DeviceCgroupRules', 'Privileged'))
                        and set(parse_qs(parsed.query)) == {'name'})
                else:
                    match = re.fullmatch(r'/v1\.45/containers/([0-9a-f]{64})(?:/(stop|start))?', parsed.path)
                    if match:
                        status, raw = docker('GET', '/v1.45/containers/' + match[1] + '/json')
                        inspected = json.loads(raw) if status == 200 else {}
                        labels = inspected.get('Config', {}).get('Labels', {})
                        scoped = (labels.get('com.docker.compose.project') == project
                                  and labels.get('com.docker.compose.service') == 'web')
                        query = parse_qs(parsed.query)
                        allowed = scoped and ((method == 'POST' and match[2] == 'stop' and query == {'t': ['10']})
                            or (method == 'POST' and match[2] == 'start' and not query)
                            or (method == 'DELETE' and match[2] is None and query == {'force': ['false'], 'v': ['false']}))
            if not allowed:
                self.send_error(403)
                return
            status, raw = docker(method, path, body)
            calls.append(dict(method=method, path=path, principal=principal, status=status))
            self.send_response(status)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        do_GET = do_POST = do_DELETE = handle_api
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory / 'server.pem'), str(directory / 'server.key'))
    context.load_verify_locations(str(directory / 'ca.pem'))
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    def certificate_hash(name):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory / (name + '.pem')).read_text())).hexdigest()
    return server, certificate_hash, calls


class TestApproval:
    """Explicit synthetic authority, never represented as GitHub approval."""
    def __init__(self):
        self.spent = set()
    def validate(self, request):
        return sdk.Grant('fixture:executor', request.digest(), request.expires_at, 1)
    def consume(self, grant, request, *, before_consume=None):
        if request.digest() in self.spent:
            raise ValueError('Fixture grant spent')
        if before_consume:
            before_consume()
        self.spent.add(request.digest())
        return sdk.Receipt(grant.grant_id, request.digest(), 1, datetime.now(timezone.utc).isoformat())
    def guard(self, request):
        if request.digest() not in self.spent:
            raise ValueError('Fixture grant not spent')


def main(*, exercise=None):
    if sys.platform != 'linux' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Independent Linux Actions fixture only')
    smoke = os.environ.get('P14_MODE') == 'smoke'
    negative = os.environ.get('P14_NEGATIVE') == 'business-failure'
    if negative and not smoke:
        raise SystemExit('Negative exercise requires explicit synthetic authority')
    directory = Path(os.environ['RUNNER_TEMP']) / 'p14-isolated'
    directory.mkdir(mode=0o700)
    output = ROOT / 'p14-results'
    output.mkdir()
    metadata = json.loads((ROOT / 'p1-fixture.json').read_text())
    candidate = Path('/tmp/dev-workflow-p14-target')
    run('git', 'clone', '--quiet', 'https://github.com/' + metadata['targetRepository'] + '.git', str(candidate))
    run('git', '-C', str(candidate), 'checkout', '--quiet', metadata['newSha'])
    bootstrap(candidate)
    adopted = json.loads((candidate / '.dev-workflow/manifest.json').read_text())
    adopted['installedPacks'] = ['deployment']
    save(candidate / '.dev-workflow/manifest.json', adopted)
    project = 'p14-' + os.environ['GITHUB_RUN_ID']
    catalog, definitions, images = [], [], {}
    server = None
    try:
        for component, version, sha in (('web', '1.0.0', metadata['oldSha']),
                                        ('web', '2.0.0', metadata['newSha']),
                                        ('api', '1.0.0', metadata['oldSha'])):
            context = directory / (component + version)
            context.mkdir()
            for filename in ('Dockerfile', 'release.txt', 'server.py'):
                raw = subprocess.run(['git', '-C', str(candidate), 'show', sha + ':fixtures/p1-runtime/' + filename],
                                     check=True, capture_output=True).stdout
                (context / filename).write_bytes(raw)
            image_id = run('docker', 'build', '--quiet', '--label', 'fixture-component=' + component, str(context))
            inspected = json.loads(run('docker', 'image', 'inspect', image_id))[0]
            source = inspected.get('Config', {})
            save(output / 'image-policy.json', dict(volumesPresent=bool(source.get('Volumes')),
                onBuildPresent=bool(source.get('OnBuild')), healthcheckPresent=bool(source.get('Healthcheck')),
                stopSignalPresent=bool(source.get('StopSignal')), argsEscaped=source.get('ArgsEscaped')))
            definition = specs.ContainerSpec.from_image(component, inspected, port_bindings=(
                {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18080'}]} if component == 'web' else None))
            definitions.append(definition)
            images[(component, version)] = (image_id, definition)
            catalog.append(dict(component=component, imageId=image_id, repository=metadata['targetRepository'],
                sourceSha=sha, version=version, os=inspected['Os'], architecture=inspected['Architecture'],
                artifact=dict(kind='local-build', imageId=image_id, buildSourceSha=sha), migration=dict(mode='none', version=None)))
        for component in ('web', 'api'):
            body = images[(component, '1.0.0')][1].to_create(project, '0' * 64)
            status, raw = docker('POST', '/v1.45/containers/create?name=' + project + '-' + component, body)
            assert status == 201
            container_id = json.loads(raw)['Id']
            assert docker('POST', '/v1.45/containers/' + container_id + '/start')[0] == 204
        server, cert_hash, calls = bridge(directory, project, {image for (component, _), (image, _) in images.items() if component == 'web'})
        policy = runtime.RuntimePolicy(endpoint='https://localhost:' + str(server.server_port),
            server_certificate_sha256=cert_hash('server'), daemon_id=run('docker', 'info', '--format', '{{.ID}}'),
            repository=metadata['targetRepository'], environment='staging', target='p1-isolated', production=False,
            project=project, components=('web', 'api'), catalog_json=json.dumps(dict(schemaVersion=1, images=catalog)),
            specifications_json=specs.specifications_json(tuple(definitions)), maximum_age=3000)
        collector = runtime.TrustedDockerCollector(policy, runtime.DockerTLSClient(policy,
            ca_file=directory / 'ca.pem', cert_file=directory / 'reader.pem', key_file=directory / 'reader.key'))
        profiles = []
        for version in ('1.0.0', '2.0.0'):
            image, spec = images[('web', version)]
            expected_version = 'v1' if version == '1.0.0' else 'v2'
            def probe(name, expectations):
                return dict(id=name, path='/' + name, status=200, jsonExpectations=expectations,
                    attempts=5, retryDelay=0.2, timeout=2, maxBodyBytes=4096)
            profiles.append(dict(component='web', imageId=image, specHash=spec.configuration_digest(),
                containerPort='8080/tcp', hostIp='127.0.0.1', hostPort='18080', address='127.0.0.1',
                scheme='http', tlsHostname=None, serverCertificateSha256=None,
                health=[probe('ready', {'/ready': True, '/version': expected_version})],
                smoke=[probe('business', {'/value': 42, '/version': expected_version})]))
        if negative:
            profiles[1]['smoke'][0]['path'] = '/wrong'
        probe_policy = verification.ProbePolicy(policy.identity_hash(), json.dumps(dict(
            schemaVersion=1, kind='deployment-probe-policy', profiles=profiles)))
        verifier = verification.TrustedProbeVerifier(probe_policy, policy)
        epolicy = execution.ExecutionPolicy(policy, cert_hash('writer'),
            verification_policy_hash=probe_policy.identity_hash())
        client = execution.DockerMutationClient(epolicy, ca_file=directory / 'ca.pem',
                                               cert_file=directory / 'writer.pem', key_file=directory / 'writer.key', timeout=30)
        executor = execution.DockerExecutor(epolicy, client, collector, verifier=verifier)
        old = collector.collect()
        save(output / 'initial-observation.json', old.to_dict())
        assert old.to_dict()['complete'] is True, old.to_dict()['incomplete']
        if exercise is not None:
            # A trusted sibling fixture may reuse provisioning, never candidate code.
            return exercise(dict(directory=directory, output=output, metadata=metadata, candidate=candidate,
                project=project, images=images, catalog=catalog, policy=policy, collector=collector,
                executor=executor, server=server, certificate_hash=cert_hash))
        # Independent server-side restrictions, not just client method guards.
        readonly_policy = replace(epolicy, writer_certificate_sha256=cert_hash('reader'))
        readonly_writer = execution.DockerMutationClient(readonly_policy, ca_file=directory / 'ca.pem',
            cert_file=directory / 'reader.pem', key_file=directory / 'reader.key')
        body = images[('web', '2.0.0')][1].to_create(project, 'f' * 64)
        expect_rejected(lambda: readonly_writer.create('dwf-' + 'f' * 64, body, before_send=lambda: None))
        api_id = next(item['containerId'] for item in old.to_dict()['instances'] if item['component'] == 'api')
        expect_rejected(lambda: client.stop(api_id, before_send=lambda: None))
        bad_policy = replace(epolicy, runtime_policy=replace(policy, server_certificate_sha256='0' * 64))
        bad_pin = execution.DockerMutationClient(bad_policy, ca_file=directory / 'ca.pem',
            cert_file=directory / 'writer.pem', key_file=directory / 'writer.key')
        expect_rejected(lambda: bad_pin.create('dwf-' + 'f' * 64, body, before_send=lambda: None))
        collector.recheck(old)
        records = candidate / sdk.RECORDS
        records.mkdir(parents=True)
        save(records / 'conditions.json', dict(schemaVersion=1, kind='deployment-conditions', environment='staging',
            target='p1-isolated', backup=dict(required=False, reference=None, restoreEvidence=None),
            migration=dict(mode='none', evidence=None)))
        gh = None if smoke else GitHubClient(os.environ['P1_GITHUB_TOKEN'])
        def phase(operation, observation, desired, history=None):
            deadline = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
            save(records / 'current.json', observation.snapshot())
            save(records / 'target.json', dict(schemaVersion=1, kind='deployment-target', environment='staging',
                target='p1-isolated', version='v2' if history is None else 'v1', components=[desired]))
            plan = sdk.planner.prepare(candidate, 'staging', sdk.RECORDS + 'target.json',
                                       sdk.RECORDS + 'current.json', sdk.RECORDS + 'conditions.json')
            assert plan['result'] == 'prepared', plan['blockers']
            intent = executor.prepare(candidate, plan, operation, observation=observation, rollback_target=history)
            request = sdk.build_request(candidate, plan, operation, collector=collector, observation=observation,
                repository_slug=metadata['targetRepository'], repository_id=metadata['targetRepositoryId'],
                expires_at=deadline, rollback_target=history, execution_intent=intent)
            if smoke:
                approval = TestApproval()
            else:
                environment = 'p14-deploy-approval' if history is None else 'p14-rollback-approval'
                hostpolicy = host.DeploymentHostPolicy(host_repository=metadata['hostRepository'],
                    host_repository_id=metadata['hostRepositoryId'], workflow_ref=os.environ['GITHUB_WORKFLOW_REF'],
                    workflow_sha=os.environ['GITHUB_SHA'], run_id=int(os.environ['GITHUB_RUN_ID']), environment='p14-observer',
                    reviewer_ids=tuple(metadata['reviewerIds']), target_repository=metadata['targetRepository'],
                    target_repository_id=metadata['targetRepositoryId'], ledger_repository=metadata['hostRepository'],
                    ledger_repository_id=metadata['hostRepositoryId'], ledger_sha=os.environ['GITHUB_SHA'],
                    expires_at=deadline, prevent_self_review=False, deployment_environment='staging',
                    deployment_target='p1-isolated', production=False, runtime_policy_hash=policy.identity_hash(),
                    allowed_components=('web', 'api'), approval_environment=environment, execution_policy_hash=epolicy.identity_hash())
                digest = bundle_digest([request], deadline, hostpolicy.bundle_context())
                save(output / (operation + '-preview.json'), dict(bundleHash=digest, request=asdict(request),
                    hostPolicy=asdict(hostpolicy), observation=observation.to_dict(), executionAvailable=True, productionReady=False))
                run_path = '/repos/' + metadata['hostRepository'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID']
                until = time.monotonic() + 2100
                while time.monotonic() < until:
                    reviews, _ = gh.request('GET', run_path + '/approvals')
                    if any(review.get('state') == 'approved' and review.get('comment') == 'dev-workflow approve ' + digest
                           and any(item.get('name') == environment for item in review.get('environments', [])) for review in reviews):
                        break
                    time.sleep(5)
                else:
                    raise ValueError('Precise environment review timed out')
                for _ in range(15):
                    active, _ = gh.request('GET', run_path)
                    if active.get('status') == 'in_progress':
                        break
                    time.sleep(2)
                approval = host.GitHubDeploymentApproval(gh, oidc(), [request], hostpolicy)
            permit = sdk.authorize(candidate, plan, request, collector=collector, observation=observation,
                approval=approval, rollback_target=history, execution_intent=intent)
            result = executor.execute(candidate, permit, intent)
            issued = result.pop('observation', None)
            save(output / (operation + '-result.json'), result)
            assert result['status'] == ('executed-unhealthy' if negative and history is None else 'executed-verified'), result.get('failureCode')
            assert result['verification']['health'] == 'passed'
            assert result['verification']['smoke'] == ('failed' if negative and history is None else 'passed')
            expect_rejected(lambda: executor.execute(candidate, permit, intent))
            return issued if issued is not None else collector.collect()
        desired = dict(next(item for item in old.snapshot()['components'] if item['name'] == 'web'))
        entry = next(item for item in catalog if item['component'] == 'web' and item['version'] == '2.0.0')
        desired.update(sourceSha=entry['sourceSha'], artifact=entry['artifact'],
                       configurationDigest=images[('web', '2.0.0')][1].configuration_digest())
        current = phase('deployment-deploy', old, desired)
        assert next(item for item in current.snapshot()['components'] if item['name'] == 'web')['sourceSha'] == metadata['newSha']
        expect_rejected(lambda: collector.recheck(old))
        target = next(item for item in old.snapshot()['components'] if item['name'] == 'web')
        final = phase('deployment-rollback', current, target, old)
        assert final.snapshot()['components'] == old.snapshot()['components']
        assert final.snapshot()['version'] == old.snapshot()['version']
        old_api = next(item for item in old.to_dict()['instances'] if item['component'] == 'api')
        final_api = next(item for item in final.to_dict()['instances'] if item['component'] == 'api')
        assert old_api == final_api
        mutations = [call for call in calls if call['method'] != 'GET']
        assert len(mutations) == 8, mutations
        assert all(call['principal'] == 'writer' for call in mutations)
        save(output / 'summary.json', dict(result='passed', realDocker=True, realMTLS=True,
            realGitHubOIDC=not smoke, authority='synthetic-test-double' if smoke else 'github-oidc-exact-review-cas',
            productDeploymentExecuted=True, productRollbackExecuted=True, preservedApiInstance=True,
            restoredHistoricalIdentity=True, readinessPassed=True, businessSmokePassed=not negative,
            negativeBusinessResponseDetected=negative, noAutomaticRollback=True, readerWriteDenied=True, unselectedWriteDenied=True,
            wrongPinDenied=True, mutations=mutations, productionReady=False))
    finally:
        if server:
            server.shutdown()
            server.server_close()
        owned = run('docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project).splitlines()
        if owned:
            subprocess.run(['docker', 'rm', '-f', *owned], capture_output=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        output = ROOT / 'p14-results'
        output.mkdir(exist_ok=True)
        save(output / 'failure.json', dict(result='failed', errorType=type(exc).__name__,
            locations=[Path(item.filename).name + ':' + str(item.lineno) for item in traceback.extract_tb(exc.__traceback__)]))
        raise SystemExit('P14 fixture failed: ' + type(exc).__name__)
