#!/usr/bin/env python3
"""Synthetic Actions-only P1 validation, never a deployment backend.

This harness creates its own disposable containers and read-only mTLS bridge.
Its explicit fixture transition is outside the product authorization API. Host
identities and both fixture commits are reviewed in the separate test repository.
Run with python -I from that trusted checkout, never install into a consumer.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import deployment_host as host
import deployment_authorize as sdk
import deployment_runtime as runtime
from release_github import GitHubClient
from release_host import bundle_digest
from release_execute import AuthorizationUnavailable
from release_host_runner import bootstrap


def run(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True, timeout=180)
    return result.stdout.strip()


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


class UnixDocker(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect('/var/run/docker.sock')


def bridge(directory):
    def openssl(*args):
        run('openssl', *args, cwd=directory)
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
            '-days', '1', '-subj', '/CN=P1 isolated CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    for name in ('server', 'client'):
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr',
                '-subj', '/CN=localhost')
        (directory / (name + '.ext')).write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n'
                'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='
                + ('serverAuth' if name == 'server' else 'clientAuth') + '\n')
        openssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
                '-days', '1', '-out', name + '.pem', '-extfile', name + '.ext')
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            allowed = (self.path == '/v1.45/info' or self.path.startswith('/v1.45/containers/json?')
                       or re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/json', self.path)
                       or re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/archive\?path=%2Fetc%2F(?:hosts|hostname|resolv\.conf)', self.path)
                       or re.fullmatch(r'/v1\.45/images/sha256:[0-9a-f]{64}/json', self.path))
            if not allowed:
                self.send_error(403)
                return
            calls.append(('GET', self.path, bool(self.connection.getpeercert())))
            connection = UnixDocker('localhost')
            try:
                connection.request('GET', self.path)
                response = connection.getresponse()
                body = response.read(runtime.MAX_RESPONSE + 1)
                if len(body) > runtime.MAX_RESPONSE:
                    self.send_error(502)
                    return
                self.send_response(response.status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                connection.close()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory / 'server.pem'), str(directory / 'server.key'))
    context.load_verify_locations(str(directory / 'ca.pem'))
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    der = ssl.PEM_cert_to_DER_cert((directory / 'server.pem').read_text())
    return server, hashlib.sha256(der).hexdigest(), calls


def oidc():
    # Reuse the pinned runner's endpoint validation; specialize only the audience.
    import release_host_runner
    previous = release_host_runner.AUDIENCE
    try:
        release_host_runner.AUDIENCE = host.AUDIENCE
        return release_host_runner.oidc_token()
    finally:
        release_host_runner.AUDIENCE = previous


def expect_rejected(callback):
    try:
        callback()
    except (ValueError, AuthorizationUnavailable):
        return
    raise AssertionError('Expected closed refusal')


def main():
    if sys.platform != 'linux' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Only the independent Linux Actions fixture is supported')
    workspace = Path(os.environ['RUNNER_TEMP']) / 'p1-isolated'
    workspace.mkdir(mode=0o700)
    output = ROOT / 'p1-results'
    output.mkdir()
    metadata = json.loads((ROOT / 'p1-fixture.json').read_text())
    candidate = Path('/tmp/dev-workflow-p1-target')
    run('git', 'clone', '--quiet', 'https://github.com/' + metadata['targetRepository'] + '.git', str(candidate))
    run('git', '-C', str(candidate), 'checkout', '--quiet', metadata['newSha'])
    bootstrap(candidate)
    manifest = candidate / '.dev-workflow/manifest.json'
    adopted = json.loads(manifest.read_text())
    adopted['installedPacks'] = ['deployment']
    save(manifest, adopted)
    project = 'p1-' + os.environ['GITHUB_RUN_ID']
    names = {name: project + '-' + name for name in ('web', 'api')}
    images, catalog = {}, []
    server = None
    try:
        for component, version, sha in (('web', '1.0.0', metadata['oldSha']),
                                         ('web', '2.0.0', metadata['newSha']),
                                         ('api', '1.0.0', metadata['oldSha'])):
            context = workspace / (component + version)
            context.mkdir()
            for filename in ('Dockerfile', 'release.txt'):
                raw = subprocess.run(['git', '-C', str(candidate), 'show', sha + ':fixtures/p1-runtime/' + filename],
                                     check=True, capture_output=True).stdout
                (context / filename).write_bytes(raw)
            # This known synthetic Dockerfile is deliberately built by the test
            # harness, never by the deployment SDK or candidate command table.
            image = run('docker', 'build', '--quiet', '--label', 'fixture-component=' + component, str(context))
            inspected = json.loads(run('docker', 'image', 'inspect', image))[0]
            images[(component, version)] = image
            catalog.append(dict(component=component, imageId=image, repository=metadata['targetRepository'],
                                sourceSha=sha, version=version, os=inspected['Os'], architecture=inspected['Architecture'],
                                artifact=dict(kind='local-build', imageId=image, buildSourceSha=sha),
                                migration=dict(mode='none', version=None)))
        def start(component, version):
            run('docker', 'run', '-d', '--read-only', '--name', names[component],
                '--label', 'com.docker.compose.project=' + project,
                '--label', 'com.docker.compose.service=' + component, images[(component, version)])
        start('web', '1.0.0')
        start('api', '1.0.0')
        server, pin, calls = bridge(workspace)
        policy = runtime.RuntimePolicy(endpoint='https://localhost:' + str(server.server_port),
                  server_certificate_sha256=pin, daemon_id=run('docker', 'info', '--format', '{{.ID}}'),
                  repository=metadata['targetRepository'], environment='staging', target='p1-isolated',
                  production=False, project=project, components=('web', 'api'),
                  catalog_json=json.dumps(dict(schemaVersion=1, images=catalog)), maximum_age=3000)
        client = runtime.DockerTLSClient(policy, ca_file=workspace / 'ca.pem',
                                        cert_file=workspace / 'client.pem', key_file=workspace / 'client.key')
        collector = runtime.TrustedDockerCollector(policy, client)
        old = collector.collect()
        assert old.to_dict()['complete'] is True
        expect_rejected(lambda: collector.validate(replace(old)))
        bad = runtime.TrustedDockerCollector(replace(policy, server_certificate_sha256='0' * 64),
                runtime.DockerTLSClient(replace(policy, server_certificate_sha256='0' * 64),
                  ca_file=workspace / 'ca.pem', cert_file=workspace / 'client.pem', key_file=workspace / 'client.key'))
        expect_rejected(bad.collect)
        gh = GitHubClient(os.environ['P1_GITHUB_TOKEN'])
        # Verify the least-privilege runner token can read all authority roots
        # before asking a human to review any request.
        for suffix in ('/actions/oidc/customization/sub', '/environments/p1-deploy-approval',
                       '/environments/p1-rollback-approval'):
            gh.request('GET', '/repos/' + metadata['hostRepository'] + suffix)
        conditions = dict(schemaVersion=1, kind='deployment-conditions', environment='staging', target='p1-isolated',
                          backup=dict(required=False, reference=None, restoreEvidence=None),
                          migration=dict(mode='none', evidence=None))
        records = candidate / sdk.RECORDS
        records.mkdir(parents=True)
        save(records / 'conditions.json', conditions)
        def phase(operation, observation, desired, history=None):
            deadline = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
            save(records / 'current.json', observation.snapshot())
            save(records / 'target.json', dict(schemaVersion=1, kind='deployment-target', environment='staging',
                 target='p1-isolated', version='v2' if history is None else 'v1', components=[desired]))
            plan = sdk.planner.prepare(candidate, 'staging', sdk.RECORDS + 'target.json',
                                      sdk.RECORDS + 'current.json', sdk.RECORDS + 'conditions.json')
            assert plan['result'] == 'prepared', plan['blockers']
            request = sdk.build_request(candidate, plan, operation, collector=collector, observation=observation,
                      repository_slug=metadata['targetRepository'], repository_id=metadata['targetRepositoryId'],
                      expires_at=deadline, rollback_target=history)
            environment = 'p1-deploy-approval' if history is None else 'p1-rollback-approval'
            hostpolicy = host.DeploymentHostPolicy(host_repository=metadata['hostRepository'],
                 host_repository_id=metadata['hostRepositoryId'], workflow_ref=os.environ['GITHUB_WORKFLOW_REF'],
                 workflow_sha=os.environ['GITHUB_SHA'], run_id=int(os.environ['GITHUB_RUN_ID']),
                 environment='p1-observer', reviewer_ids=tuple(metadata['reviewerIds']),
                 target_repository=metadata['targetRepository'], target_repository_id=metadata['targetRepositoryId'],
                 ledger_repository=metadata['hostRepository'], ledger_repository_id=metadata['hostRepositoryId'],
                 ledger_sha=os.environ['GITHUB_SHA'], expires_at=deadline, prevent_self_review=False,
                 deployment_environment='staging', deployment_target='p1-isolated', production=False,
                 runtime_policy_hash=policy.identity_hash(), allowed_components=('web', 'api'),
                 approval_environment=environment)
            digest = bundle_digest([request], deadline, hostpolicy.bundle_context())
            preview = dict(operation=operation, bundleHash=digest, request=asdict(request),
                           hostPolicy=asdict(hostpolicy), observation=observation.to_dict(),
                           executionAvailable=False, productionReady=False)
            save(output / (operation + '-preview.json'), preview)
            approvals = '/repos/' + metadata['hostRepository'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID'] + '/approvals'
            until = time.monotonic() + 2100
            while time.monotonic() < until:
                reviews, _ = gh.request('GET', approvals)
                if any(review.get('state') == 'approved'
                       and review.get('comment') == 'dev-workflow approve ' + digest
                       and any(env.get('name') == environment for env in review.get('environments', []))
                       for review in reviews):
                    break
                time.sleep(5)
            else:
                raise ValueError('Scoped human environment approval timed out')
            for _ in range(12):
                active, _ = gh.request('GET', '/repos/' + metadata['hostRepository']
                                       + '/actions/runs/' + os.environ['GITHUB_RUN_ID'])
                if active.get('status') == 'in_progress':
                    break
                time.sleep(2)
            else:
                raise ValueError('Reviewed workflow is not actively running')
            approval = host.GitHubDeploymentApproval(gh, oidc(), [request], hostpolicy)
            permit = sdk.authorize(candidate, plan, request, collector=collector, observation=observation,
                                   approval=approval, rollback_target=history)
            permit.claim_for_dispatch()  # No backend is connected; no deploy/rollback occurs.
            expect_rejected(permit.claim_for_dispatch)
            expect_rejected(lambda: approval.consume(permit.grant, request))
            save(output / (operation + '-result.json'), permit.to_dict())
            return request
        # The desired container configuration is intent, not evidence of execution.
        desired = dict(next(item for item in old.snapshot()['components'] if item['name'] == 'web'))
        entry = next(item for item in catalog if item['component'] == 'web' and item['version'] == '2.0.0')
        desired.update(sourceSha=entry['sourceSha'], artifact=entry['artifact'])
        phase('deployment-deploy', old, desired)
        # Explicit synthetic test transition, never a production/product adapter.
        run('docker', 'rm', '-f', names['web'])
        start('web', '2.0.0')
        current = collector.collect()
        expect_rejected(lambda: collector.recheck(old))
        assert current.state_hash != old.state_hash
        assert len({item['sourceSha'] for item in current.snapshot()['components']}) == 2
        target = next(item for item in old.snapshot()['components'] if item['name'] == 'web')
        phase('deployment-rollback', current, target, old)
        assert all(method == 'GET' and authenticated for method, _, authenticated in calls)
        save(output / 'summary.json', dict(result='passed', realDocker=True, realMTLS=True,
             getOnlyRequests=len(calls), realGitHubOIDC=True, deployAndRollbackAuthorization=True,
             productDeploymentExecuted=False, productRollbackExecuted=False, productionReady=False))
    finally:
        if server:
            server.shutdown()
            server.server_close()
        for name in names.values():
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Type only: raw API, TLS and subprocess errors can contain sensitive data.
        output = ROOT / 'p1-results'
        output.mkdir(exist_ok=True)
        save(output / 'failure.json', dict(result='failed', errorType=type(exc).__name__,
             locations=[Path(item.filename).name + ':' + str(item.lineno)
                        for item in traceback.extract_tb(exc.__traceback__)]))
        raise SystemExit('P1 fixture failed: ' + type(exc).__name__)
