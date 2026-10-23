#!/usr/bin/env python3
"""Read-only host diagnostics; no deployment or authority initialization."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import time
import socket
import threading
from urllib.parse import urlsplit, quote
from deployment_host_config import load_host_config, read_private_bytes, DISTRIBUTION
import deployment_runtime as runtime

REMEDIATION = 'Verify explicit host configuration and independently provision trusted private inputs.'

def _get_raw(host, port, path, context, headers=None, pin=None, timeout=10):
    # Resolver workers never connect: a late DNS result cannot send a request.
    deadline = time.monotonic() + timeout
    resolved = []
    ready = threading.Event()
    def resolve():
        try:
            resolved.extend(socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM))
        except OSError:
            pass
        finally:
            ready.set()
    threading.Thread(target=resolve, daemon=True).start()
    if not ready.wait(timeout) or not resolved:
        raise TimeoutError()
    peer = None
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
    watchdog = None
    try:
        for family, kind, protocol, _, address in resolved:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            peer = socket.socket(family, kind, protocol)
            peer.settimeout(remaining)
            try:
                peer.connect(address)
                break
            except OSError:
                peer.close()
                peer = None
        if peer is None:
            raise ConnectionError()
        peer = context.wrap_socket(peer, server_hostname=host, do_handshake_on_connect=False)
        def expire():
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        watchdog = threading.Timer(remaining, expire)
        watchdog.daemon = True
        watchdog.start()
        peer.settimeout(remaining)
        peer.do_handshake()
        if pin and hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() != pin:
            raise ValueError()
        conn.sock = peer
        conn.request('GET', path, headers=headers or {})
        response = conn.getresponse()
        seen = response.getheaders()
        lengths = [v for k, v in seen if k.lower() == 'content-length']
        if (len(seen) > 64 or sum(len(k)+len(v) for k,v in seen) > 32768
                or len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) > 1024*1024
                or any(k.lower() == 'transfer-encoding' for k,v in seen)):
            raise ValueError()
        raw = response.read(1024*1024+1)
        if response.status != 200 or len(raw) != int(lengths[0]) or time.monotonic() >= deadline:
            raise ValueError()
        return raw
    finally:
        if watchdog:
            watchdog.cancel()
        conn.close()
        if peer:
            peer.close()

def _get(*args, **kwargs):
    return runtime.parse_json(_get_raw(*args, **kwargs).decode('utf-8'))

def _tls_context(ca, certificate, key):
    # OpenSSL reads immutable in-memory snapshots through anonymous pipes.
    # No credential pathname is reopened and no temporary file is created.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=ca.decode('ascii'))
    pipes = [os.pipe(), os.pipe()]
    threads = []
    def feed(fd, value):
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(value)
        except (OSError, BrokenPipeError):
            pass
    try:
        for (_, writer), value in zip(pipes, (certificate, key)):
            thread = threading.Thread(target=feed, args=(writer, value), daemon=True)
            thread.start()
            threads.append(thread)
        context.load_cert_chain('/dev/fd/'+str(pipes[0][0]), '/dev/fd/'+str(pipes[1][0]), password=lambda: '')
        return context
    finally:
        for reader, _ in pipes:
            os.close(reader)
        for thread in threads:
            thread.join(1)

def _distribution_verified(expected):
    import stat
    environment = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    environment.update(GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1',
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS='1')
    def git(*args):
        raw = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                              '-c', 'core.hooksPath='+os.devnull, '-C', str(DISTRIBUTION), *args],
                             capture_output=True, check=True, timeout=10, env=environment).stdout
        if len(raw) > 16*1024*1024:
            raise ValueError()
        return raw
    settings = git('config', '--local', '--no-includes', '--list').decode().lower()
    if any('promisor' in line.split('=',1)[0] or 'partialclone' in line.split('=',1)[0] or line.startswith(('include.', 'includeif.'))
           for line in settings.splitlines()):
        raise ValueError()
    gitdir = Path(git('rev-parse', '--git-common-dir').decode().strip())
    if not gitdir.is_absolute():
        gitdir = DISTRIBUTION/gitdir
    if any((gitdir/'objects'/'pack').glob('*.promisor')) or (gitdir/'objects'/'info'/'alternates').exists():
        raise ValueError()
    if git('rev-parse', 'HEAD').decode().strip() != expected:
        raise ValueError()
    entries = git('ls-tree', '-rz', '--full-tree', 'HEAD', '--', 'scripts', 'core', 'packs').split(b'\0')
    tracked = set()
    if len(entries) > 10001:
        raise ValueError()
    for entry in filter(None, entries):
        header, name = entry.split(b'\t',1)
        mode, kind, oid = header.split()
        path = Path(name.decode('utf-8'))
        if len(name)>4096 or path.is_absolute() or '..' in path.parts or kind!=b'blob' or mode not in (b'100644',b'100755'):
            raise ValueError()
        full = DISTRIBUTION/path
        for ancestor in (full,*full.parents):
            if ancestor == DISTRIBUTION.parent:
                break
            if ancestor.is_symlink():
                raise ValueError()
        details = full.stat()
        if not stat.S_ISREG(details.st_mode) or details.st_size > 16*1024*1024:
            raise ValueError()
        if os.name != 'nt' and bool(details.st_mode & 0o111) != (mode == b'100755'):
            raise ValueError()
        # Raw cat-file never requests conversion, textconv, or clean/process filters.
        if full.read_bytes() != git('cat-file', 'blob', oid.decode('ascii')):
            raise ValueError()
        tracked.add(path.as_posix())
    count = 0
    for directory in ('scripts','core','packs'):
        for base, dirs, files in os.walk(DISTRIBUTION/directory, followlinks=False):
            for name in dirs + files:
                full = Path(base)/name
                if full.is_symlink():
                    raise ValueError()
            dirs[:] = [name for name in dirs if name != '__pycache__']
            for name in files:
                count += 1
                if count > 20000:
                    raise ValueError()
                full = Path(base)/name
                if full.relative_to(DISTRIBUTION).as_posix() not in tracked:
                    raise ValueError()
    return True


def diagnose(config, *, online=False):
    checks = []
    def add(name, status, code):
        checks.append(dict(id=name, status=status, code=code, remediation='' if status == 'pass' else {'hmac-keys': 'Provision explicit private store and gate keys containing at least 32 bytes each.', 'distribution': 'Use the configured clean trusted distribution commit; remove unexpected source modules.', 'tls-load': 'Provision private readable matching PEM credentials with distinct reader/writer identities and the configured writer pin.', 'runtime': 'Run online with the pinned reachable mTLS reader and a matching complete catalog/specification.', 'github': 'Verify explicit token access, repository IDs, commit SHAs and protected host review environments.', 'online': 'Unset SSLKEYLOGFILE before online diagnosis.', 'private-acl': 'Use a host with supported private ACL verification.'}.get(name, REMEDIATION)))
    add('configuration', 'pass', 'configuration-valid')
    try:
        _distribution_verified(config.distribution_commit)
        add('distribution', 'pass', 'distribution-pin-verified')
    except Exception:
        add('distribution', 'fail', 'distribution-pin-mismatch')
    add('private-acl', 'unknown' if os.name == 'nt' else 'pass', 'windows-acl-unverified' if os.name == 'nt' else 'posix-mode-checks')
    context = None
    try:
        for name in ('store_key_file', 'gate_key_file'):
            read_private_bytes(getattr(config, name), maximum=1024*1024, minimum=32)
        add('hmac-keys', 'pass', 'hmac-key-length-valid')
    except Exception:
        add('hmac-keys', 'fail', 'hmac-key-invalid-or-short')
    try:
        private_inputs = {}
        for name in ('store_key_file', 'gate_key_file', 'ca_file', 'reader_cert_file', 'reader_key_file', 'writer_cert_file', 'writer_key_file'):
            private_inputs[name] = read_private_bytes(getattr(config, name), maximum=1024*1024, minimum=1)
        for prefix in ('reader', 'writer'):
            ctx = _tls_context(private_inputs['ca_file'], private_inputs[prefix+'_cert_file'], private_inputs[prefix+'_key_file'])
            if prefix == 'reader':
                context = ctx
        for name, original in private_inputs.items():
            if read_private_bytes(getattr(config, name), maximum=1024*1024) != original:
                raise ValueError()
        reader_hash = hashlib.sha256(ssl.PEM_cert_to_DER_cert(private_inputs['reader_cert_file'].decode())).hexdigest()
        writer_hash = hashlib.sha256(ssl.PEM_cert_to_DER_cert(private_inputs['writer_cert_file'].decode())).hexdigest()
        if reader_hash == writer_hash or writer_hash != config.execution_policy.writer_certificate_sha256:
            raise ValueError()
        add('tls-load', 'pass', 'tls-loadable-only')
    except Exception:
        add('tls-load', 'fail', 'private-input-or-tls-invalid')
    if not online:
        add('runtime', 'unknown', 'online-check-required')
        add('github', 'unknown', 'online-check-required')
    elif os.environ.get('SSLKEYLOGFILE'):
        add('online', 'unknown', 'ambient-tls-output-refused')
    else:
        try:
            if context is None:
                raise ValueError()
            endpoint = urlsplit(config.runtime_policy.endpoint)
            capture_deadline = time.monotonic() + config.runtime_policy.capture_deadline
            def transport(path):
                remaining = capture_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                raw = _get_raw(endpoint.hostname, endpoint.port, path, context,
                               pin=config.runtime_policy.server_certificate_sha256, timeout=min(10, remaining))
                return raw if '/archive?' in path else runtime.parse_json(raw.decode('utf-8'))
            client = runtime.DockerTLSClient(config.runtime_policy, ca_file=config.ca_file,
                                            cert_file=config.reader_cert_file, key_file=config.reader_key_file,
                                            transport=transport)
            runtime.TrustedDockerCollector(config.runtime_policy, client).collect()
            add('runtime', 'pass', 'runtime-complete-observation')
        except Exception:
            add('runtime', 'unknown', 'runtime-unverified')
        try:
            token = read_private_bytes(config.github['credential_file'], maximum=16384, minimum=1).decode().strip()
            if any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise ValueError()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_default_certs()
            headers = {'Authorization': 'Bearer '+token, 'User-Agent': 'dev-workflow-host-doctor', 'Accept': 'application/vnd.github+json'}
            for slug, identity in ((config.runtime_policy.repository, config.store_policy.repository_id),
                                   (config.github['host_repository'], config.github['host_repository_id']),
                                   (config.github['ledger_repository'], config.github['ledger_repository_id'])):
                repo = _get('api.github.com', 443, '/repos/'+slug, ctx, headers)
                if repo.get('id') != identity or repo.get('full_name') != slug:
                    raise ValueError()
            for repository, sha in ((config.github['host_repository'], config.github['workflow_sha']),
                                    (config.github['ledger_repository'], config.github['ledger_sha'])):
                commit = _get('api.github.com', 443, '/repos/'+repository+'/git/commits/'+sha, ctx, headers)
                if commit.get('sha') != sha:
                    raise ValueError()
            for field in ('deploy_approval_environment', 'rollback_approval_environment', 'recovery_approval_environment'):
                name = config.github[field]
                env = _get('api.github.com', 443, '/repos/'+config.github['host_repository']+'/environments/'+quote(name, safe=''), ctx, headers)
                rules = [r for r in env.get('protection_rules', []) if r.get('type') == 'required_reviewers']
                if env.get('name') != name or env.get('can_admins_bypass') is not False or len(rules) != 1:
                    raise ValueError()
                rule = rules[0]
                reviewers = rule.get('reviewers', [])
                if (rule.get('prevent_self_review') is not config.github['prevent_self_review']
                        or not reviewers or any(r.get('type') != 'User' for r in reviewers)
                        or {r.get('reviewer', {}).get('id') for r in reviewers} != set(config.github['reviewer_ids'])):
                    raise ValueError()
            add('github', 'pass', 'github-identities-and-review-policy-observed')

        except Exception:
            add('github', 'unknown', 'github-unverified')
    status = 'fail' if any(c['status'] == 'fail' for c in checks) else 'unknown' if any(c['status'] == 'unknown' for c in checks) else 'pass'
    return dict(schemaVersion=1, status=status, checks=checks, productionReady=False, authorityGranted=False, deferred=['fresh-oidc-and-execution-approval'])

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--online', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        report = diagnose(load_host_config(args.config), online=args.online)
    except Exception as error:
        incomplete = str(error) == 'private-acl-unverified'
        report = dict(schemaVersion=1, status='unknown' if incomplete else 'fail', productionReady=False, checks=[dict(id='configuration', status='unknown' if incomplete else 'fail', code='private-acl-unverified' if incomplete else 'invalid-host-configuration', remediation=REMEDIATION)])
    print(json.dumps(report, sort_keys=True))
    return {'pass': 0, 'fail': 1, 'unknown': 2}[report['status']]

if __name__ == '__main__':
    sys.exit(main())
