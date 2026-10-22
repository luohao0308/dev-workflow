#!/usr/bin/env python3
"""Trusted GitHub Actions embedding host. Never load this from candidate code.

Policy, this module, and its imports must come from the pinned trusted checkout.
The candidate checkout, local JSON, and environment variables confer no authority.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import urllib.request

from release_execute import AuthorizationUnavailable, Grant, Receipt, Request, OPERATIONS, canonical, timestamp

ISSUER = 'https://token.actions.githubusercontent.com'
AUDIENCE = 'dev-workflow-release-host'


def bundle_digest(requests, expires_at, context=None):
    return hashlib.sha256(canonical({'context': context, 'expiresAt': expires_at, 'requests': [request.digest() for request in requests]}).encode('ascii')).hexdigest()


def _deny(message, *, mismatch_fields=()):
    error = AuthorizationUnavailable(message)
    # Messages here are fixed host diagnostics, never response bodies or tokens.
    # Preserve a stable bounded identifier when the runner suppresses raw errors.
    error.failure_code = 'authorization-' + hashlib.sha256(message.encode('utf-8')).hexdigest()[:12]
    error.mismatch_fields = tuple(mismatch_fields)
    raise error


def _decode(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        _deny('Invalid OIDC encoding')
    try:
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except ValueError:
        _deny('Invalid OIDC encoding')


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _deny('Duplicate OIDC JSON key')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        _deny('Invalid OIDC JSON')
    if not isinstance(value, dict):
        _deny('Invalid OIDC object')
    return value


def _der(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else bytes([128 + (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + encoded + value


def _integer(value):
    raw = _decode(value).lstrip(b'\x00') or b'\x00'
    return _der(2, (b'\x00' if raw[0] & 128 else b'') + raw)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _deny('OIDC key endpoint redirected')


def verify_oidc(token):
    """Authenticate RS256 JWT against issuer keys using fixed host OpenSSL."""
    if not isinstance(token, str) or len(token) > 32768 or token.count('.') != 2:
        _deny('Invalid OIDC token')
    header_text, claims_text, signature_text = token.split('.')
    header = _json(_decode(header_text))
    claims = _json(_decode(claims_text))
    if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str) or header.get('crit'):
        _deny('Unsupported OIDC signature')
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(ISSUER + '/.well-known/jwks', timeout=15) as response:
            raw = response.read(262145)
        if len(raw) > 262144:
            _deny('OIDC key response too large')
        keys = _json(raw).get('keys')
        if not isinstance(keys, list):
            _deny('Invalid OIDC key set')
        matches = [key for key in keys if isinstance(key, dict) and key.get('kid') == header['kid']]
        if len(matches) != 1:
            _deny('Unknown OIDC signing key')
        key = matches[0]
        if key.get('kty') != 'RSA' or key.get('alg', 'RS256') != 'RS256' or key.get('use', 'sig') != 'sig':
            _deny('Invalid OIDC signing key')
        modulus, exponent = _decode(key.get('n')), _decode(key.get('e'))
        if not 256 <= len(modulus) <= 1024 or not 1 <= len(exponent) <= 8:
            _deny('Invalid OIDC RSA key size')
        rsa = _der(48, _integer(key['n']) + _integer(key['e']))
        spki = _der(48, bytes.fromhex('300d06092a864886f70d0101010500') + _der(3, b'\x00' + rsa))
        pem = b'-----BEGIN PUBLIC KEY-----\n' + base64.encodebytes(spki) + b'-----END PUBLIC KEY-----\n'
        with tempfile.TemporaryDirectory(prefix='workflow-oidc-') as directory:
            root = Path(directory)
            (root / 'key.pem').write_bytes(pem)
            (root / 'signature').write_bytes(_decode(signature_text))
            result = subprocess.run(['/usr/bin/openssl', 'dgst', '-sha256', '-verify', str(root / 'key.pem'),
                                     '-signature', str(root / 'signature')], input=(header_text + '.' + claims_text).encode('ascii'),
                                    capture_output=True, timeout=15, env={'PATH': '/usr/bin:/bin'})
        if result.returncode:
            _deny('OIDC signature rejected')
    except AuthorizationUnavailable:
        raise
    except Exception:
        _deny('OIDC signature could not be verified')
    return claims


@dataclass(frozen=True)
class HostPolicy:
    host_repository: str
    host_repository_id: int
    workflow_ref: str
    workflow_sha: str
    run_id: int
    environment: str
    reviewer_ids: tuple[int, ...]
    target_repository: str
    target_repository_id: int
    ledger_repository: str
    ledger_repository_id: int
    ledger_sha: str
    expires_at: str
    prevent_self_review: bool = True

    def __post_init__(self):
        for slug in (self.host_repository, self.target_repository, self.ledger_repository):
            if not isinstance(slug, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', slug):
                _deny('Invalid trusted repository policy')
        for value in (self.host_repository_id, self.target_repository_id, self.ledger_repository_id, self.run_id):
            if type(value) is not int or value <= 0:
                _deny('Invalid trusted identity policy')
        if not isinstance(self.ledger_sha, str) or not re.fullmatch(r'[0-9a-f]{40}', self.ledger_sha):
            _deny('Invalid trusted ledger object')
        timestamp(self.expires_at)
        if type(self.prevent_self_review) is not bool:
            _deny('Invalid trusted self-review policy')
        if self.ledger_repository_id == self.target_repository_id:
            _deny('Grant ledger must be outside target repository')
        if (not isinstance(self.reviewer_ids, tuple) or not self.reviewer_ids
                or any(type(value) is not int or value <= 0 for value in self.reviewer_ids)
                or len(set(self.reviewer_ids)) != len(self.reviewer_ids)):
            _deny('Invalid trusted reviewer policy')
        if (not isinstance(self.workflow_sha, str) or not re.fullmatch(r'[0-9a-f]{40}', self.workflow_sha)
                or not isinstance(self.workflow_ref, str)
                or not self.workflow_ref.startswith(self.host_repository + '/.github/workflows/')
                or '@' not in self.workflow_ref or not isinstance(self.environment, str)
                or not re.fullmatch(r'[A-Za-z0-9_-]+', self.environment)):
            _deny('Invalid trusted workflow policy')

    def bundle_context(self):
        """All trusted host scope is bound into the human-reviewed digest."""
        value = asdict(self)
        value.pop('expires_at')
        return value


class GitHubActionsApproval:
    """Protected-environment consent plus absent-only durable grant consumption.

    ``client`` uses GitHubClient.request(method, path, payload=None), returning ``(JSON, headers)``.
    An alternate verifier is solely a trusted embedding/test dependency, never a
    project-selected module or CLI option. GitHub-hosted Linux is the first host.
    """
    # Only trusted distribution subclasses may specialize these hooks. There is
    # deliberately no module path, plugin loader, or candidate configuration hook.
    request_type = Request
    operations = OPERATIONS
    audience = AUDIENCE
    grant_type = Grant
    receipt_type = Receipt
    ledger_namespace = 'workflow-grants'
    grant_namespace = 'github-actions'

    def _approval_environment(self):
        return self.policy.environment

    def _grant_expiry(self, request):
        return self._expires

    def __init__(self, client, oidc_token, requests, policy: HostPolicy, *, verifier=None):
        self.client, self.token, self.policy = client, oidc_token, policy
        self.requests = tuple(requests)
        if (not self.requests or any(type(item) is not self.request_type or item.operation not in self.operations for item in self.requests)
                or len({item.operation for item in self.requests}) != len(self.requests)):
            _deny('Invalid frozen operation bundle')
        self._requests = {item.digest(): item for item in self.requests}
        self.bundle_hash = bundle_digest(self.requests, policy.expires_at, policy.bundle_context())
        self.verifier = verifier or verify_oidc
        self._consumed = set()
        self._verified_consumptions = set()
        self._lock = threading.Lock()
        self._expires = None
        self._check_authority()

    def _get(self, path):
        result, _headers = self.client.request('GET', path)
        if not isinstance(result, (dict, list)):
            _deny('Invalid GitHub authority response')
        return result

    def _check_authority(self):
        policy = self.policy
        claims = self.verifier(self.token)
        if not isinstance(claims, dict):
            _deny('OIDC claims unavailable')
        now = time.time()
        bundle_expiry = timestamp(policy.expires_at).timestamp()
        if bundle_expiry <= now or bundle_expiry > now + 3600:
            _deny('Operation bundle expired or lifetime exceeds one hour')
        if (any(type(claims.get(key)) is not int for key in ('exp', 'iat', 'nbf'))
                or claims['exp'] <= now or claims['nbf'] > now or claims['iat'] > now
                or claims['iat'] < now - 600 or claims['exp'] - claims['iat'] > 600):
            _deny('OIDC token expired or outside bounded lifetime')
        expected = {'iss': ISSUER, 'aud': self.audience, 'repository': policy.host_repository,
                    'repository_id': str(policy.host_repository_id), 'workflow_ref': policy.workflow_ref,
                    'workflow_sha': policy.workflow_sha, 'run_id': str(policy.run_id), 'run_attempt': '1',
                    'environment': policy.environment}
        mismatches = tuple(key for key, value in expected.items() if claims.get(key) != value)
        if mismatches:
            _deny('OIDC workflow identity does not match trusted policy', mismatch_fields=mismatches)
        host_repository = None
        for slug, identity in ((policy.host_repository, policy.host_repository_id),
                               (policy.target_repository, policy.target_repository_id),
                               (policy.ledger_repository, policy.ledger_repository_id)):
            repo = self._get('/repos/' + slug)
            if repo.get('id') != identity or repo.get('full_name') != slug:
                _deny('GitHub repository identity changed')
            if slug == policy.host_repository:
                host_repository = repo
        self._verify_subject(claims, host_repository)
        run_path = '/repos/' + policy.host_repository + '/actions/runs/' + str(policy.run_id)
        run = self._get(run_path)
        if (run.get('id') != policy.run_id or run.get('run_attempt') != 1 or run.get('head_sha') != policy.workflow_sha
                or run.get('status') != 'in_progress' or run.get('event') != 'workflow_dispatch'
                or run.get('repository', {}).get('id') != policy.host_repository_id
                or str(run.get('actor', {}).get('id')) != claims.get('actor_id')):
            _deny('Workflow run does not match authenticated execution')
        approval_environment = self._approval_environment()
        environment = self._get('/repos/' + policy.host_repository + '/environments/' + approval_environment)
        if (type(environment.get('id')) is not int or environment['id'] <= 0
                or environment.get('name') != approval_environment):
            _deny('Protected environment identity changed')
        rules = environment.get('protection_rules', [])
        required = [rule for rule in rules if rule.get('type') == 'required_reviewers']
        if environment.get('can_admins_bypass') is not False or len(required) != 1 or required[0].get('prevent_self_review') is not policy.prevent_self_review:
            _deny('Environment requires non-bypassable review matching host policy')
        reviewers = required[0].get('reviewers', [])
        ids = [item.get('reviewer', {}).get('id') for item in reviewers if item.get('type') == 'User']
        if (len(ids) != len(reviewers) or not ids or set(ids) != set(policy.reviewer_ids)):
            _deny('Protected environment reviewer policy changed')
        reviews = self._get(run_path + '/approvals')
        if not isinstance(reviews, list):
            _deny('Run approval history unavailable')
        if any(review.get('state') == 'rejected' and any(item.get('id') == environment.get('id') for item in review.get('environments', [])) for review in reviews):
            _deny('Protected environment approval was rejected')
        approved = [review for review in reviews if review.get('state') == 'approved'
                    and review.get('user', {}).get('id') in policy.reviewer_ids
                    and (not policy.prevent_self_review or review.get('user', {}).get('id') != run.get('actor', {}).get('id'))
                    and review.get('comment') == 'dev-workflow approve ' + self.bundle_hash
                    and any(item.get('id') == environment.get('id') and item.get('name') == approval_environment
                            for item in review.get('environments', []))]
        if not approved:
            _deny('Exact operation bundle lacks protected-environment approval')
        self._expires = min(claims['exp'], bundle_expiry)
        if time.time() >= self._expires:
            _deny('Authorization expired during authority verification')

    def _verify_subject(self, claims, repository):
        # Repository API settings select the exact format. Neither a token's
        # appearance nor project-controlled data may choose a weaker subject.
        policy = self.policy
        settings = self._get('/repos/' + policy.host_repository + '/actions/oidc/customization/sub')
        if (not isinstance(settings, dict) or settings.get('use_default') is not True
                or ('include_claim_keys' in settings and settings['include_claim_keys'] != [])):
            _deny('Custom OIDC subject templates are unsupported')
        immutable = settings.get('use_immutable_subject', False)
        if type(immutable) is not bool:
            _deny('Invalid OIDC immutable subject configuration')
        owner_name, repository_name = policy.host_repository.split('/')
        if immutable:
            owner = repository.get('owner')
            if not isinstance(owner, dict) or type(owner.get('id')) is not int or owner['id'] <= 0:
                _deny('Immutable OIDC subject requires authenticated owner identity')
            prefix = 'repo:' + owner_name + '@' + str(owner['id']) + '/' + repository_name + '@' + str(policy.host_repository_id)
        else:
            prefix = 'repo:' + policy.host_repository
        if 'sub_claim_prefix' in settings and settings['sub_claim_prefix'] != prefix:
            _deny('OIDC subject prefix disagrees with authenticated repository identity')
        if claims.get('sub') != prefix + ':environment:' + policy.environment:
            _deny('OIDC workflow identity does not match trusted policy', mismatch_fields=('sub',))

    def _match(self, request):
        if type(request) is not self.request_type or self._requests.get(request.digest()) != request:
            _deny('Operation differs from reviewed bundle')
        if request.release_json:
            try:
                spec = json.loads(request.release_json)
            except ValueError:
                _deny('Invalid reviewed release identity')
            if not isinstance(spec, dict) or spec.get('repository') != self.policy.target_repository or spec.get('repositoryId') != self.policy.target_repository_id:
                _deny('Reviewed target differs from host policy')
        # All operations, including local tag creation, require a target binding.
        remote = request.remote_url or ''
        slug = self.policy.target_repository
        if remote not in ('https://github.com/' + slug, 'https://github.com/' + slug + '.git',
                           'git@github.com:' + slug, 'git@github.com:' + slug + '.git',
                           'ssh://git@github.com/' + slug, 'ssh://git@github.com/' + slug + '.git'):
            _deny('Reviewed remote differs from host policy')

    def validate(self, request):
        self._match(request)
        self._check_authority()
        expires = datetime.fromtimestamp(self._grant_expiry(request), timezone.utc).isoformat()
        return self.grant_type(self.grant_namespace + ':' + str(self.policy.run_id) + ':' + request.operation, request.digest(), expires, 1)

    def consume(self, grant, request, *, before_consume=None):
        """Consume once, optionally checking a trusted SDK guard at the CAS edge."""
        if before_consume is not None and not callable(before_consume):
            _deny('Consumption guard must be callable')
        with self._lock:
            expected = self.validate(request)
            if type(grant) is not self.grant_type or grant != expected or request.digest() in self._consumed:
                _deny('Grant changed or already consumed')
            marker = 'refs/tags/' + self.ledger_namespace + '/' + str(self.policy.run_id) + '/' + self.bundle_hash + '/' + request.operation
            # No automatic retry: both a duplicate and a lost response deny dispatch.
            self._consumed.add(request.digest())
            def before_send():
                self._check_authority()
                if before_consume is not None:
                    before_consume()
                # All blocking authority and SDK reads precede these local checks.
                self._match(request)
                if time.time() >= min(self._grant_expiry(request), timestamp(grant.expires_at).timestamp()):
                    _deny('Authorization expired before grant consumption')
            try:
                value, _headers = self.client.request('POST', '/repos/' + self.policy.ledger_repository + '/git/refs',
                                            {'ref': marker, 'sha': self.policy.ledger_sha}, before_send=before_send)
            except Exception:
                _deny('Durable grant consumption rejected or outcome unknown')
            if not isinstance(value, dict) or value.get('ref') != marker or value.get('object', {}).get('sha') != self.policy.ledger_sha:
                _deny('Durable grant consumption not verified')
            self._verified_consumptions.add(request.digest())
            return self.receipt_type(grant.grant_id, request.digest(), 1, datetime.now(timezone.utc).isoformat())

    def guard(self, request):
        """Provider calls immediately before dispatch; never issues another grant."""
        self._match(request)
        self._check_authority()
        if request.digest() not in self._verified_consumptions:
            _deny('Mutation requires consumed grant')
        marker = 'tags/' + self.ledger_namespace + '/' + str(self.policy.run_id) + '/' + self.bundle_hash + '/' + request.operation
        value = self._get('/repos/' + self.policy.ledger_repository + '/git/ref/' + marker)
        if value.get('ref') != 'refs/' + marker or value.get('object', {}).get('sha') != self.policy.ledger_sha:
            _deny('Durable grant ledger changed')
        if time.time() >= self._grant_expiry(request):
            _deny('Authorization expired during ledger verification')
