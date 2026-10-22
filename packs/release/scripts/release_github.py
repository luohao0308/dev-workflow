#!/usr/bin/env python3
"""Bounded GitHub.com providers for a trusted release host.

No credentials, authorization, code, or transport configuration are loaded from
project files or the environment. A host supplies a token and a final mutation
guard. The tag operation creates an absent REST Git ref; it does not upload Git
objects. The approved commit must already exist in the destination repository.
"""
from __future__ import annotations

from http.client import HTTPException
import json
import math
import re
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from release_execute import ExecutionError, IdentityConflict, ProviderRejected, verified_tag

API = 'https://api.github.com'
OID = re.compile(r'[0-9a-f]{40}')
SLUG = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
MAX_RESPONSE = 8 * 1024 * 1024


class GitHubUnavailable(ExecutionError):
    """An authoritative response is unavailable; a mutation may have happened."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubClient:
    def __init__(self, token: str, *, timeout: float = 15, transport=None):
        if (not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 60):
            raise ExecutionError('Invalid trusted GitHub credential or timeout')
        self._token = token
        self.timeout = timeout
        self._transport = transport
        # Ignore environment proxy configuration, .netrc, and redirect targets.
        self._opener = build_opener(ProxyHandler({}), HTTPSHandler(), NoRedirect())

    def _network(self, method, path, payload, before_send):
        data = None if payload is None else json.dumps(payload, ensure_ascii=True, allow_nan=False).encode('ascii')
        request = Request(API + path, data=data, method=method, headers={
            'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + self._token,
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'dev-workflow-release',
            'Content-Type': 'application/json', 'Cache-Control': 'no-cache',
        })
        before_send()
        try:
            response = self._opener.open(request, timeout=self.timeout)
        except HTTPError as error:
            # Never expose response bodies, URL strings, or exception text.
            status = error.code
            error.close()
            return status, {}, None
        except (URLError, OSError, socket.timeout, HTTPException, ValueError):
            raise GitHubUnavailable('GitHub transport unavailable') from None
        try:
            with response:
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise GitHubUnavailable('GitHub response exceeds the bounded limit')
                result = json.loads(raw.decode('utf-8'))
                return response.status, dict(response.headers.items()), result
        except (OSError, HTTPException, ValueError, UnicodeError):
            raise GitHubUnavailable('GitHub response unavailable or invalid') from None

    def request(self, method: str, path: str, payload=None, *, allow_missing=False, before_send=lambda: None):
        if (method not in ('GET', 'POST') or not isinstance(path, str) or not path.startswith('/repos/')
                or any(ord(c) < 33 or ord(c) > 126 for c in path) or '#' in path
                or urlsplit(API + path).netloc != 'api.github.com'):
            raise ExecutionError('Invalid GitHub API request')
        if self._transport is None:
            status, headers, result = self._network(method, path, payload, before_send)
        else:
            before_send()
            try:
                status, headers, result = self._transport(method, path, payload)
            except Exception:
                raise GitHubUnavailable('GitHub transport unavailable') from None
        if method == 'GET' and status == 404 and allow_missing:
            return None, {}
        expected = 200 if method == 'GET' else 201
        if status != expected:
            if method == 'POST' and isinstance(status, int) and 400 <= status < 500 and status != 408:
                raise ProviderRejected('GitHub rejected the mutation (HTTP ' + str(status) + ')')
            raise GitHubUnavailable('GitHub authoritative response unavailable')
        if not isinstance(headers, dict):
            raise GitHubUnavailable('GitHub response headers unavailable')
        return result, headers


class GitHubTagProvider:
    def __init__(self, client: GitHubClient, repository: str, repository_id: int, *, before_mutation):
        if (not isinstance(repository, str) or not SLUG.fullmatch(repository)
                or any(part in ('.', '..') for part in repository.split('/'))
                or type(repository_id) is not int or repository_id <= 0 or not callable(before_mutation)):
            raise ExecutionError('Invalid trusted GitHub repository or mutation guard')
        self.client = client
        self.repository = repository
        self.repository_id = repository_id
        self.before_mutation = before_mutation
        self.base = '/repos/' + repository

    def _bind(self, request):
        remote = request.remote_url
        if not isinstance(remote, str):
            raise IdentityConflict('Missing approved GitHub remote')
        if remote.startswith('git@github.com:'):
            slug = remote[len('git@github.com:'):]
        else:
            parsed = urlsplit(remote)
            if (parsed.scheme not in ('https', 'ssh') or parsed.hostname != 'github.com'
                    or parsed.netloc not in ('github.com', 'git@github.com')
                    or parsed.password is not None or parsed.query or parsed.fragment
                    or (parsed.scheme == 'https' and parsed.username is not None)
                    or (parsed.scheme == 'ssh' and parsed.username != 'git')):
                raise IdentityConflict('Unexpected approved GitHub remote')
            slug = parsed.path.removeprefix('/')
        if slug.removesuffix('.git') != self.repository:
            raise IdentityConflict('GitHub destination differs from the approved remote')
        if (not isinstance(request.tag, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', request.tag)
                or any(part in ('', '.', '..') or part.endswith(('.', '.lock')) or part.startswith('.')
                       for part in request.tag.split('/')) or '..' in request.tag
                or not isinstance(request.target_sha, str) or not OID.fullmatch(request.target_sha)
                or not isinstance(request.tag_object_sha, str) or not OID.fullmatch(request.tag_object_sha)):
            raise IdentityConflict('Invalid approved tag identity')
        if request.release_json is not None:
            try:
                spec = json.loads(request.release_json)
            except (TypeError, ValueError):
                raise IdentityConflict('Invalid approved Release specification') from None
            if (not isinstance(spec, dict) or spec.get('endpoint') != API
                    or spec.get('repository') != self.repository
                    or type(spec.get('repositoryId')) is not int or spec['repositoryId'] != self.repository_id):
                raise IdentityConflict('GitHub repository identity differs from approved Release')
        repo, _ = self.client.request('GET', self.base)
        if (not isinstance(repo, dict) or type(repo.get('id')) is not int or repo['id'] != self.repository_id
                or not isinstance(repo.get('full_name'), str) or repo['full_name'].lower() != self.repository.lower()
                or not isinstance(repo.get('permissions'), dict) or repo['permissions'].get('push') is not True):
            # Push access is required to observe drafts; public read access alone
            # cannot establish the absence of an existing draft Release.
            raise IdentityConflict('GitHub repository ID or authenticated push access could not be verified')

    def _tag(self, request):
        value, _ = self.client.request('GET', self.base + '/git/ref/tags/' + quote(request.tag, safe=''), allow_missing=True)
        if value is None:
            return None
        if not isinstance(value, dict) or value.get('ref') != 'refs/tags/' + request.tag:
            raise IdentityConflict('GitHub returned a different tag reference')
        obj = value.get('object')
        raw = obj.get('sha') if isinstance(obj, dict) else None
        if raw != request.tag_object_sha:
            raise IdentityConflict('Remote tag raw object differs from approved object')
        seen = set()
        for _ in range(16):
            if not isinstance(obj, dict) or not isinstance(obj.get('sha'), str) or not OID.fullmatch(obj['sha']):
                raise IdentityConflict('Invalid remote Git object')
            if obj.get('type') == 'commit':
                observed = dict(objectSha=raw, targetSha=obj['sha'])
                verified_tag(observed, request)
                return observed
            if obj.get('type') != 'tag' or obj['sha'] in seen:
                raise IdentityConflict('Unexpected or cyclic remote Git tag object')
            seen.add(obj['sha'])
            tag, _ = self.client.request('GET', self.base + '/git/tags/' + obj['sha'])
            if not isinstance(tag, dict) or tag.get('sha') != obj['sha']:
                raise IdentityConflict('GitHub annotated tag object identity differs')
            obj = tag.get('object')
        raise IdentityConflict('Remote Git tag nesting exceeds the bounded limit')

    def inspect(self, request):
        self._bind(request)
        return self._tag(request)

    def push(self, request):
        if request.operation != 'remote-tag-push':
            raise ProviderRejected('Tag provider received an unrelated operation')
        self._bind(request)
        if request.tag_object_sha != request.target_sha:
            raise ProviderRejected('Only lightweight tag creation is supported')
        if self._tag(request) is not None:
            return
        commit, _ = self.client.request('GET', self.base + '/git/commits/' + request.target_sha)
        if not isinstance(commit, dict) or commit.get('sha') != request.target_sha:
            raise IdentityConflict('Approved commit is unavailable in the destination repository')
        self.client.request('POST', self.base + '/git/refs',
                            dict(ref='refs/tags/' + request.tag, sha=request.tag_object_sha),
                            before_send=lambda: self.before_mutation(request))
        if self.inspect(request) is None:
            raise GitHubUnavailable('Created GitHub tag could not be verified')


class GitHubReleaseProvider(GitHubTagProvider):
    MAX_PAGES = 100

    def require_tag_protection(self, request):
        """Require an active repository tag ruleset forbidding update/deletion.

        The API cannot atomically bind Release creation to an expected tag OID.
        A separately provisioned immutable tag closes the implicit tag-creation
        race. Missing bypass metadata is unknown, not an empty bypass list.
        Ruleset administrators remain trusted and must not change this policy
        during execution. This provider never provisions or relaxes rulesets.
        """
        self._bind(request)
        identifiers, seen = [], set()
        for page in range(1, self.MAX_PAGES + 1):
            values, headers = self.client.request(
                'GET', self.base + '/rulesets?includes_parents=false&per_page=100&page=' + str(page))
            if not isinstance(values, list) or len(values) > 100:
                raise GitHubUnavailable('GitHub tag protection listing is incomplete')
            for value in values:
                if (not isinstance(value, dict) or type(value.get('id')) is not int
                        or value['id'] <= 0 or value['id'] in seen):
                    raise GitHubUnavailable('GitHub tag protection listing is invalid or changed')
                seen.add(value['id'])
                identifiers.append(value['id'])
            link = next((v for k, v in headers.items() if k.lower() == 'link'), '')
            if not isinstance(link, str):
                raise GitHubUnavailable('Invalid GitHub tag protection pagination header')
            if len(values) < 100 and 'rel="next"' not in link:
                break
            if not values:
                raise GitHubUnavailable('GitHub tag protection pagination is incomplete')
        else:
            raise GitHubUnavailable('GitHub tag protection listing exceeds the bounded page limit')
        for identifier in identifiers:
            ruleset, _ = self.client.request('GET', self.base + '/rulesets/' + str(identifier))
            if not isinstance(ruleset, dict) or type(ruleset.get('id')) is not int or ruleset['id'] != identifier:
                raise GitHubUnavailable('GitHub tag protection ruleset identity changed')
            if (ruleset.get('source_type') != 'Repository' or ruleset.get('source') != self.repository
                    or ruleset.get('target') != 'tag' or ruleset.get('enforcement') != 'active'
                    or ruleset.get('bypass_actors') != []):
                continue
            conditions = ruleset.get('conditions')
            if not isinstance(conditions, dict) or set(conditions) != {'ref_name'}:
                continue
            ref = conditions['ref_name']
            if (not isinstance(ref, dict) or set(ref) != {'include', 'exclude'} or ref['exclude'] != []
                    or not isinstance(ref['include'], list)
                    or not all(isinstance(item, str) for item in ref['include'])
                    or not any(item in ('~ALL', 'refs/tags/' + request.tag) for item in ref['include'])):
                continue
            rules = ruleset.get('rules')
            if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
                continue
            updates = [rule for rule in rules if rule.get('type') == 'update']
            deletions = [rule for rule in rules if rule.get('type') == 'deletion']
            if (any(rule.get('parameters', {}) in ({}, {'update_allows_fetch_and_merge': False}) for rule in updates)
                    and any(rule.get('parameters', {}) == {} for rule in deletions)):
                return
        raise ProviderRejected('Release creation requires verified immutable tag protection without bypass actors')

    def _before_release_mutation(self, request):
        self.before_mutation(request)
        self.require_tag_protection(request)
        if self._tag(request) is None:
            raise IdentityConflict('Approved protected tag disappeared before Release creation')
        # The authorization check may itself perform network reads. Immutable
        # update/deletion rules keep this tag stable across those reads.
        self.before_mutation(request)

    def _spec(self, request):
        if request.release_json is None:
            raise IdentityConflict('Approved Release specification is missing')
        try:
            spec = json.loads(request.release_json)
        except (TypeError, ValueError):
            raise IdentityConflict('Invalid approved Release specification') from None
        required = {'endpoint', 'repository', 'repositoryId', 'name', 'body', 'draft', 'prerelease'}
        if (not isinstance(spec, dict) or set(spec) != required
                or not isinstance(spec.get('name'), str) or not spec['name'].strip()
                or not isinstance(spec.get('body'), str) or type(spec.get('draft')) is not bool
                or type(spec.get('prerelease')) is not bool):
            raise IdentityConflict('Invalid approved Release payload')
        return spec

    def _release(self, request):
        matches, seen = [], set()
        for page in range(1, self.MAX_PAGES + 1):
            values, headers = self.client.request('GET', self.base + '/releases?per_page=100&page=' + str(page))
            if not isinstance(values, list) or len(values) > 100:
                raise GitHubUnavailable('GitHub Release listing is incomplete')
            for value in values:
                if (not isinstance(value, dict) or type(value.get('id')) is not int or value['id'] <= 0
                        or value['id'] in seen or not isinstance(value.get('tag_name'), str)):
                    raise GitHubUnavailable('GitHub Release listing is invalid or changed during pagination')
                seen.add(value['id'])
                if value['tag_name'] == request.tag:
                    matches.append(value['id'])
            if len(matches) > 1:
                raise IdentityConflict('Multiple GitHub Releases use the approved tag')
            link = next((v for k, v in headers.items() if k.lower() == 'link'), '')
            if not isinstance(link, str):
                raise GitHubUnavailable('Invalid GitHub pagination header')
            if len(values) < 100 and 'rel="next"' not in link:
                break
            if not values:
                raise GitHubUnavailable('GitHub Release pagination cannot establish completeness')
        else:
            raise GitHubUnavailable('GitHub Release listing exceeds the bounded page limit')
        if not matches:
            return None
        value, _ = self.client.request('GET', self.base + '/releases/' + str(matches[0]))
        if (not isinstance(value, dict) or type(value.get('id')) is not int or value['id'] != matches[0]
                or value.get('tag_name') != request.tag):
            raise IdentityConflict('GitHub Release identity changed during inspection')
        return value

    def _observation(self, request, value, spec):
        if value is None:
            return None
        # All payload values below come from the fresh authenticated API result.
        observed = dict(endpoint=API, repository=self.repository, repositoryId=self.repository_id,
                        releaseId=value['id'], tag=value['tag_name'], tagObjectSha=request.tag_object_sha,
                        targetSha=request.target_sha)
        for field in ('name', 'body', 'draft', 'prerelease'):
            if type(value.get(field)) is not type(spec[field]) or value[field] != spec[field]:
                raise IdentityConflict('Observed GitHub Release payload differs from approved content')
            observed[field] = value[field]
        return observed

    def inspect(self, request):
        spec = self._spec(request)
        self._bind(request)
        if self._tag(request) is None:
            raise IdentityConflict('Approved remote tag is missing')
        value = self._release(request)
        if self._tag(request) is None:
            raise IdentityConflict('Approved remote tag disappeared during Release inspection')
        return self._observation(request, value, spec)

    def create(self, request):
        if request.operation != 'remote-release-create':
            raise ProviderRejected('Release provider received an unrelated operation')
        spec = self._spec(request)
        if self.inspect(request) is not None:
            return
        # Recheck after the potentially long complete draft/published listing.
        self._bind(request)
        if self._tag(request) is None:
            raise IdentityConflict('Approved remote tag disappeared before Release creation')
        payload = {key: spec[key] for key in ('name', 'body', 'draft', 'prerelease')}
        payload.update(tag_name=request.tag, target_commitish=request.target_sha,
                       make_latest='false', generate_release_notes=False)
        self.client.request('POST', self.base + '/releases', payload,
                            before_send=lambda: self._before_release_mutation(request))
        if self.inspect(request) is None:
            raise GitHubUnavailable('Created GitHub Release could not be verified')
