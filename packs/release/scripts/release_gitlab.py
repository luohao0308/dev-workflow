#!/usr/bin/env python3
"""Bounded GitLab.com prototype; not wired into the GitHub-only release SDK.

The Tags API can create a lightweight tag at an existing commit. GitLab's
protected-tags API cannot prove the immutable/no-bypass contract needed for
Release creation, so this provider refuses that mutation.
Release inspection is standalone: its observation is not the v1 SDK's GitHub
Release shape, which requires a numeric releaseId.
"""
from __future__ import annotations

from http.client import HTTPException, HTTPSConnection
import json
import math
import re
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from release_execute import ExecutionError, IdentityConflict, ProviderRejected, verified_tag

API = 'https://gitlab.com/api/v4'
OID = re.compile(r'[0-9a-f]{40}')
PROJECT = re.compile(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+')
MAX_RESPONSE = 8 * 1024 * 1024


class GitLabUnavailable(ExecutionError):
    """The result cannot be verified; a mutation may have happened."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _mutation_deadline(value):
    if value is None:return None
    if type(value) not in (int,float) or not math.isfinite(value) or value<=time.monotonic():
        raise GitLabUnavailable('GitLab mutation deadline unavailable')
    return value


class _DeadlineHTTPSConnection(HTTPSConnection):
    def __init__(self,host,*,deadline,**kwargs):
        super().__init__(host,**kwargs)
        self._deadline=deadline
        self._io_timeout=self.timeout

    def _remaining(self):
        left=self._deadline-time.monotonic()
        if left<=0:
            self.close()
            raise GitLabUnavailable('GitLab mutation deadline exceeded')
        return min(self._io_timeout,left)

    def connect(self):
        self.timeout=self._remaining()
        super().connect()  # DNS/TCP/TLS may block; no HTTP is sent by connect.
        self.sock.settimeout(self._remaining())

    def send(self,data):
        if self.sock is None:self.connect()
        self.sock.settimeout(self._remaining())
        super().send(data)


class _DeadlineHTTPSHandler(HTTPSHandler):
    def __init__(self,deadline):
        super().__init__();self._deadline=deadline

    def https_open(self,request):
        def connection(host,**kwargs):
            if host!='gitlab.com':raise GitLabUnavailable('Unexpected GitLab mutation host')
            return _DeadlineHTTPSConnection(host,deadline=self._deadline,**kwargs)
        return self.do_open(connection,request,context=self._context)


class GitLabClient:
    """POST guard may return None (legacy) or a finite monotonic send deadline."""
    def __init__(self, token: str, *, timeout: float = 15, transport=None):
        if (not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 60):
            raise ExecutionError('Invalid trusted GitLab credential or timeout')
        self._token = token
        self.timeout = timeout
        self._transport = transport
        self._opener = build_opener(ProxyHandler({}), HTTPSHandler(), NoRedirect())

    def _network(self, method, path, payload, before_send):
        data = None if payload is None else json.dumps(payload, ensure_ascii=True, allow_nan=False).encode('ascii')
        request = Request(API + path, data=data, method=method, headers={
            'PRIVATE-TOKEN': self._token, 'Accept': 'application/json',
            'Content-Type': 'application/json', 'Cache-Control': 'no-cache',
            'User-Agent': 'dev-workflow-release',
        })
        supplied=before_send()
        deadline=_mutation_deadline(supplied) if method=='POST' else None
        opener=self._opener if deadline is None else build_opener(ProxyHandler({}),_DeadlineHTTPSHandler(deadline),NoRedirect())
        try:
            response = opener.open(request, timeout=self.timeout)
        except HTTPError as error:
            status = error.code
            error.close()
            return status, {}, None
        except (URLError, OSError, socket.timeout, HTTPException, ValueError):
            raise GitLabUnavailable('GitLab transport unavailable') from None
        try:
            with response:
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise GitLabUnavailable('GitLab response exceeds the bounded limit')
                return response.status, dict(response.headers.items()), json.loads(raw.decode('utf-8'))
        except (OSError, HTTPException, ValueError, UnicodeError):
            raise GitLabUnavailable('GitLab response unavailable or invalid') from None

    def request(self, method: str, path: str, payload=None, *, allow_missing=False, before_send=lambda: None):
        if (method not in ('GET', 'POST') or not isinstance(path, str) or not path.startswith('/projects/')
                or any(ord(c) < 33 or ord(c) > 126 for c in path) or '#' in path
                or any(part in ('.', '..') for part in path.split('/'))
                or urlsplit(API + path).netloc != 'gitlab.com'):
            raise ExecutionError('Invalid GitLab API request')
        if self._transport is None:
            status, headers, result = self._network(method, path, payload, before_send)
        else:
            supplied=before_send()
            if method=='POST':_mutation_deadline(supplied)
            try:
                status, headers, result = self._transport(method, path, payload)
            except Exception:
                raise GitLabUnavailable('GitLab transport unavailable') from None
        if method == 'GET' and status == 404 and allow_missing:
            return None
        expected = 200 if method == 'GET' else 201
        if status != expected:
            if method == 'POST' and isinstance(status, int) and 400 <= status < 500 and status not in (408, 429):
                raise ProviderRejected('GitLab rejected the mutation (HTTP ' + str(status) + ')')
            raise GitLabUnavailable('GitLab authoritative response unavailable')
        if not isinstance(headers, dict):
            raise GitLabUnavailable('GitLab response headers unavailable')
        return result


class GitLabTagProvider:
    def __init__(self, client: GitLabClient, project: str, project_id: int, *, before_mutation):
        if (not isinstance(client, GitLabClient) or not isinstance(project, str)
                or not PROJECT.fullmatch(project) or any(p in ('.', '..') for p in project.split('/'))
                or type(project_id) is not int or project_id <= 0 or not callable(before_mutation)):
            raise ExecutionError('Invalid trusted GitLab project or mutation guard')
        self.client = client
        self.project = project
        self.project_id = project_id
        self.before_mutation = before_mutation
        self.base = '/projects/' + str(project_id)

    def _bind(self, request):
        remote = request.remote_url
        if not isinstance(remote, str):
            raise IdentityConflict('Missing approved GitLab remote')
        if remote.startswith('git@gitlab.com:'):
            path = remote[len('git@gitlab.com:'):]
        else:
            parsed = urlsplit(remote)
            if (parsed.scheme not in ('https', 'ssh') or parsed.hostname != 'gitlab.com'
                    or parsed.netloc not in ('gitlab.com', 'git@gitlab.com')
                    or parsed.password is not None or parsed.query or parsed.fragment
                    or (parsed.scheme == 'https' and parsed.username is not None)
                    or (parsed.scheme == 'ssh' and parsed.username != 'git')):
                raise IdentityConflict('Unexpected approved GitLab remote')
            path = parsed.path.removeprefix('/')
        if path.removesuffix('.git') != self.project:
            raise IdentityConflict('GitLab destination differs from approved remote')
        if (not isinstance(request.tag, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', request.tag)
                or any(p in ('', '.', '..') or p.endswith(('.', '.lock')) or p.startswith('.')
                       for p in request.tag.split('/')) or '..' in request.tag
                or not isinstance(request.target_sha, str) or not OID.fullmatch(request.target_sha)
                or not isinstance(request.tag_object_sha, str) or not OID.fullmatch(request.tag_object_sha)):
            raise IdentityConflict('Invalid approved tag identity')
        project = self.client.request('GET', self.base)
        if (not isinstance(project, dict) or type(project.get('id')) is not int
                or project['id'] != self.project_id or project.get('path_with_namespace') != self.project):
            raise IdentityConflict('GitLab project identity could not be verified')

    def _tag(self, request):
        value = self.client.request('GET', self.base + '/repository/tags/' + quote(request.tag, safe=''), allow_missing=True)
        if value is None:
            return None
        commit = value.get('commit') if isinstance(value, dict) else None
        if (not isinstance(value, dict) or value.get('name') != request.tag
                or value.get('message', object()) is not None or value.get('target') != request.target_sha
                or not isinstance(commit, dict) or commit.get('id') != request.target_sha
                or request.tag_object_sha != request.target_sha):
            raise IdentityConflict('GitLab tag is not the approved lightweight commit tag')
        observed = dict(objectSha=value['target'], targetSha=commit['id'])
        verified_tag(observed, request)
        return observed

    def inspect(self, request):
        self._bind(request)
        return self._tag(request)

    def push(self, request):
        if request.operation != 'remote-tag-push':
            raise ProviderRejected('Tag provider received an unrelated operation')
        if request.tag_object_sha != request.target_sha:
            raise ProviderRejected('Only lightweight tag creation is supported')
        self._bind(request)
        if self._tag(request) is not None:
            return
        commit = self.client.request('GET', self.base + '/repository/commits/' + request.target_sha)
        if not isinstance(commit, dict) or commit.get('id') != request.target_sha:
            raise IdentityConflict('Approved commit is unavailable in the destination project')
        self.client.request('POST', self.base + '/repository/tags',
                            dict(tag_name=request.tag, ref=request.target_sha),
                            before_send=lambda: self.before_mutation(request))
        if self.inspect(request) is None:
            raise GitLabUnavailable('Created GitLab tag could not be verified')


class GitLabReleaseProvider(GitLabTagProvider):
    def inspect(self, request):
        if request.release_json is None:
            raise IdentityConflict('Approved GitLab Release specification is missing')
        try:
            spec = json.loads(request.release_json)
        except (TypeError, ValueError):
            raise IdentityConflict('Invalid approved GitLab Release specification') from None
        if (not isinstance(spec, dict) or set(spec) != {'endpoint', 'project', 'projectId', 'name', 'description'}
                or spec['endpoint'] != API or spec['project'] != self.project
                or type(spec['projectId']) is not int or spec['projectId'] != self.project_id
                or not isinstance(spec['name'], str) or not spec['name'].strip()
                or not isinstance(spec['description'], str)):
            raise IdentityConflict('GitLab Release specification differs from the trusted project')
        self._bind(request)
        if self._tag(request) is None:
            raise IdentityConflict('Approved remote tag is missing')
        value = self.client.request('GET', self.base + '/releases/' + quote(request.tag, safe=''), allow_missing=True)
        if value is None:
            return None
        commit = value.get('commit') if isinstance(value, dict) else None
        if (not isinstance(value, dict) or value.get('tag_name') != request.tag
                or value.get('name') != spec['name'] or value.get('description') != spec['description']
                or not isinstance(commit, dict) or commit.get('id') != request.target_sha):
            raise IdentityConflict('GitLab Release differs from approved content or commit')
        if self._tag(request) is None:
            raise IdentityConflict('Approved remote tag disappeared during Release inspection')
        return dict(endpoint=API, project=self.project, projectId=self.project_id,
                    tag=request.tag, tagObjectSha=request.tag_object_sha,
                    targetSha=commit['id'], name=value['name'], description=value['description'])

    def create(self, request):
        # Releases API accepts ref and can implicitly create a tag. GitLab's
        # protected-tags API does not establish immutable update/deletion rules
        # without bypass, so read-before/write/read-after cannot close the race.
        raise ProviderRejected('GitLab Release creation requires an immutable-tag guarantee unavailable from this API')
