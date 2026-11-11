"""Owned Linux unit launcher for the fixed retained-production archive."""
import base64
import hashlib
from pathlib import Path
import secrets

from deployment_compose_owned_recovery_unit_v3_host import OwnedRecoveryUnitV3
from deployment_compose_production_scope_v1_host import ScopeRegistrationV1
from deployment_compose_retained_native_entry_v1_host import _inspect_registration
from deployment_compose_retained_source_v1_host import (
    CHANNEL_MEMBER, ENTRYPOINT, PROFILE, archive_files, production_bootstrap,
)
from deployment_compose_v3_channel_worker import read_frame, write_frame
from deployment_compose_witness_store import hex_value


def reject():
    raise ValueError('retained-production-unit-rejected') from None


class RetainedProductionUnitV1(OwnedRecoveryUnitV3):
    """Original Linux owner pins startup before accepting a controller channel."""

    def __init__(self, archive, *, source_sha, expected_archive_digest):
        files = archive_files(archive)
        if hashlib.sha256(archive).hexdigest() != expected_archive_digest:
            reject()
        super().__init__(expected_archive_digest, source_sha, disable_site=True)
        self._archive = archive
        self._has_channel = CHANNEL_MEMBER in files
        self._code = production_bootstrap(source_sha, expected_archive_digest)

    def start_registered(self, registration, *, work_directory, mode='startup-check', expected_endpoint_digest=None):
        if (type(registration) is not ScopeRegistrationV1 or registration.project != 'luohao-blog-prod'
                or not isinstance(work_directory, Path) or not work_directory.is_absolute()
                or mode not in ('startup-check', 'channel')
                or mode == 'channel' and (not self._has_channel or not hex_value(expected_endpoint_digest))
                or expected_endpoint_digest is not None and not hex_value(expected_endpoint_digest)
                or hashlib.sha256(self._archive).hexdigest() != self._archive_digest
                or self._code != production_bootstrap(self._source_sha, self._archive_digest)):
            reject()
        _inspect_registration(registration)
        scope = dict(root=str(registration.root), rootIdentity=list(registration.root_identity),
                     journalIdentity=list(registration.journal_identity), hostId=registration.host_id,
                     project=registration.project, daemonId=registration.daemon_id)
        nonce = secrets.token_hex(32)
        process = self.start(timeout=20)
        try:
            origin = self.capture_origin(timeout=5)
            source = dict(profile=PROFILE, sourceSha=self._source_sha, archiveDigest=self._archive_digest,
                          channelNonce=nonce, originDigest=hashlib.sha256(origin).hexdigest())
            write_frame(process.stdin, dict(entrypoint=ENTRYPOINT, sourceSha=self._source_sha,
                archiveDigest=self._archive_digest, channelNonce=nonce, scope=scope, mode=mode,
                workDirectory=str(work_directory), archiveBase64=base64.b64encode(self._archive).decode('ascii')),
                timeout=20)
            startup = read_frame(process.stdout, timeout=45)
            if type(startup) is not dict or not hex_value(startup.get('endpointDigest')):
                reject()
            expected = dict(kind='production-startup', channelNonce=nonce, source=source,
                scope=scope, endpointDigest=expected_endpoint_digest or startup['endpointDigest'])
            if startup != expected:
                reject()
            if mode == 'startup-check' and process.wait(timeout=10) != 0:
                reject()
            return process, expected
        except BaseException as primary:
            try:
                self.stop(timeout=30)
                self.close()
            except Exception:
                if hasattr(primary, 'add_note'):
                    primary.add_note('original production unit cleanup could not be verified')
            raise
