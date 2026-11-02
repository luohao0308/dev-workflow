"""Private custody of a session's exact source archive, never source authority.

The archive hash is bound to independently supplied checkpoint and origin pins.
Git/source provenance is verified separately. No adjacent manifest pins itself.
"""
import os
import sys

from deployment_compose_owned_recovery_session_v3_host import session_source_archive, writer_origin_record
from deployment_compose_restart_checkpoint_v3_host import (
    RestartCheckpointReaderV3, _sealed_reader, _Guard, publish, digest, note_cleanup, read_file)
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical

MAX_ARCHIVE=2*1024*1024
_DESCRIPTOR={'casePath','materialDigest','custodyDigest','context','witnessKeyHash',
             'writerOriginMaterialDigest','writerOriginDigest'}


def reject():raise ValueError('compose-checkpoint-archive-v3-rejected') from None


def _reader(case,pins):
    material,custody,context,witness_key,origin_material,origin=pins
    if origin_material is None or origin is None:reject()
    return RestartCheckpointReaderV3(case,expected_material_digest=material,
        expected_custody_digest=custody,expected_context=decode(context),expected_witness_key_hash=witness_key,
        expected_origin_material_digest=origin_material,expected_origin_digest=origin)


def _archive_guard(case):
    guard=_Guard(case)
    try:
        guard.add_dir(case/'source-archive')
        raw=guard.add_file(case/'source-archive','archive.private.zip',MAX_ARCHIVE)
        _check_archive(guard)
        if not raw:reject()
        return guard,raw
    except BaseException as primary:
        try:guard.close()
        except Exception:note_cleanup(primary)
        raise


def _check_archive(guard):
    guard.check()
    if set(os.listdir(guard.dirs[guard.case/'source-archive'][0]))!={'archive.private.zip'}:reject()


def read_bound_source_archive(reader):
    """Cold reauthentication, without trusting a replaceable cached context."""
    guard=None
    try:
        seal=_sealed_reader(reader)
        case,pins=seal[1:3]
        material,custody,context,witness_key,origin_material,origin=pins
        if origin_material is None or origin is None:reject()
        guard,raw=_archive_guard(case)
        expected=decode(context)
        if digest(raw)!=expected['archiveDigest']:reject()
        with _reader(case,pins) as fresh:
            fresh_seal=_sealed_reader(fresh)
            authenticated=fresh.context
            source=authenticated.history._request.source
            if (source.source_sha!=expected['sourceSha'] or fresh.writer_origin is None
                    or authenticated.material_digest!=material):reject()
            # Complete original history reauthentication under the external pins.
            if authenticated.history.capture().canonical!=authenticated.snapshot.canonical:reject()
            if _sealed_reader(fresh)!=fresh_seal:reject()
        _check_archive(guard)
        if _sealed_reader(reader)!=seal:reject()
        return raw,source,decode(context),material
    except Exception:reject()
    finally:
        if guard is not None:
            primary=sys.exc_info()[1]
            try:guard.close()
            except Exception:
                if primary is None:reject()
                note_cleanup(primary)


def read_source_archive(reader):
    return read_bound_source_archive(reader)[0]


def retain_source_archive(case,*,session,checkpoint_descriptor):
    guard=None
    try:
        descriptor=decode(canonical(checkpoint_descriptor))
        if type(descriptor) is not dict or set(descriptor)!=_DESCRIPTOR or descriptor['casePath']!=str(case):reject()
        pins=(descriptor['materialDigest'],descriptor['custodyDigest'],canonical(descriptor['context']),
              descriptor['witnessKeyHash'],descriptor['writerOriginMaterialDigest'],descriptor['writerOriginDigest'])
        def binding():
            raw=session_source_archive(session)
            origin,manager,hello=writer_origin_record(session)
            if (hello is None or not session._started or session._early_terminal is not None
                    or digest(raw)!=descriptor['context']['archiveDigest']
                    or digest(origin)!=descriptor['writerOriginDigest']):reject()
            parsed=decode(hello)
            if any(parsed[k]!=descriptor['context'][k] for k in ('sourceSha','archiveDigest','hostId','daemonId')):reject()
            return raw,origin,manager,hello,session.nonce
        frozen=binding()
        with _reader(case,pins) as reader:
            _sealed_reader(reader)
            if (reader.writer_origin!=frozen[1] or reader.context.history._policy.scope_hash!=digest(frozen[3])):reject()
            artifact_raw,_=read_file(reader._guard.dirs[case/'writer-origin'][0],'origin.private.json',32768)
            if digest(artifact_raw)!=descriptor['writerOriginMaterialDigest']:reject()
            artifact=decode(artifact_raw)
            if (canonical(artifact['managerBinding'])!=frozen[2] or artifact['channelNonce']!=frozen[4]
                    or artifact['helloDigest']!=digest(frozen[3])):reject()
            _sealed_reader(reader)
        if binding()!=frozen:reject()
        guard=_Guard(case)
        os.mkdir('source-archive',0o700,dir_fd=guard.dirs[case][0]);os.fsync(guard.dirs[case][0])
        guard.add_dir(case/'source-archive')
        publish(guard.dirs[case/'source-archive'][0],'archive.private.zip',frozen[0])
        guard.close();guard=None
        with _reader(case,pins) as reader:
            if read_source_archive(reader)!=frozen[0] or binding()!=frozen:reject()
        return dict(descriptor,sourceArchiveDigest=digest(frozen[0]))
    except Exception:reject()
    finally:
        if guard is not None:
            primary=sys.exc_info()[1]
            try:guard.close()
            except Exception:
                if primary is None:reject()
                note_cleanup(primary)
