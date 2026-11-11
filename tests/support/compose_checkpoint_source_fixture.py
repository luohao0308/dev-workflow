"""Original controller source retention, exited producer and fresh Git verifier.

SSH publication, provider, Engine and kernel are doubles in produce mode; source
Git objects, ZIP bytes, HMAC/SSHSIG, controller ownership and private I/O are real.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),*(str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts'))]


def produce(directory,repository,sha,archive_path):
    import deployment_compose_owned_recovery_session_v3_host as sessions
    import deployment_compose_owned_recovery_controller_v3_host as controller
    from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase
    engine=Path('/var/tmp')/('dw-engine-'+secrets.token_hex(8))
    raw=archive_path.read_bytes()
    def spawn(argv):
        return subprocess.Popen([sys.executable,'-u',str(Path(__file__).resolve()),'--managed',str(engine)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    captured=[];owner=SimpleNamespace(reviewed=[]);base=LocalAcceptanceCase.review_adapter(owner)
    class Review:
        def consume_prepared(self,bundle,request,notice):
            if request.operation=='recovery':raise RuntimeError('source-cut-before-recovery')
            return base.consume_prepared(bundle,request,notice)
        def close(self):pass
    session=None
    try:
        with patch.object(sessions.loader,'published_manager_archive',return_value=raw),patch.object(sessions,'_spawn',side_effect=spawn):
            session=sessions.OwnedRecoverySSHSessionV3(directory,'host-one',sha,verify_daemon_stop=True,timeout=30)
        try:
            controller._drive_managed_recovery_protocol(directory,session=session,review=Review(),on_review=lambda value:None,
                on_restart_checkpoint=lambda value:captured.append(deepcopy(value)),timeout=100)
        except RuntimeError as error:
            if str(error)!='source-cut-before-recovery':raise
        else:raise AssertionError('expected cut before second consumption')
        if len(captured)!=1 or [r.operation for r in owner.reviewed]!=['deploy']:raise AssertionError('checkpoint scope')
        return dict(descriptor=captured[0],producerPid=os.getpid(),repository=str(repository),
            newRecoveryConsumptions=0,executionRecovered=False,controllerClosed=session.cleanup_report()['closed'])
    finally:
        if session is not None:session.close()
        shutil.rmtree(engine,ignore_errors=True)


def managed_worker(engine):
    from tests.support import owned_recovery_managed_fixture as managed
    # Preserve the real manager/child pipes, while selecting this fixture's
    # source-aware child setup instead of the legacy hardcoded b40 input.
    managed.__file__=str(Path(__file__).resolve())
    managed.main('',engine)


def managed_child(attack,engine):
    from tests.support import owned_recovery_managed_fixture as managed
    from tests.support import owned_recovery_controller_fixture as worker
    from tests.test_deployment_compose_live_controller_flow_v3_host import preparation
    def execute(executable,argv):
        if executable!=sys.executable or Path(argv[1])!=ROOT/'tests/support/owned_recovery_controller_fixture.py':
            raise ValueError('source-fixture-program')
        cfg=json.loads(Path(argv[-1]).read_text())
        original=preparation._prepare_observed
        def source_inputs(*args,**kwargs):
            # Fix fixture input at its production point; the original preparer
            # generates every request, model and authenticated commitment.
            kwargs['source_sha']=cfg['sourceSha']
            return original(*args,**kwargs)
        old_argv=sys.argv
        try:
            sys.argv=argv[1:]
            with patch.object(preparation,'_prepare_observed',side_effect=source_inputs):
                worker.run()
        finally:
            sys.argv=old_argv
    with patch.object(os,'execv',side_effect=execute):
        managed.child(attack,engine)


def consume(value):
    from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3
    from deployment_compose_checkpoint_source_v3_host import verify_checkpoint_published_source
    d=value['descriptor'];case=Path(d['casePath'])
    with RestartCheckpointReaderV3(case,expected_material_digest=d['materialDigest'],expected_custody_digest=d['custodyDigest'],
            expected_context=d['context'],expected_witness_key_hash=d['witnessKeyHash'],
            expected_origin_material_digest=d['writerOriginMaterialDigest'],expected_origin_digest=d['writerOriginDigest']) as reader:
        result=verify_checkpoint_published_source(reader,repository=Path(value['repository']))
    return dict(producerPid=value['producerPid'],consumerPid=os.getpid(),summary=result.public_summary(),
        newApprovalConsumptions=0,executionRecovered=False)


if __name__=='__main__':
    mode=sys.argv[1]
    if mode=='--managed':
        managed_worker(sys.argv[2]);raise SystemExit(0)
    if mode=='--child':
        managed_child(sys.argv[2],sys.argv[3]);raise SystemExit(0)
    if mode=='produce':
        result=produce(Path(sys.argv[2]).resolve(strict=True),Path(sys.argv[3]).resolve(strict=True),
            sys.argv[4],Path(sys.argv[5]).resolve(strict=True))
    elif mode=='consume':result=consume(json.load(sys.stdin))
    else:raise ValueError('fixture mode')
    print(json.dumps(result),flush=True)
