"""Synthetic cross-host status verification only; no approval or Docker access."""
import argparse
import base64
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import io
import json
import os
import select
from pathlib import Path
import queue
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('deployment_compose_intent_status_v3.py', 'deployment_contract_v2.py', 'deployment_gate_witness.py')
CASES = ('valid', 'lag-one-second', 'future', 'expired', 'bad-signature', 'wrong-nonce', 'wrong-hash')
LIMIT = 262144
REMOTE = r'''import base64,io,json,os,pathlib,select,sys,tempfile,time,zipfile
from types import SimpleNamespace
LIMIT=262144
REMOTE_TIMEOUT=90
deadline=time.monotonic()+REMOTE_TIMEOUT
pending=bytearray()
names=('deployment_compose_intent_status_v3.py','deployment_contract_v2.py','deployment_gate_witness.py')
def read():
 global pending
 while True:
  end=pending.find(b'\n')
  if end>=0:
   if end+1>LIMIT:raise ValueError('bounded-input')
   raw=bytes(pending[:end+1]);del pending[:end+1];return json.loads(raw)
  if len(pending)>=LIMIT:raise ValueError('bounded-input')
  left=deadline-time.monotonic()
  if left<=0 or not select.select([0],[],[],left)[0]:raise ValueError('read-timeout')
  chunk=os.read(0,min(65536,LIMIT-len(pending)))
  if not chunk:raise ValueError('bounded-input')
  pending.extend(chunk)
def send(v):print(json.dumps(v,separators=(',',':')),flush=True)
v=read()
with tempfile.TemporaryDirectory(prefix='dw-status-diagnostic-') as d:
 with zipfile.ZipFile(io.BytesIO(base64.b64decode(v['archive'],validate=True))) as z:
  if tuple(z.namelist())!=names or sum(i.file_size for i in z.infolist())>LIMIT:raise ValueError('source-bound')
  for n in names:(pathlib.Path(d)/n).write_bytes(z.read(n))
 sys.path.insert(0,d)
 from deployment_contract_v2 import RequestV2
 import deployment_compose_intent_status_v3 as status
 req=RequestV2.from_json(json.dumps(v['request'],sort_keys=True,separators=(',',':')))
 result=[]
 for case in v['cases']:
  observed=[];signed={};real=status.time
  def transport(rpc):
   send(dict(kind='rpc',case=case,request=rpc));reply=read();signed.update(reply['payload']);return reply
  def clock():
   now=time.time()-(1 if case=='lag-one-second' else 0);observed.append(now);return now
  status.time=SimpleNamespace(time=clock,sleep=time.sleep)
  try:
   status.IntentStatusClientV3(req,base64.b64decode(v['public'],validate=True),transport).check_consumed_intent(req)
   outcome='accepted';stage=None
  except status.IntentStatusRejected as e:outcome='rejected';stage=e.stage
  finally:status.time=real
  row=dict(case=case,outcome=outcome,stage=stage)
  if observed:
   row.update(signedIssued=signed['issuedAt'],receiverBefore=observed[0],receiverAfter=observed[-1],legacyTimeCheckWouldReject=observed[0]<signed['issuedAt'])
  result.append(row)
 send(dict(kind='result',cases=result,scratchCleanedOnExit=True))
'''


def _archive():
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in MODULES:
            archive.writestr(name, (ROOT/'packs/deployment/scripts'/name).read_bytes())
    if len(out.getvalue()) > LIMIT // 2:
        raise ValueError('source-bound')
    return base64.b64encode(out.getvalue()).decode('ascii')


def _request():
    sys.path.insert(0, str(ROOT/'packs/deployment/scripts'))
    from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity
    return asdict(RequestV2(schema_version=2, operation='deploy', profile_id='compose-application-batch-v1',
        profile_version='3', source=SourceIdentity('github.com', 'https://github.com/diagnostic/fixture.git',
        1, 'diagnostic/fixture', 'a'*40), target=TargetIdentity('compose', 'dw-diagnostic', 'fixture'),
        environment='staging', production=False, daemon_id='synthetic-only', components=('backend',),
        protected_components=('peer',), before_hash='a'*64, after_hash='b'*64, artifact_digest='c'*64,
        observation_hash='d'*64, history_hash=None, host_id='diagnostic-only', plan_hash='e'*64,
        policy_hash='f'*64, expires_at=(datetime.now(timezone.utc)+timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'), max_uses=1))


def _run(argv):
    """Private helper also exercised using a local Python subprocess in tests."""
    with tempfile.TemporaryDirectory(prefix='dw-status-probe-host-') as directory:
        key = Path(directory)/'diagnostic-key'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)], check=True, capture_output=True, timeout=10)
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        events = queue.Queue(maxsize=16)
        def receive():
            try:
                for _ in range(16):
                    raw = process.stdout.readline(LIMIT+1)
                    if not raw or len(raw)>LIMIT or not raw.endswith(b'\n'):raise ValueError('bounded-output')
                    events.put(json.loads(raw), timeout=1)
            except Exception:
                try:events.put(None, timeout=1)
                except queue.Full:pass
        thread = threading.Thread(target=receive, daemon=True)
        thread.start()
        def send(value):
            raw = json.dumps(value,separators=(',',':')).encode()+b'\n'
            if len(raw)>LIMIT:raise ValueError('bounded-input')
            fd=process.stdin.fileno();os.set_blocking(fd,False)
            while raw:
                left=deadline-time.monotonic()
                if left<=0 or not select.select([], [fd], [], min(10,left))[1]:raise ValueError('write-timeout')
                try:written=os.write(fd,raw)
                except BlockingIOError:continue
                if not written:raise ValueError('write-failed')
                raw=raw[written:]
        deadline = time.monotonic()+90
        try:
            send(dict(archive=_archive(),request=_request(),public=base64.b64encode(key.with_suffix('.pub').read_bytes()).decode(),cases=CASES))
            for case in CASES:
                frame=events.get(timeout=max(.01,deadline-time.monotonic()))
                if type(frame) is not dict or set(frame)!={'kind','case','request'} or frame['kind']!='rpc' or frame['case']!=case:raise ValueError('unexpected-rpc')
                issued=int(time.time())
                if case=='future':issued+=10
                if case=='expired':issued-=40
                payload=dict(frame['request'],purpose='consumed-intent-status-v3',issuedAt=issued,expiresAt=issued+30,
                    consumed=True,authorityGranted=False,runtimePermit=False,productionReady=False)
                if case=='wrong-nonce':payload['rpcNonce']='0'*64
                if case=='wrong-hash':payload['requestHash']='0'*64
                signed=subprocess.run(['ssh-keygen','-Y','sign','-f',str(key),'-n','dev-workflow-compose-consumed-intent-status-v3'],
                    input=json.dumps(payload,sort_keys=True,separators=(',',':')).encode(),check=True,capture_output=True,timeout=10).stdout
                if case=='bad-signature':signed=b'invalid diagnostic signature'
                send(dict(payload=payload,signature=base64.b64encode(signed).decode()))
            result=events.get(timeout=max(.01,deadline-time.monotonic()))
            if type(result) is not dict or result.get('kind')!='result' or len(result.get('cases',[]))!=len(CASES):raise ValueError('unexpected-result')
            expected={'valid':None,'lag-one-second':None,'future':'time-validity','expired':'time-validity',
                      'bad-signature':'signature-verification','wrong-nonce':'response-binding','wrong-hash':'response-binding'}
            failed_cases = [case for case, row in zip(CASES, result['cases'])
                            if row['case'] != case or row['stage'] != expected[case]
                            or row['outcome'] != ('accepted' if expected[case] is None else 'rejected')]
            if failed_cases:
                # Only fixed local case names enter errors, never remote text.
                raise ValueError('matrix-failed:' + ','.join(failed_cases))
            process.stdin.close();process.wait(timeout=10)
            if process.returncode:raise ValueError('worker-failed')
            return dict(success=True,diagnosticOnly=True,authorityGranted=False,dockerWrites=0,productionReady=False,
                        cases=result['cases'],workerStopped=True,scratchCleaned=True)
        finally:
            if not process.stdin.closed:process.stdin.close()
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            thread.join(timeout=2);process.stdout.close()


def run_probe(ssh_alias):
    if not isinstance(ssh_alias,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',ssh_alias):raise ValueError('invalid-ssh-alias')
    return _run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',
        '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ForwardX11=no','-o','PermitLocalCommand=no',
        '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','-T',ssh_alias,'exec python3 -I -u -c '+shlex.quote(REMOTE)])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-alias',required=True)
    print(json.dumps(run_probe(parser.parse_args().ssh_alias),sort_keys=True))
