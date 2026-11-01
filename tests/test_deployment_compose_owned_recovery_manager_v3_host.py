"""Real binary pipes/children, explicit service owner and business worker doubles."""
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_owned_recovery_manager_v3_host as manager
from deployment_compose_v3_channel_worker import read_frame,write_frame

ARCHIVE=b'fixture-code'
NONCE='1'*64


def worker(mode):
    if mode=='blocked-input':time.sleep(30);return
    initial=read_frame(sys.stdin.buffer)
    assert initial['entrypoint']==(manager.RESPONSE_LOSS_ENTRYPOINT if mode=='diagnostic' else manager.ENTRYPOINT)
    assert base64.b64decode(initial['archiveBase64'])==ARCHIVE
    if mode=='stderr-overflow':
        sys.stderr.buffer.write(b'x'*(1024*1024+1));sys.stderr.buffer.flush();time.sleep(30);return
    if mode=='partial-worker':
        sys.stdout.buffer.write(struct.pack('!I',100)+b'{');sys.stdout.buffer.flush();time.sleep(30);return
    if mode=='flood':
        for _ in range(4):write_frame(sys.stdout.buffer,dict(kind='data',channelNonce=NONCE,value='x'*600000))
        time.sleep(30);return
    kind='manager-stopped' if mode=='spoof-control' else 'hello'
    write_frame(sys.stdout.buffer,dict(kind=kind,channelNonce=NONCE))
    reply=read_frame(sys.stdin.buffer)
    assert reply==dict(kind='configure',channelNonce=NONCE)
    write_frame(sys.stdout.buffer,dict(kind='final',channelNonce=NONCE))


def fixture(mode,state):
    class Owner:
        def __init__(self,*args):
            self.unit='dw-writer-host-'+'2'*16+'.service'
            self._boot_id='kernel-boot';self._invocation='3'*32
            self._stopped=False;self.transport_returncode=None;self.process=None
        def record(self):
            path=Path(state);temporary=path.with_name(path.name+'.new')
            temporary.write_text(json.dumps(dict(stopped=self._stopped,started=self.process is not None,
                reaped=self.process is not None and self.process.poll() is not None)))
            os.replace(temporary,path)
        def start(self,**kwargs):
            self.process=subprocess.Popen([sys.executable,'-u',__file__,'--worker',mode],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            self.record();return self.process
        def stop(self,**kwargs):
            if mode=='stop-fails':raise ValueError('fixture-stop-failed')
            if self.process.poll() is None:self.process.kill()
            self.transport_returncode=self.process.wait(timeout=3)
            self._stopped=True;self.record()
        def _discard_local(self):
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=3)
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):stream.close()
            self.record()
        def close(self):self._discard_local()
    config=dict(entrypoint=manager.RESPONSE_LOSS_MANAGER_ENTRYPOINT if mode=='diagnostic' else manager.MANAGER_ENTRYPOINT,channelNonce=NONCE,sourceSha='b'*40,
        archiveDigest=hashlib.sha256(ARCHIVE).hexdigest(),hostId='host-one')
    with patch.object(manager,'OwnedRecoveryUnitV3',Owner),patch.object(manager,'ResponseLossUnitV3',Owner):
        if mode=='diagnostic':
            import deployment_compose_response_loss_manager_v3_host as diagnostic
            diagnostic.run(config,sys.stdin.buffer,sys.stdout.buffer,ARCHIVE,timeout=5)
        else:manager.run(config,sys.stdin.buffer,sys.stdout.buffer,ARCHIVE,timeout=5)


@unittest.skipUnless(os.name=='posix','POSIX pipe selectors required')
class ManagerTests(unittest.TestCase):
    def start(self,mode='normal'):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.state=Path(temp.name)/'state.json'
        self.process=subprocess.Popen([sys.executable,'-u',__file__,'--manager',mode,str(self.state)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        self.addCleanup(self.reap)
        self.bound=read_frame(self.process.stdout,timeout=5)
        self.assertEqual(self.bound['kind'],'manager-bound')
        self.assertEqual(self.bound['binding']['sourceSha'],'b'*40)
        return self.bound
    def reap(self):
        if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
        for p in (self.process.stdin,self.process.stdout,self.process.stderr):p.close()
    def send(self,kind,**data):
        write_frame(self.process.stdin,dict(kind=kind,channelNonce=NONCE,**data))
    def receive(self):return read_frame(self.process.stdout,timeout=5)
    def done(self,expected=0):
        code=self.process.wait(timeout=5)
        error=self.process.stderr.read()
        if expected==0:self.assertEqual(code,0,error)
        else:self.assertNotEqual(code,0)
        return json.loads(self.state.read_text())

    def test_diagnostic_route_acknowledges_profile_and_pins_worker_entry(self):
        self.start('diagnostic')
        self.assertEqual(self.bound['binding']['diagnosticProfile'],'response-unobserved-v3')
        self.send('manager-start');self.assertEqual(self.receive()['frame']['kind'],'hello')
        self.send('worker-frame',frame=dict(kind='configure',channelNonce=NONCE))
        self.assertEqual(self.receive()['frame']['kind'],'final')
        terminal=self.receive();self.assertEqual(terminal['binding'],self.bound['binding'])
        self.done()

    def test_profile_identity_and_wrong_fixed_entry_fail_before_owner_creation(self):
        config=dict(entrypoint=manager.MANAGER_ENTRYPOINT,channelNonce=NONCE,sourceSha='b'*40,
            archiveDigest=hashlib.sha256(ARCHIVE).hexdigest(),hostId='host-one')
        with patch.object(manager,'OwnedRecoveryUnitV3') as normal,patch.object(manager,'ResponseLossUnitV3') as diagnostic:
            for profile in (None,'response-unobserved-v3',object(),{}):
                with self.assertRaises(ValueError):manager._run(config,None,None,ARCHIVE,_profile=profile)
            with self.assertRaises(ValueError):manager._run(config,None,None,ARCHIVE,_profile=manager.profiles.RESPONSE_LOSS)
            config['entrypoint']=manager.RESPONSE_LOSS_MANAGER_ENTRYPOINT
            with self.assertRaises(ValueError):manager.run(config,None,None,ARCHIVE)
            for key in ('diagnosticProfile','faultMode','program','connector'):
                with self.assertRaises(ValueError):
                    manager._run(dict(config,**{key:'response-unobserved-v3'}),None,None,ARCHIVE,
                        _profile=manager.profiles.RESPONSE_LOSS)
            normal.assert_not_called();diagnostic.assert_not_called()

    def test_bound_then_stop_never_starts_worker_archive(self):
        self.start();self.send('manager-stop')
        self.assertNotIn('diagnosticProfile',self.bound['binding'])
        result=self.receive()
        self.assertEqual(result['kind'],'manager-stopped')
        self.assertEqual(result['binding'],self.bound['binding'])
        self.assertFalse(result['workerStartRequested']);self.assertFalse(result['daemonCleanupVerified'])
        self.assertFalse(result['productionReady']);self.assertTrue(result['wrapperStopped'])
        self.assertTrue(self.done()['stopped'])

    def test_coalesced_start_and_stop_reports_request_not_worker_execution(self):
        self.start()
        frames=[]
        for kind in ('manager-start','manager-stop'):
            body=manager.encode(dict(kind=kind,channelNonce=NONCE))
            frames.append(struct.pack('!I',len(body))+body)
        os.write(self.process.stdin.fileno(),b''.join(frames))
        value=self.receive()
        self.assertEqual(value['kind'],'manager-stopped')
        self.assertTrue(value['workerStartRequested'])
        self.assertNotIn('workerStarted',value)
        self.done()

    def test_full_duplex_business_frames_are_always_nested(self):
        self.start();self.send('manager-start')
        value=self.receive();self.assertEqual(value['kind'],'worker-frame')
        self.assertEqual(value['frame']['kind'],'hello')
        self.send('worker-frame',frame=dict(kind='configure',channelNonce=NONCE))
        self.assertEqual(self.receive()['frame']['kind'],'final')
        terminal=self.receive();self.assertEqual(terminal['kind'],'manager-stopped')
        self.assertEqual(terminal['transportReturncode'],0)
        self.assertTrue(self.done()['stopped'])

    def test_worker_cannot_impersonate_outer_control(self):
        self.start('spoof-control');self.send('manager-start')
        value=self.receive();self.assertEqual(value['kind'],'worker-frame')
        self.assertEqual(value['frame']['kind'],'manager-stopped')
        self.send('manager-stop');self.assertEqual(self.receive()['binding'],self.bound['binding'])
        self.done()

    def test_duplicate_start_or_wrong_nonce_fails_and_stops_owner(self):
        for attack in ('duplicate','nonce'):
            with self.subTest(attack=attack):
                self.start()
                if attack=='duplicate':
                    self.send('manager-start');self.send('manager-start')
                else:write_frame(self.process.stdin,dict(kind='manager-stop',channelNonce='0'*64))
                self.assertTrue(self.done(expected=1)['stopped']);self.reap()

    def test_partial_worker_frame_does_not_block_stop(self):
        self.start('partial-worker');self.send('manager-start');time.sleep(.2)
        started=time.monotonic();self.send('manager-stop')
        self.assertEqual(self.receive()['kind'],'manager-stopped')
        self.assertLess(time.monotonic()-started,2)
        self.done()

    def test_full_child_input_does_not_block_stop(self):
        self.start('blocked-input');self.send('manager-start')
        self.send('worker-frame',frame=dict(kind='configure',channelNonce=NONCE,value='x'*300000))
        started=time.monotonic();self.send('manager-stop')
        self.assertEqual(self.receive()['kind'],'manager-stopped')
        self.assertLess(time.monotonic()-started,2);self.done()

    def test_full_parent_output_does_not_block_stop(self):
        self.start('flood');self.send('manager-start');time.sleep(.2)
        self.send('manager-stop')
        deadline=time.monotonic()+2
        while time.monotonic()<deadline and not json.loads(self.state.read_text())['stopped']:time.sleep(.01)
        self.assertTrue(json.loads(self.state.read_text())['stopped'])
        while self.receive()['kind']!='manager-stopped':pass
        self.done()

    def test_eof_and_stderr_overflow_stop_without_terminal_success(self):
        for mode in ('normal','stderr-overflow'):
            with self.subTest(mode=mode):
                self.start(mode)
                if mode=='normal':self.process.stdin.close()
                else:self.send('manager-start')
                self.assertTrue(self.done(expected=1)['stopped']);self.reap()

    def test_stop_failure_never_emits_stopped_envelope(self):
        self.start('stop-fails');self.send('manager-stop')
        self.assertFalse(self.done(expected=1)['stopped'])
        self.assertEqual(self.process.stdout.read(),b'')


class DecoderTests(unittest.TestCase):
    def test_partial_deadline_belongs_to_one_frame(self):
        raw=manager.encode(dict(kind='x'));frame=struct.pack('!I',len(raw))+raw
        decoder=manager._Frames()
        with patch.object(manager.time,'monotonic',return_value=1):decoder.feed(frame[:2])
        with patch.object(manager.time,'monotonic',return_value=40):
            self.assertEqual(decoder.feed(frame[2:]+frame[:2]),[dict(kind='x')])
        self.assertEqual(decoder.partial_since,40)
        with self.assertRaises(ValueError):decoder.eof()

    def test_duplicate_noncanonical_and_oversized_frames_reject(self):
        for body in (b'{"x":1,"x":2}',b'{ "x":1}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):manager._Frames().feed(struct.pack('!I',len(body))+body)
        with self.assertRaises(ValueError):manager._Frames().feed(struct.pack('!I',manager.LIMIT+1))


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--worker':worker(sys.argv[2])
    elif len(sys.argv)>1 and sys.argv[1]=='--manager':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main()
