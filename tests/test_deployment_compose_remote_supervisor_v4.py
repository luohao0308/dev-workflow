"""Real signed multiprocess diagnostic lifecycle; no Engine or production writer."""
import base64
from copy import deepcopy
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_compose_remote_supervisor_v4 as remote
from deployment_compose_actor_supervisor_v4 import ActorSupervisorV4

SOURCE = 'a'*64
CURSOR = {'sequence': 2, 'head': 'b'*64}
SESSION = 'c'*64


def serve(pipe, supervisor, key):
    server = remote.DiagnosticSupervisorServerV4(supervisor=supervisor, signing_key=key, source_digest=SOURCE)
    try:
        while True:
            request = pipe.recv()
            if request is None: break
            try:
                response = server.respond(request)
                if request['operation'] == 'stop-and-joined':
                    # Test-only assertion checks the actual child owned by server.
                    assert all(r[1].poll() is not None for r in supervisor._actors.values())
                pipe.send(response)
            except Exception:
                pipe.send({'rejected': True})
    except EOFError:
        pass
    finally:
        server.close(); pipe.close()


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class RemoteSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.key = Path(self.temp.name)/'key'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.key)],check=True)
        self.public = self.key.with_suffix('.pub').read_bytes()
        self.local = ActorSupervisorV4(); self.addCleanup(self.local.close)
        self.server = remote.DiagnosticSupervisorServerV4(supervisor=self.local,signing_key=self.key,source_digest=SOURCE)

    def client(self, transport=None, **change):
        args = dict(public_key=self.public,expected_boot=self.local.boot,source_digest=SOURCE,
                    expected_cursor=CURSOR,transport=transport or self.server.respond)
        args.update(change)
        return remote.RemoteActorSupervisorV4(**args)

    def sign(self, payload, namespace=remote.NAMESPACE):
        signature = subprocess.run(['ssh-keygen','-Y','sign','-f',str(self.key),'-n',namespace],
            input=remote.canonical(payload),capture_output=True,check=True,timeout=5).stdout
        return {'payload':payload,'signature':base64.b64encode(signature).decode()}

    def test_real_separate_supervisor_process_starts_and_joins_its_child(self):
        context=multiprocessing.get_context('fork')
        parent, child = context.Pipe()
        child_supervisor=ActorSupervisorV4(); self.addCleanup(child_supervisor.close)
        process=context.Process(target=serve,args=(child,child_supervisor,self.key)); process.start(); child.close()
        def cleanup():
            if process.is_alive():
                try: parent.send(None)
                except (BrokenPipeError,EOFError): pass
            process.join(5)
            if process.is_alive(): process.kill(); process.join(5)
            parent.close()
        self.addCleanup(cleanup)
        calls=[]
        def rpc(request):
            calls.append(deepcopy(request)); parent.send(request)
            if not parent.poll(5): raise TimeoutError()
            return parent.recv()
        client=self.client(rpc,expected_boot=child_supervisor.boot)
        actor=client.start_fixed_actor(SESSION)
        self.assertIs(type(actor),remote.RemoteActorHandle)
        proof=client.stop_and_join(actor)
        self.assertEqual(len(client.termination_digest(actor,proof,SESSION)),64)
        self.assertIs(client.stop_and_join(actor),proof)
        self.assertEqual(len(calls),2)
        self.assertNotEqual(calls[0]['rpcNonce'],calls[1]['rpcNonce'])
        restarted=self.client(rpc,expected_boot=child_supervisor.boot)
        with self.assertRaises(ValueError): restarted.actor_identity(actor,SESSION)
        with self.assertRaises(ValueError): client.termination_digest(actor,remote.RemoteActorTermination(),SESSION)
        client.close()
        with self.assertRaises(ValueError): client.actor_identity(actor,SESSION)
        cleanup(); self.assertEqual(process.exitcode,0)

    def test_signed_binding_time_and_namespace_attacks_never_register_handle(self):
        attacks=[('supervisorBoot','0'*64),('sessionHash','0'*64),('actorEpoch','0'*64),
                 ('rpcNonce','0'*64),('challenge','0'*64),('sourceDigest','0'*64),
                 ('cursor',{'sequence':True,'head':'b'*64}),('issuedAt',0),('expiresAt',0),
                 ('diagnosticOnly',1),('writerDrained',True)]
        for field,value in attacks:
            def rpc(request):
                response=self.server.respond(request);payload=response['payload'];payload[field]=value
                return self.sign(payload)
            client=self.client(rpc)
            with self.subTest(field=field),self.assertRaises(ValueError): client.start_fixed_actor(SESSION)
            self.assertEqual(client._actors,{})
        client=self.client(lambda req:self.sign(self.server.respond(req)['payload'], 'wrong-namespace'))
        with self.assertRaises(ValueError): client.start_fixed_actor(SESSION)
        with self.assertRaises(ValueError): self.client(expected_cursor={'sequence':True,'head':'b'*64})

    def test_stop_binds_advanced_cursor_without_resurrecting_actor(self):
        client=self.client();actor=client.start_fixed_actor(SESSION)
        cursor={'sequence':3,'head':'d'*64}
        proof=client.stop_and_join(actor,expected_cursor=cursor)
        self.assertEqual(len(client.termination_digest(actor,proof,SESSION,expected_cursor=cursor)),64)
        with self.assertRaises(ValueError):
            client.termination_digest(actor,proof,SESSION,expected_cursor=CURSOR)
        with self.assertRaises(ValueError): client.stop_and_join(actor,expected_cursor=CURSOR)
        with self.assertRaises(ValueError): self.client().stop_and_join(actor,expected_cursor=cursor)

    def test_transport_cannot_mutate_pinned_cursor_by_shared_reference(self):
        def rpc(request):
            request['cursor']['sequence']=9
            return self.server.respond(request)
        client=self.client(rpc)
        with self.assertRaises(ValueError): client.start_fixed_actor(SESSION)
        self.assertEqual(client._cursor,CURSOR)
        self.assertEqual(client._actors,{})

    def test_wrong_pinned_key_replay_and_malformed_responses(self):
        other=Path(self.temp.name)/'other'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(other)],check=True)
        client=self.client(public_key=other.with_suffix('.pub').read_bytes())
        with self.assertRaises(ValueError): client.start_fixed_actor(SESSION)
        saved=[]
        def save(request):
            response=self.server.respond(request); saved.append(response); return response
        first=self.client(save); first.start_fixed_actor(SESSION)
        with self.assertRaises(ValueError): self.client(lambda req:saved[0]).start_fixed_actor(SESSION)
        for response in ({}, {'payload':{},'signature':'!'},{'payload':{},'signature':'x'*20000},None):
            with self.subTest(response=str(response)[:40]),self.assertRaises(ValueError):
                self.client(lambda req:response).start_fixed_actor(SESSION)

    def test_lost_transport_and_failed_join_issue_no_proof(self):
        responses=[]
        def rpc(request):
            response=self.server.respond(request); responses.append(response);return response
        client=self.client(rpc);actor=client.start_fixed_actor(SESSION)
        with patch.object(self.local,'stop_and_join',side_effect=TimeoutError()),self.assertRaises(ValueError):
            client.stop_and_join(actor)
        self.assertEqual(len(responses),1);self.assertEqual(client._terminations,{})
        with patch.object(client,'_transport',side_effect=EOFError()),self.assertRaises(ValueError):
            client.stop_and_join(actor)
        self.assertEqual(client._terminations,{})
        with self.assertRaises(ValueError): client.termination_digest(actor,{},SESSION)

    def test_same_supervisor_cannot_rebuild_server_and_alias_original_epoch(self):
        calls=[]
        def rpc(request):
            calls.append(deepcopy(request)); return self.server.respond(request)
        client=self.client(rpc);actor=client.start_fixed_actor(SESSION)
        process=next(iter(self.local._actors.values()))[1]
        self.assertIsNone(process.poll())
        for _ in range(2):
            with self.assertRaises(ValueError):
                remote.DiagnosticSupervisorServerV4(supervisor=self.local,signing_key=self.key,source_digest=SOURCE)
        with self.assertRaises(ValueError): self.server.respond(calls[0])
        self.assertEqual(len(self.local._actors),1)
        proof=client.stop_and_join(actor)
        self.assertEqual(len(client.termination_digest(actor,proof,SESSION)),64)
        self.assertIsNotNone(process.poll())
        self.assertEqual(len(self.local._actors),1)
        self.server.close()
        with self.assertRaises(ValueError):
            remote.DiagnosticSupervisorServerV4(supervisor=self.local,signing_key=self.key,source_digest=SOURCE)

    def test_join_callback_cannot_sign_for_an_unjoined_actor(self):
        client=self.client()
        actor_a=client.start_fixed_actor(SESSION);actor_b=client.start_fixed_actor(SESSION)
        epoch_a=client.actor_identity(actor_a,SESSION);epoch_b=client.actor_identity(actor_b,SESSION)
        process_a=self.local._actors[id(self.server._actors[epoch_a][1])][1]
        process_b=self.local._actors[id(self.server._actors[epoch_b][1])][1]
        original=self.local.stop_and_join
        def rpc(request):
            # Substitute B before validation, then mutate the caller-owned dict
            # back to A during B's genuine join. The signer must still bind B.
            request['actorEpoch']=epoch_b
            def joined(handle):
                proof=original(handle)
                request['actorEpoch']=epoch_a
                return proof
            with patch.object(self.local,'stop_and_join',side_effect=joined):
                return self.server.respond(request)
        with patch.object(client,'_transport',side_effect=rpc),self.assertRaises(ValueError):
            client.stop_and_join(actor_a)
        self.assertEqual(client._terminations,{})
        self.assertIsNone(process_a.poll())
        self.assertIsNotNone(process_b.poll())
        proof=client.stop_and_join(actor_a)
        self.assertEqual(len(client.termination_digest(actor_a,proof,SESSION)),64)
        self.assertIsNotNone(process_a.poll())

    def test_server_snapshots_request_before_lifecycle_callbacks(self):
        request=dict(operation='start',supervisorBoot=self.local.boot,sourceDigest=SOURCE,
                     cursor=deepcopy(CURSOR),sessionHash=SESSION,actorEpoch='d'*64,
                     rpcNonce='e'*64,challenge='f'*64)
        original=self.local.start_fixed_actor
        def mutate(session):
            request['actorEpoch']='0'*64
            request['cursor']['sequence']=99
            return original(session)
        with patch.object(self.local,'start_fixed_actor',side_effect=mutate):
            response=self.server.respond(request)
        self.assertEqual(response['payload']['actorEpoch'],'d'*64)
        self.assertEqual(response['payload']['cursor'],CURSOR)
        self.assertEqual(set(self.server._actors),{'d'*64})
        self.server.close()
        self.assertTrue(all(row[1].poll() is not None for row in self.local._actors.values()))

    def test_server_rejects_replayed_nonce_boot_and_unregistered_epoch(self):
        request=dict(operation='start',supervisorBoot=self.local.boot,sourceDigest=SOURCE,
                     cursor=CURSOR,sessionHash=SESSION,actorEpoch='d'*64,rpcNonce='e'*64,challenge='f'*64)
        self.server.respond(request)
        with self.assertRaises(ValueError): self.server.respond(request)
        for changes in ({'supervisorBoot':'0'*64},{'sourceDigest':'0'*64},
                        {'operation':'stop-and-joined','actorEpoch':'0'*64}, {'argv':['echo']}):
            value=dict(request,rpcNonce='1'*64);value.update(changes)
            with self.assertRaises(ValueError): self.server.respond(value)
