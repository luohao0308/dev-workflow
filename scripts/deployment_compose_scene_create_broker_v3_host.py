"""One original scene create worker; chunked transport never grants approval.

The original native issuer remains the sole stop authority. A lost controller
freezes the attempt; neither JSON nor reconnect can reconstruct its writer.
"""
import base64
import hashlib
import os
import re
import secrets
import selectors
import struct
import threading
import weakref
import time
from dataclasses import asdict
from datetime import datetime, timezone

from deployment_compose_witness_store import canonical
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_operation_witness_client_v3 import hex_value
from deployment_gate_witness import key_material
from deployment_gateway import GatePolicy
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_v3_channel_worker import write_frame,LIMIT
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_scene_preparation_v3_host import PreparationOwnerV3
from deployment_compose_scene_writer_slot_v3_host import SlotOwnerV3
from deployment_compose_cold_writer_v3_host import observe_stopped_writer

MAX_MESSAGE=4*1024*1024
_RECORDS=weakref.WeakKeyDictionary()
_FALSE=('authorityGranted','runtimePermit','recoveryAuthorized','productionReady','executionAvailable','writerQuiescenceVerified')


def reject():raise ValueError('compose-scene-create-broker-v3-rejected') from None


def digest(raw):return hashlib.sha256(raw).hexdigest()


def _record(broker):
    record=_RECORDS.get(broker)
    if type(broker) is not SceneCreateBrokerV3 or record is None or record['issuer']!=(os.getpid(),threading.get_ident()):reject()
    if record['unit'] is not None and record['unit']._process is not record['process']:reject()
    return record


def _b64(value):
    if type(value) is not str:reject()
    raw=base64.b64decode(value,validate=True)
    if base64.b64encode(raw).decode('ascii')!=value:reject()
    return raw



class SceneCreateBrokerV3:
    def __init__(self,preparation,raw_archive,witness_public_key,intent_public_key,slot,scene_id):
        if (type(preparation) is not PreparationOwnerV3 or type(slot) is not SlotOwnerV3 or type(raw_archive) is not bytes
                or type(scene_id) is not str or re.fullmatch('dw-scene-[0-9a-f]{16}',scene_id) is None):reject()
        witness=key_material(witness_public_key);intent=key_material(intent_public_key)
        if witness==intent:reject()
        inputs=PreparationOwnerV3.business_inputs(preparation);hello=inputs['hello']
        if digest(raw_archive)!=hello['archiveDigest']:reject()
        _RECORDS[self]=dict(issuer=(os.getpid(),threading.get_ident()),preparation=preparation,inputs=inputs,
            archive=raw_archive,witness=witness,intent=intent,slot=slot,scene=scene_id,state='new',unit=None,process=None,
            origin=None,attempt=None,pending=None,staged=None,terminal=None,buffer=bytearray(),
            stdout_eof=False,stderr_eof=False,last_rpc=0,stop=None,lease=None,generation=None,nonce=None)

    def __copy__(self):reject()
    def __deepcopy__(self,memo):reject()
    def __reduce_ex__(self,protocol):reject()

    def status(self):
        r=_record(self)
        result=dict(businessState=r['state'],attemptId=r['attempt'],businessSlotGeneration=r['generation'],
            pendingNonce=r['nonce'],transportClosed=r['stop'] is not None and r['terminal'] is not None,closureReconciled=r['state']=='reconciled',
            witnessKeyHash=digest(r['witness']),intentKeyHash=digest(r['intent']),**{k:False for k in _FALSE})
        if r.get('request_hash') is not None:
            meta=r['inputs']['metadata']
            result['closureChallenge']=dict(sceneId=r['scene'],attemptId=r['attempt'],attemptNonce=r['nonce'],
                preparationId=meta['preparationId'],capsuleDigest=meta['capsuleDigest'],slotGeneration=r['generation'],
                requestHash=r['request_hash'],bundleDigest=r['bundle_digest'])
        if (r['state'] in ('closed','reconciled') and r.get('origin') is not None
                and r['stop'] is not None and r['terminal'] is not None
                and 'daemonBinding' in r['inputs']):
            # These belong to this original attempt, even if the slot is later
            # used by a different generation. Never read a replacement's facts.
            result['checkpointEvidence']=dict(writerOrigin=decode(r['origin']),
                stopObservationDigest=r['stop'],daemonBinding=decode(canonical(r['inputs']['daemonBinding'])))
        return result

    def start_first_create(self,args,lease_generation):
        r=_record(self);inputs=r['inputs'];meta=inputs['metadata'];session=inputs['session']
        if (r['state']!='new' or type(args) is not dict or set(args)!={'preparationId','capsuleDigest','slotGeneration',
                'policy','gateKeyBase64','requestHash','receiptHash','firstBinding'}):reject()
        args=decode(canonical(args))
        slot=r['slot'].status()
        if (slot['slotState'] not in ('empty','drained') or type(args['slotGeneration']) is not int
                or args['slotGeneration']!=slot['slotGeneration'] or args['preparationId']!=meta['preparationId']
                or args['capsuleDigest']!=meta['capsuleDigest']):reject()
        policy=GatePolicy(**decode(canonical(args['policy'])));gate_key=_b64(args['gateKeyBase64'])
        request=session.prepared['request'];bundle=session.prepared['bundle'];hello=inputs['hello']
        descriptor=Profile3StepExecutor.scope_descriptor(bundle,request,args['receiptHash'],bundle.creation_operations()[0],0,{})
        binding=args['firstBinding']
        if (not 32<=len(gate_key)<=4096 or args['requestHash']!=request.digest() or not hex_value(args['receiptHash'])
                or request.policy_hash!=policy.identity_hash() or policy.operation_profile!='compose-v3'
                or policy.witness_required is not True or policy.scope_hash!=digest(canonical(hello))
                or policy.writer_certificate_sha256!=hello['writerCertificateSha256'] or policy.witness_key_sha256!=digest(r['witness'])
                or type(binding) is not dict or set(binding)!={'scopeHash','generation','policyHash','epoch'}
                or any(not hex_value(v) for v in binding.values()) or binding['scopeHash']!=descriptor['scopeHash']
                or binding['generation']!=descriptor['generation'] or binding['policyHash']!=policy.identity_hash()):reject()
        # The archive and capsule have separate custody bounds, but their
        # combined loader configuration must fit the unchanged native frame.
        # Validate before burning pending state or creating a writer unit.
        from deployment_compose_scene_create_worker_v3_host import ENTRYPOINT
        nonce=secrets.token_hex(32)
        context=dict(daemonBinding=inputs['daemonBinding'],
            hello=hello,capsuleBase64=base64.b64encode(inputs['capsule']).decode(),
            integrityKeys={k:base64.b64encode(v).decode() for k,v in inputs['keys'].items()},gatePolicy=asdict(policy),
            gateKey=base64.b64encode(gate_key).decode(),witnessPublicKey=base64.b64encode(r['witness']).decode(),
            intentPublicKey=base64.b64encode(r['intent']).decode(),consume={k:args[k] for k in ('requestHash','receiptHash','firstBinding')},
            observerFacts=meta['observerFacts'],normalizationVersion=decode(canonical(session.guard._version)))
        config=dict(entrypoint=ENTRYPOINT,sourceSha=hello['sourceSha'],archiveDigest=hello['archiveDigest'],
            channelNonce=nonce,hostId=hello['hostId'],context=context,archiveBase64=base64.b64encode(r['archive']).decode())
        if not 0<len(encode(config))<=LIMIT:reject()
        r.update(state='starting',attempt=secrets.token_hex(32),nonce=nonce,
            generation=slot['slotGeneration']+1,lease=lease_generation)
        PreparationOwnerV3.mark_product_pending(r['preparation'])
        try:
            allocated=r['slot'].reserve_create(args['slotGeneration'])
            unit=r['slot'].borrow_create_unit();r['unit']=unit;r['process']=unit._process
            r['origin']=canonical(allocated['writerOrigin']);r['generation']=allocated['slotGeneration']
            write_frame(r['process'].stdin,config,timeout=5)
            r.update(state='active',request_hash=request.digest(),bundle_digest=bundle.digest,
                     recoveryGateKey=gate_key,recoveryGatePolicy=policy)
            return self.status()
        except BaseException:
            r['state']='failed';raise

    def _pump(self,r):
        p=r['process']
        if p is None:return
        if r['state'] in ('active','terminal'):
            with selectors.DefaultSelector() as selector:
                if not r['stdout_eof'] and r['pending'] is None:selector.register(p.stdout,selectors.EVENT_READ,'out')
                if not r['stderr_eof']:selector.register(p.stderr,selectors.EVENT_READ,'err')
                for key,_ in selector.select(0):
                    raw=os.read(key.fd,65536)
                    if key.data=='err':
                        if raw:reject()
                        r['stderr_eof']=True
                    elif not raw:r['stdout_eof']=True
                    else:r['buffer'].extend(raw)
            if len(r['buffer'])>MAX_MESSAGE+4:reject()
            if r['pending'] is None and len(r['buffer'])>=4:
                size=struct.unpack('!I',r['buffer'][:4])[0]
                if not 0<size<=MAX_MESSAGE:reject()
                if len(r['buffer'])>=size+4:
                    raw=bytes(r['buffer'][4:4+size]);del r['buffer'][:size+4];value=decode(raw)
                    if type(value) is not dict or value.get('channelNonce')!=r['nonce'] or r['terminal'] is not None:reject()
                    if value.get('kind')=='rpc':
                        if (set(value)!={'kind','channelNonce','rpcId','service','method','request'} or type(value['rpcId']) is not int
                                or value['rpcId']!=r['last_rpc']+1 or value['rpcId']>4096
                                or value['method'] not in self._worker_methods(r).get(value['service'],set())):reject()
                        if 'stopStatus' not in r and 'relayTerminal' in r and (value['rpcId'], value['service'], value['method']) not in (
                                (1, 'intent', 'check'), (2, 'witness', 'check')):
                            reject()
                        if 'stopStatus' in r and value['rpcId'] > (256 if r['fullRecovery'] else 128):reject()
                        r['last_rpc']=value['rpcId'];r['pending']=(raw,value)
                    elif 'relayTerminal' in r:
                        if 'stopStatus' in r:
                            from deployment_compose_scene_recovery_worker_v3_host import stop_terminal
                            terminal_digest = value.get('terminalPhaseDigest')
                            if r['fullRecovery'] and not hex_value(terminal_digest):reject()
                            if not r['fullRecovery'] and terminal_digest is not None:reject()
                            if (not hex_value(value.get('head')) or raw != canonical(stop_terminal(
                                    r['nonce'], r['proofDigest'], value['head'], r['stopStatus'],
                                    through_delete=r['throughDelete'], terminal_digest=terminal_digest))):reject()
                        elif raw != r['relayTerminal']:reject()
                        r['terminal']=raw;r['state']='terminal';p.stdin.close()
                    elif value.get('kind')=='scene-create-closed':
                        required={'kind','channelNonce','requestHash','bundleDigest','historyDigest','receiptMap','history',
                            'authorityGranted','runtimePermit','recoveryAuthorized','productionReady'}
                        if (set(value)!=required or value['requestHash']!=r['request_hash'] or value['bundleDigest']!=r['bundle_digest']
                                or not hex_value(value['historyDigest']) or digest(canonical(value['history']))!=value['historyDigest']
                                or any(value[k] is not False for k in ('authorityGranted','runtimePermit','recoveryAuthorized','productionReady'))):reject()
                        r['terminal']=raw;r['state']='terminal';p.stdin.close()
                    else:reject()
            if r['stdout_eof'] and (r['buffer'] or r['terminal'] is None):reject()
            if r['terminal'] is not None and r['stdout_eof'] and r['stderr_eof']:
                code=p.poll()
                if code is not None:
                    if code!=0:reject()
                    r['state']='transport-exited'

    def _worker_record(self):
        r = _record(self)
        active = r.get('recoveryRelay')
        if active is None:
            return r
        if active['unit']._process is not active['process']:
            reject()
        return active

    @staticmethod
    def _worker_methods(record):
        witness = {'read','check','events_after','chain_status','append_event'}
        if record.get('throughDelete') is True:
            witness.add('transition_successor')
        return {'intent': {'check'}, 'witness': witness}

    def _worker_status(self, record):
        if 'relayTerminal' not in record:
            return self.status()
        return dict(attemptId=record['attempt'], pendingNonce=record['nonce'], businessState=record['state'])

    def poll_worker(self):
        r=self._worker_record()
        try:self._pump(r)
        except BaseException:r['state']='failed';raise
        result=self._worker_status(r)
        if r['pending'] is not None:
            raw,value=r['pending'];result['message']=dict(attemptId=r['attempt'],messageDigest=digest(raw),totalBytes=len(raw),
                rpcId=value['rpcId'],service=value['service'],method=value['method'])
        if r['terminal'] is not None:
            terminal=decode(r['terminal'])
            if 'relayTerminal' in r:
                result['relayDigest'] = digest(r['terminal'])
                if 'stopStatus' in r:
                    head_key = 'startHead' if r['fullRecovery'] else 'deleteHead' if r['throughDelete'] else 'stopHead'
                    result[head_key] = terminal['head']
                    if r['fullRecovery']:
                        result['terminalPhaseDigest'] = terminal['terminalPhaseDigest']
            else:
                result['closedResult']={key:terminal[key] for key in ('requestHash','bundleDigest','historyDigest','receiptMap')}
            result['terminalMessage']=dict(attemptId=r['attempt'],messageDigest=digest(r['terminal']),totalBytes=len(r['terminal']))
        return result

    def finish_worker(self,attempt_id):
        r=self._worker_record()
        if attempt_id!=r['attempt'] or r['state']!='transport-exited':reject()
        self.drain()
        if 'stopStatus' in r:
            original = _record(self)
            if r['throughDelete']:
                PreparationOwnerV3._reconcile_closed_scene_delete(
                    original['preparation'], decode(original['closure'])['receiptMap'],
                    terminal_digest=decode(r['terminal']).get('terminalPhaseDigest'))
            else:
                original['inputs']['session'].unknown_write_result = False
        r['state']='closed'
        return self._worker_status(r)

    def read_worker_chunk(self,attempt_id,message_digest,offset,length):
        r=self._worker_record()
        if attempt_id!=r['attempt'] or r['state'] in ('failed','frozen'):reject()
        if r['pending'] is not None and digest(r['pending'][0])==message_digest:raw=r['pending'][0]
        elif r['terminal'] is not None and digest(r['terminal'])==message_digest:raw=r['terminal']
        else:reject()
        if (digest(raw)!=message_digest or type(offset) is not int or type(length) is not int
                or not 0<=offset<len(raw) or not 0<length<=4096):reject()
        return dict(attemptId=attempt_id,messageDigest=message_digest,totalBytes=len(raw),offset=offset,
            dataBase64=base64.b64encode(raw[offset:offset+length]).decode())

    def begin_worker_reply(self,attempt_id,total_bytes,message_digest,rpc_id):
        r=self._worker_record()
        if (r['state']!='active' or attempt_id!=r['attempt'] or r['pending'] is None or r['staged'] is not None
                or type(total_bytes) is not int or not 0<total_bytes<=MAX_MESSAGE or not hex_value(message_digest)
                or type(rpc_id) is not int or rpc_id!=r['pending'][1]['rpcId']):reject()
        r['staged']=dict(raw=bytearray(),total=total_bytes,digest=message_digest,rpc=rpc_id)
        return self._worker_status(r)

    def worker_reply_chunk(self,attempt_id,offset,data_base64):
        r=self._worker_record();staged=r['staged'];raw=_b64(data_base64)
        if (r['state']!='active' or attempt_id!=r['attempt'] or staged is None or type(offset) is not int
                or offset!=len(staged['raw']) or not 0<len(raw)<=4096 or offset+len(raw)>staged['total']):reject()
        staged['raw'].extend(raw)
        return dict(attemptId=attempt_id,receivedBytes=len(staged['raw']),**{k:False for k in _FALSE})

    def commit_worker_reply(self,attempt_id):
        r=self._worker_record();staged=r['staged']
        if r['state']!='active' or attempt_id!=r['attempt'] or staged is None:reject()
        raw=bytes(staged['raw'])
        if len(raw)!=staged['total'] or digest(raw)!=staged['digest']:reject()
        value=decode(raw)
        if (type(value) is not dict or set(value)!={'kind','channelNonce','rpcId','response'} or value['kind']!='reply'
                or value['channelNonce']!=r['nonce'] or type(value['rpcId']) is not int or value['rpcId']!=staged['rpc']):reject()
        try:write_frame(r['process'].stdin,value,timeout=5)
        except BaseException:r['state']='failed';raise
        r['pending']=None;r['staged']=None
        return self._worker_status(r)

    def drain(self):
        r=self._worker_record()
        if r['stop'] is not None:return self._worker_status(r)
        if r['unit'] is None and r['slot'].status()['slotState'] in ('empty','drained'):return self.status()
        stopped=r['slot'].drain(r['generation'])
        r['stop']=stopped['stopObservationDigest']
        if r['state'] not in ('terminal','transport-exited','closed','reconciled'):r['state']='frozen'
        r['pending']=None;r['staged']=None
        return self._worker_status(r)

    def controller_lost(self):
        r=self._worker_record()
        if r['state'] not in ('new','closed','reconciled'):self.drain();r['state']='frozen'

    def reconcile_closure(self,certificate):
        r=_record(self)
        if r['state']!='closed' or r['terminal'] is None or r['stop'] is None:reject()
        from deployment_compose_scene_create_certificate_v3_host import verify_create_closure
        terminal=decode(r['terminal'])
        expected=dict(schemaVersion=1,purpose='scene-create-closure-v3',**self.status()['closureChallenge'],
            historyDigest=terminal['historyDigest'],receiptMap=terminal['receiptMap'])
        verified=verify_create_closure(certificate,public_key=r['intent'],expected=expected)
        receipts=verified['receiptMap']
        PreparationOwnerV3._reconcile_closed_create(r['preparation'],receipts)
        r['closure']=canonical(verified)
        r['state']='reconciled'
        return self.status()


    def _closed_phase_seal(self):
        r=_record(self)
        if (r['state']!='reconciled' or r.get('closure') is None
                or r['terminal'] is None or r['stop'] is None):reject()
        slot=r['slot'].status()
        if (slot['slotState']!='drained' or slot['slotRole']!='scene-create'
                or slot['creationOutcomeUnknown'] is not False or slot['slotGeneration']!=r['generation']
                or slot['writerOriginDigest']!=digest(r['origin'])):reject()
        return (r['closure'],r['terminal'],r['stop'],r['origin'],canonical(r['inputs']['daemonBinding']))

    def _capture_closed_phase(self,request_nonce,*,end=None):
        r=_record(self)
        if (not hex_value(request_nonce) or r['state']!='reconciled' or r.get('closure') is None
                or r['terminal'] is None or r['stop'] is None):reject()
        end=time.monotonic()+15 if end is None else end
        before=self._closed_phase_seal();closure=decode(r['closure'])
        phase,endpoint,version,baseline=PreparationOwnerV3._observe_closed_create_phase(
            r['preparation'],dict(closure['receiptMap']),end)
        if self._closed_phase_seal()!=before or time.monotonic()>=end:reject()
        endpoint_value=decode(endpoint)
        if canonical(endpoint_value['daemonBinding'])!=before[4]:reject()
        flags=('phaseFreshnessVerified','daemonContinuityVerified','writerQuiescenceVerified',
            'authorityGranted','executionAvailable','runtimePermit','recoveryAuthorized','productionReady','sourceRevalidated')
        summary=dict(schemaVersion=1,kind='scene-live-phase-summary-v3',requestNonce=request_nonce,
            closure=closure,phaseIndex=1,baselineDigest=baseline,phaseDigest=digest(phase),
            endpointBinding=endpoint_value,endpointBindingDigest=digest(endpoint),
            normalizationVersion=decode(version),readOnly=True,**{key:False for key in flags})

        return summary,phase,before

    def observe_closed_phase(self,request_nonce):
        summary,_,_=self._capture_closed_phase(request_nonce)
        return summary

    def observe_stopped_writer_phase(self, request_nonce, first_write, *, recovery_handoff=None, lease_generation=None):
        """Validate the exact first recovery write against the live original scene."""
        if not hex_value(request_nonce) or type(first_write) is not dict:reject()
        first_write = dict(first_write)
        end = time.monotonic() + 25
        seal = self._closed_phase_seal()
        origin = seal[3]
        origin_digest = digest(origin)
        inputs = _record(self)['inputs']
        hello = inputs['hello']
        closure = decode(seal[0])
        bundle = inputs['session'].prepared['bundle']
        operation = bundle.resolve_operations(closure['receiptMap'])[1]
        pinned = dict(historyDigest=closure['historyDigest'], slotGeneration=closure['slotGeneration'],
                      nextOperationDigest=operation['requestDigest'])
        observed_fields = ('phaseDigest', 'endpointBindingDigest')
        if (operation['phase'] != 'stop' or set(first_write) != set(pinned) | set(observed_fields)
                or canonical({key:first_write[key] for key in pinned}) != canonical(pinned)
                or any(not hex_value(first_write[key]) for key in observed_fields)):reject()
        if recovery_handoff is not None:
            from deployment_compose_scene_recovery_handoff_v3_host import check_expiry, verify
            record = _record(self)
            if 'recoveryHandoff' in record:reject()
            request = verify(recovery_handoff, public_key=record['intent'], scene_id=record['scene'],
                             nonce=request_nonce, first_write=first_write, original=inputs['session'].prepared['request'],
                             bundle=bundle, history=decode(seal[1])['history'])

        def observe():
            budget = min(5, end - time.monotonic())
            if budget <= 0:reject()
            result = observe_stopped_writer(origin, expected_digest=origin_digest,
                expected_source_sha=hello['sourceSha'], expected_archive_digest=hello['archiveDigest'],
                timeout=budget)
            if (result.writerStoppedObserved is not True or result.origin_digest != origin_digest
                    or not hex_value(result.observation_digest)):reject()
            return result.observation_digest

        stopped_before = observe()
        if self._closed_phase_seal() != seal:reject()
        summary, _, _ = self._capture_closed_phase(request_nonce, end=min(time.monotonic() + 15, end - 5))
        stopped_after = observe()
        if (stopped_before != stopped_after or self._closed_phase_seal() != seal
                or any(summary[key] != first_write[key] for key in observed_fields)
                or time.monotonic() >= end):reject()
        result = dict(phaseObservation=summary, writerOriginDigest=origin_digest,
                      writerStopObservationDigest=stopped_after, firstWriteBindingDigest=digest(canonical(first_write)))
        if recovery_handoff is not None:
            payload = recovery_handoff['payload']
            check_expiry(payload)
            request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=1800)
            if payload['writerStopObservationDigest'] != stopped_after or time.monotonic() >= end:reject()
            record['recoveryHandoff'] = canonical(dict(certificate=recovery_handoff, firstWrite=first_write))
            record['recoveryHandoffLease'] = lease_generation
            record['recoveryWorkerNonce'] = secrets.token_hex(32)
            result['recoveryHandoffDigest'] = digest(canonical(payload))
            result['recoveryWorkerNonce'] = record['recoveryWorkerNonce']
        return result

    def confirm_recovery_worker(self, proof, lease_generation, *, launch=False, relay=False, execute=False,
                                through_delete=False, full_recovery=False):
        from deployment_compose_scene_recovery_worker_v3_host import relay_terminal, verify_worker_proof

        record = _record(self)
        seal = self._closed_phase_seal()
        if (record.get('recoveryHandoffLease') != lease_generation
                or record.get('recoveryWorkerNonce') is None):reject()
        nonce = record.pop('recoveryWorkerNonce')
        if (any(type(mode) is not bool for mode in (launch, relay, execute, through_delete, full_recovery))
                or sum((launch, relay, execute)) > 1 or through_delete and not execute
                or full_recovery and not through_delete):reject()
        staged = decode(record['recoveryHandoff'])
        certificate = staged['certificate']
        handoff = certificate['payload']
        verified = verify_worker_proof(proof, handoff=handoff, nonce=nonce,
                                      intent_key=record['intent'], witness_key=record['witness'])
        if self._closed_phase_seal() != seal:reject()
        record['recoveryWorkerProofDigest'] = verified
        record['recoveryWorkerProof'] = canonical(proof)
        result = dict(workerProofDigest=verified, recoveryHandoffDigest=digest(canonical(handoff)))
        if launch:
            deadline = time.monotonic() + proof['intent']['payload']['expiresAt'] - time.time()
            startup = record['slot'].verify_recovery_startup(record['generation'], record['archive'],
                daemon_binding=decode(seal[4]), certificate=certificate, proof=proof, nonce=nonce,
                intent_key=record['intent'], witness_key=record['witness'], proof_digest=verified, deadline=deadline)
            record['recoveryWorkerStartup'] = canonical(startup)
            result['workerStartupDigest'] = digest(record['recoveryWorkerStartup'])
        elif relay or execute:
            deadline = time.monotonic() + proof['intent']['payload']['expiresAt'] - time.time()
            stop_context = None
            if execute:
                inputs = record['inputs']
                session = inputs['session']
                closure = decode(seal[0])
                if session.unknown_write_result:reject()
                stop_context = dict(capsule=base64.b64encode(inputs['capsule']).decode('ascii'),
                    hello=inputs['hello'], bootId=inputs['metadata']['observerFacts']['bootId'],
                    keys={key:base64.b64encode(value).decode('ascii') for key,value in inputs['keys'].items()},
                    policy=asdict(record['recoveryGatePolicy']), gateKey=base64.b64encode(record['recoveryGateKey']).decode('ascii'),
                    firstWrite=staged['firstWrite'], receiptMap=closure['receiptMap'], writerOrigin=decode(seal[3]),
                    version=decode(canonical(session.guard._version)), throughDelete=through_delete, fullRecovery=full_recovery)
                # No cleanup can infer ownership while a write result is uncertain.
                session.unknown_write_result = True
            unit, generation, channel_nonce = record['slot'].start_recovery_relay(
                record['generation'], record['archive'], daemon_binding=decode(seal[4]), certificate=certificate,
                proof=proof, nonce=nonce, intent_key=record['intent'], witness_key=record['witness'], deadline=deadline,
                stop_context=stop_context)
            attempt = secrets.token_hex(32)
            record['recoveryRelay'] = dict(state='active', unit=unit, process=unit._process, generation=generation,
                nonce=channel_nonce, attempt=attempt, slot=record['slot'], stop=None, pending=None, staged=None,
                terminal=None, buffer=bytearray(), stdout_eof=False, stderr_eof=False, last_rpc=0,
                relayTerminal=canonical(relay_terminal(channel_nonce, verified)))
            if execute:
                index = 4 if full_recovery else 2 if through_delete else 1
                operation = session.prepared['bundle'].resolve_operations(closure['receiptMap'])[index]
                record['recoveryRelay'].update(stopStatus=operation['expectedStatus'], proofDigest=verified,
                                               throughDelete=through_delete, fullRecovery=full_recovery)
            result['workerRelay'] = dict(attemptId=attempt, channelNonce=channel_nonce)
        return result

    def capture_closed_phase_snapshot(self,request_nonce):
        summary,raw,seal=self._capture_closed_phase(request_nonce)
        if type(raw) is not bytes or not 0<len(raw)<=MAX_MESSAGE:reject()
        value=decode(raw)
        if type(value) is not dict or set(value)!={'rows','resources'} or canonical(value)!=raw:reject()
        snapshot_id=secrets.token_hex(32)
        cache=dict(snapshotId=snapshot_id,phaseDigest=summary['phaseDigest'],raw=raw,seal=seal)
        if digest(raw)!=cache['phaseDigest'] or self._closed_phase_seal()!=seal:reject()
        _record(self)['phase_snapshot']=cache
        return dict(observation=summary,snapshotId=snapshot_id,totalBytes=len(raw),chunkBytes=4096)

    def read_closed_phase_chunk(self,snapshot_id,phase_digest,offset,length):
        r=_record(self);seal=self._closed_phase_seal();cache=r.get('phase_snapshot')
        if (not hex_value(snapshot_id) or not hex_value(phase_digest) or cache is None
                or cache['snapshotId']!=snapshot_id or cache['phaseDigest']!=phase_digest
                or cache['seal']!=seal or type(offset) is not int or type(length) is not int
                or not 0<length<=4096):reject()
        raw=cache['raw']
        if (type(raw) is not bytes or not 0<len(raw)<=MAX_MESSAGE or not 0<=offset<len(raw)
                or digest(raw)!=phase_digest):reject()
        return dict(snapshotId=snapshot_id,phaseDigest=phase_digest,totalBytes=len(raw),offset=offset,
            dataBase64=base64.b64encode(raw[offset:offset+length]).decode('ascii'))
