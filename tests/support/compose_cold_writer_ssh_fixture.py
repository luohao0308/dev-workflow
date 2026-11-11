"""Actual pipes and fixed worker; Linux/proc/cgroup are explicit doubles."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),*(str(ROOT/p) for p in
    ('scripts','packs/deployment/scripts','packs/release/scripts'))]
import deployment_compose_cold_writer_ssh_v3_host as bridge
import deployment_compose_cold_writer_v3_host as cold
from deployment_compose_v3_channel_worker import read_frame,write_frame
from deployment_compose_witness_store import canonical


def main(mode):
    config=read_frame(sys.stdin.buffer)
    archive=base64.b64decode(config.pop('archiveBase64'),validate=True)
    assert hashlib.sha256(archive).hexdigest()==config['archiveDigest']
    if mode=='hang':time.sleep(3);return
    source=config['origin']
    snapshot=dict(namespace=[source['pidNamespaceDevice'],source['pidNamespaceInode']],
        boot=source['kernelBoot'],unit=dict(LoadState='not-found',ActiveState='inactive',SubState='dead',
            MainPID='0',ControlGroup='',InvocationID='',Delegate='no'),tree=None)
    def observe(raw,**kwargs):
        assert raw==canonical(source)
        assert kwargs['expected_source_sha']==config['producerSourceSha']
        assert kwargs['expected_archive_digest']==config['producerArchiveDigest']
        material=canonical([snapshot,snapshot])
        return cold.StoppedWriterObservationV3(config['originDigest'],hashlib.sha256(material).hexdigest(),material)
    def output(stream,value,**kwargs):
        reply=copy.deepcopy(value)
        edits={'nonce':('channelNonce','0'*64),'host':('hostId','wrong-host'),
            'verifier-source':('verifierSourceSha','0'*40),'verifier-archive':('verifierArchiveDigest','0'*64),
            'producer-source':('producerSourceSha','0'*40),'producer-archive':('producerArchiveDigest','0'*64),
            'request':('requestDigest','0'*64),'origin':('originDigest','0'*64),
            'observation-hash':('observationDigest','0'*64),'bool':('writerStoppedObserved',1),
            'authority':('authorityGranted',True),'bound':('checkpointBound',False)}
        if mode in edits:
            key,value=edits[mode];reply[key]=value
        if mode=='checkpoint':reply['checkpointBinding']=dict(reply['checkpointBinding'],historyDigest='0'*64)
        if mode=='extra-field':reply['unknown']=True
        if mode in ('boot','namespace','active','populated','tree-inode','unequal'):
            a=reply['observations'][0]
            if mode=='boot':a['boot']='22222222-2222-2222-2222-222222222222'
            if mode=='namespace':a['namespace'][1]+=1
            if mode=='active':a['unit'].update(LoadState='loaded',ActiveState='active',SubState='running',MainPID=str(source['mainPid']))
            if mode in ('populated','tree-inode'):
                a['tree']=dict(device=source['cgroupDevice'],inode=source['cgroupInode']+(mode=='tree-inode'),
                    files={'cgroup.type':'domain\n','cgroup.events':'populated '+('1' if mode=='populated' else '0')+'\nfrozen 0\n','cgroup.procs':''},children=[])
            if mode!='unequal':reply['observations'][1]=copy.deepcopy(a)
            else:reply['observations'][1]['boot']='22222222-2222-2222-2222-222222222222'
            reply['observationDigest']=hashlib.sha256(canonical(reply['observations'])).hexdigest()
        if mode=='partial':
            import struct
            raw=canonical(reply);os.write(stream.fileno(),struct.pack('!I',len(raw))+raw[:10]);return
        if mode=='oversized':
            import struct
            os.write(stream.fileno(),struct.pack('!I',65537));return
        write_frame(stream,reply,**kwargs)
        if mode=='extra-output':write_frame(stream,dict(kind='extra'))
        if mode=='warning':sys.stderr.write('fixture warning\n');sys.stderr.flush()
        if mode=='held-stderr':
            subprocess.Popen([sys.executable,'-c','import time;time.sleep(.8)'],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=sys.stderr,close_fds=True)
    with patch.object(cold,'observe_stopped_writer',side_effect=observe), \
         patch.object(bridge,'write_frame',side_effect=output):
        bridge.run(config,sys.stdin.buffer,sys.stdout.buffer)
    if mode=='nonzero':raise SystemExit(7)


def reader_consume(descriptor):
    from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3
    archive=b'fixture-verifier-source'
    case=Path(descriptor['casePath']);before=(case/'witness/state.json').read_bytes()
    def spawn(argv):
        return subprocess.Popen([sys.executable,'-u',__file__,'good'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    with RestartCheckpointReaderV3(case,expected_material_digest=descriptor['materialDigest'],
            expected_custody_digest=descriptor['custodyDigest'],expected_context=descriptor['context'],
            expected_witness_key_hash=descriptor['witnessKeyHash'],
            expected_origin_material_digest=descriptor['writerOriginMaterialDigest'],
            expected_origin_digest=descriptor['writerOriginDigest']) as reader, \
         patch.object(bridge,'published_cold_archive',return_value=archive), \
         patch.object(bridge,'_private_spawn',side_effect=spawn):
        result=reader.observe_writer_stopped(verifier_source_sha='e'*40)
    assert before==(case/'witness/state.json').read_bytes()
    return dict(consumerPid=os.getpid(),summary=result.public_summary(),witnessUnchanged=True,
        newApprovalConsumptions=0,engineRequests=0,executionRecovered=False)


if __name__=='__main__':
    if sys.argv[1]=='reader-consume':print(json.dumps(reader_consume(json.load(sys.stdin))),flush=True)
    else:main(sys.argv[1])
