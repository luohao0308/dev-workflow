"""Real service Unix protocol; daemon creation and peer credentials are doubles."""
import json,os,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),*(str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts'))]
import deployment_compose_scene_service_v3_host as scene
base=Path(sys.argv[2]);scene.BASE=base;scene.ROOT_UID=os.getuid();scene._peer=lambda sock:(os.getpid(),os.getuid(),os.getgid());scene.units._environment=lambda:None
if sys.argv[1]=='serve':
    marker=Path(sys.argv[4]);delay=float(sys.argv[5]) if len(sys.argv)>5 else 0
    scene.LEASE_SECONDS=float(sys.argv[6]) if len(sys.argv)>6 else 30
    if len(sys.argv)>7:
        rename=os.rename
        def delayed(source,target,**kwargs):
            if target=='ready-marker':time.sleep(float(sys.argv[7]))
            return rename(source,target,**kwargs)
        scene.os.rename=delayed
    class Observer:
        daemon_id='fixture-daemon'
        def binding(self):return dict(root='/var/tmp/dw-engine-'+'a'*16,daemonId='fixture-daemon')
    class Owner:
        def __init__(self):self.observer=Observer();self.result=None
        def start(self,**kwargs):return self.observer
        def stop(self,**kwargs):
            if self.result is not None:return self.result
            time.sleep(delay);marker.write_text('stopped')
            self.result=dict(daemonStoppedVerified=True,productionSnapshotUnchanged=True,authorityGranted=False,runtimePermit=False,productionReady=False)
            return self.result
        def close(self):return self.stop()
    import deployment_compose_scene_writer_slot_v3_host as slots
    from tests.test_deployment_compose_scene_writer_slot_v3_host import FakeUnit
    from types import SimpleNamespace
    if len(sys.argv)>8 and sys.argv[8]=='fail-drain':FakeUnit.fail_stop=True
    slots.OwnedRecoveryUnitV3=FakeUnit
    slots.observe_stopped_writer=lambda *a,**kw:SimpleNamespace(writerStoppedObserved=True,observation_digest='c'*64)
    scene.OwnedRecoveryDaemonHostV3=Owner
    scene.serve(sys.argv[3])
elif sys.argv[1]=='client':
    scene_id=sys.argv[3];key=(base/scene_id/'control.key').read_bytes()
    client=scene.SceneClientV3(scene.SceneHandleV3(scene_id,str(base/scene_id/'control.sock'),key))
    print(json.dumps(client.status()),flush=True)
    while True:time.sleep(1)
else:raise ValueError('fixture-mode')
