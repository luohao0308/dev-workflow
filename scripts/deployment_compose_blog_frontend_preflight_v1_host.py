"""Read-only SSH preparation for the fixed luohao-blog frontend target.

This command never sends Docker writes, authorizes a request, or starts a worker.
Private captures/plans remain on the controller, outside the source checkout.
"""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time

from deployment_compose_production_frontend_v3_host import prepare_frontend_plan, snapshot_digest

_REMOTE_CAPTURE = r'''import subprocess,json

def get(args):
 return subprocess.run(args,capture_output=True,text=True,check=True,timeout=15).stdout
allowed={'NUXT_PUBLIC_SITE_URL','NUXT_PUBLIC_CHAT_MASCOT_SRC','NUXT_BACKEND_BASE','NUXT_PUBLIC_ICP_NUMBER','PATH','NODE_VERSION','YARN_VERSION','NODE_ENV'}
def inspect():
 return json.loads(get(['docker','inspect','--format','{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"Config":{{json .Config}},"HostConfig":{{json .HostConfig}},"Mounts":{{json .Mounts}},"NetworkSettings":{{json .NetworkSettings}},"RestartCount":{{json .RestartCount}},"State":{"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}},"Running":{{json .State.Running}},"Paused":{{json .State.Paused}},"Restarting":{{json .State.Restarting}},"Dead":{{json .State.Dead}},"Status":{{json .State.Status}},"Health":{"Status":{{json .State.Health.Status}}}}}','blog-frontend']))
def protected(cid):
 return sorted(x for x in get(['docker','ps','-a','--no-trunc','--format','{{.ID}}']).splitlines() if x!=cid)
row=inspect();daemon=json.loads(get(['docker','info','--format','{{json .ID}}']))
assert {x.partition('=')[0] for x in row['Config']['Env']}<=allowed
image=json.loads(get(['docker','image','inspect','--format','{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"Config":{{json .Config}}}',row['Image']]))
assert {x.partition('=')[0] for x in image['Config'].get('Env',[])}<=allowed
others=protected(row['Id'])
assert inspect()==row and protected(row['Id'])==others
assert json.loads(get(['docker','info','--format','{{json .ID}}']))==daemon
payload=json.dumps(dict(daemonId=daemon,row=row,image=image,protectedContainerIds=others),sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
assert len(payload)<=1048576
import sys
sys.stdout.buffer.write(payload)
'''


def reject():
    raise ValueError('blog-frontend-preflight-rejected') from None


def capture(alias):
    if type(alias) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',alias):
        reject()
    argv=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',
          '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ForwardX11=no',
          '-o','PermitLocalCommand=no',alias,'python3 -I -S -']
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    deadline=time.monotonic()+90
    result=bytearray();errors=bytearray()
    try:
        # The fixed source is small enough for the pipe; no configuration/code is
        # accepted from a project file or interpolated into the remote command.
        process.stdin.write(_REMOTE_CAPTURE.encode('ascii'));process.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ,(result,1048576))
            selector.register(process.stderr,selectors.EVENT_READ,(errors,4096))
            while selector.get_map():
                left=deadline-time.monotonic()
                if left<=0:reject()
                ready=selector.select(left)
                if not ready:reject()
                for key,_ in ready:
                    target,bound=key.data
                    data=os.read(key.fileobj.fileno(),min(65536,bound+1-len(target)))
                    if not data:selector.unregister(key.fileobj);continue
                    target.extend(data)
                    if len(target)>bound:reject()
        if process.wait(timeout=max(.001,deadline-time.monotonic()))!=0:reject()
        return json.loads(result)
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        for stream in (process.stdin,process.stdout,process.stderr):stream.close()


def prepare_capture(value,pins):
    if (type(value) is not dict or set(value)!={'daemonId','row','image','protectedContainerIds'}
            or type(pins) is not dict or value['daemonId']!=pins.get('daemonId')
            or pins.get('project')!='luohao-blog-prod' or pins.get('service')!='frontend'
            or pins.get('containerName')!='blog-frontend'):
        reject()
    row=value['row'];protected=value['protectedContainerIds']
    networks={name:net['NetworkID'] for name,net in row['NetworkSettings']['Networks'].items()}
    return prepare_frontend_plan(row,value['image'],expected_identity=pins,
        expected_snapshot_digest=snapshot_digest(row,value['image'],protected),
        network_ids=networks,protected_container_ids=protected)


def save_private(root,values):
    root=Path(root)
    if (not root.is_absolute() or any(p.is_symlink() for p in (root,*root.parents))
            or root.resolve().is_relative_to(Path(__file__).resolve().parents[1])):
        reject()
    root.mkdir(mode=0o700)
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        original=os.fstat(directory)
        def check():
            current=os.stat(root,follow_symlinks=False)
            if (not stat.S_ISDIR(current.st_mode) or current.st_uid!=os.getuid()
                    or stat.S_IMODE(current.st_mode)!=0o700
                    or (current.st_dev,current.st_ino)!=(original.st_dev,original.st_ino)):
                reject()
        check()
        for name,value in values.items():
            if name not in ('capture.private.json','plan.private.json','review.json'):reject()
            raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
            if len(raw)>1048576:reject()
            check()
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as output:
                output.write(raw);output.flush();os.fsync(output.fileno())
            check()
        os.fsync(directory);check()
    finally:
        os.close(directory)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-alias',default='xterminal-server')
    parser.add_argument('--pins',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    pins=json.loads(args.pins.read_bytes());value=capture(args.ssh_alias);plan=prepare_capture(value,pins)
    save_private(args.output,{'capture.private.json':value,'plan.private.json':plan,'review.json':plan['publicReview']})
    print(json.dumps(dict(reviewPath=str(args.output/'review.json'),bodyDigest=plan['publicReview']['bodyDigest'],
                         executionAvailable=False,productionWrites=0)))
