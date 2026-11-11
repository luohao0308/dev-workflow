"""Read-only same-image frontend reconstruction values; never execution authority.

The caller independently pins private snapshots. A digest match proves byte
identity, not native observation freshness, enrollment, image provenance or
approval. The returned body may contain secrets and must remain private.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'packs/deployment/scripts'))
from deployment_compose_config import map_config
from deployment_compose_host_config import map_host_config
from deployment_compose_image_defaults import INERT, ZERO_DEFAULTS
from deployment_compose_recipe import NAME, IMAGE, HEX, ENV_NAME

IDENTITY={'hostId','daemonId','project','service','containerId','containerName','imageId','sourceSha'}
ROW={'Id','Name','Image','Config','HostConfig','Mounts','NetworkSettings','RestartCount','State'}
BLOCKERS=('production-worker-not-enrolled','scope-writer-exclusion-not-established','fresh-exact-approval-required','engine-reconstruction-not-verified')


def reject():
    raise ValueError('production-frontend-plan-rejected') from None


def _encode(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(raw)>1024*1024:reject()
    return raw


def snapshot_digest(row,image,protected_container_ids):
    return hashlib.sha256(_encode(dict(row=row,image=image,protectedContainerIds=protected_container_ids))).hexdigest()


def _inheritance(config,image):
    defaults=image['Config']
    if type(defaults) is not dict or set(defaults)-set(INERT)-set(ZERO_DEFAULTS):reject()
    for field,value in defaults.items():
        if field=='ArgsEscaped':
            if type(value) is not bool:reject()
        elif field in INERT and (type(value) is not type(INERT[field]) or value!=INERT[field]):reject()
    for field,value in defaults.items():
        if field in INERT:continue
        if field in ('User','WorkingDir','StopSignal'):
            if type(value) is not str or len(value)>8192 or '\0' in value:reject()
        elif field in ('Env','Entrypoint','Cmd'):
            if value is not None and (type(value) is not list or len(value)>128 or any(type(x) is not str or len(x)>8192 or '\0' in x for x in value)):reject()
        elif value is not None:
            if type(value) is not dict or len(value)>128:reject()
            if field=='Labels' and any(type(k) is not str or not k or len(k)>1024 or '\0' in k or type(v) is not str or len(v)>8192 or '\0' in v for k,v in value.items()):reject()
            if field=='ExposedPorts' and any(type(k) is not str or re.fullmatch(r'[1-9][0-9]{0,4}/(?:tcp|udp)',k) is None or int(k.split('/')[0])>65535 or type(v) is not dict or v!={} for k,v in value.items()):reject()
            if field=='Healthcheck':
                if set(value)-{'Test','Interval','Timeout','Retries','StartPeriod','StartInterval'}:reject()
                if 'Test' in value and (type(value['Test']) is not list or not value['Test'] or len(value['Test'])>32 or value['Test'][0] not in ('CMD','CMD-SHELL','NONE') or any(type(x) is not str or len(x)>1024 or '\0' in x for x in value['Test'])):reject()
                if 'Test' in value:
                    test=value['Test']
                    if (test[0]=='NONE' and len(test)!=1 or test[0]=='CMD-SHELL' and len(test)!=2 or test[0]=='CMD' and len(test)<2):reject()
                if any(type(v) is not int or not 0<=v<=(20 if k=='Retries' else 60_000_000_000) for k,v in value.items() if k!='Test'):reject()
    if defaults.get('Volumes') not in (None,{}) or defaults.get('StopSignal','')!='':reject()
    for field in ('User','WorkingDir'):
        if defaults.get(field) and not config[field]:reject()
    for field in ('Entrypoint','Cmd'):
        if defaults.get(field) and not config[field]:reject()
    env=config['Env'];names={x.partition('=')[0] for x in env}
    inherited=defaults.get('Env')
    if inherited is not None:
        if type(inherited) is not list or any(type(x) is not str or '=' not in x for x in inherited):reject()
        image_names=[x.partition('=')[0] for x in inherited]
        if any(not ENV_NAME.fullmatch(name) for name in image_names):reject()
        if len(image_names)!=len(set(image_names)) or not set(image_names)<=names:reject()
    for field in ('Labels','ExposedPorts','Healthcheck'):
        value=defaults.get(field)
        if value is not None and (type(value) is not dict or not set(value)<=set(config.get(field) or {})):reject()


def prepare_frontend_plan(row,image,*,expected_identity,expected_snapshot_digest,network_ids,protected_container_ids):
    """Pin and compare observed values without issuing a production request."""
    try:
        original=snapshot_digest(row,image,protected_container_ids)
        row,image,identity,nets,protected=deepcopy((row,image,expected_identity,network_ids,protected_container_ids))
        if original!=expected_snapshot_digest or not HEX.fullmatch(expected_snapshot_digest):reject()
        if type(identity) is not dict or set(identity)!=IDENTITY:reject()
        for key in ('hostId','project','service','containerName'):
            if type(identity[key]) is not str or not NAME.fullmatch(identity[key]):reject()
        if identity['service']!='frontend' or not re.fullmatch('[0-9a-f]{40}',identity['sourceSha']):reject()
        if type(identity['daemonId']) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}',identity['daemonId']):reject()
        if not HEX.fullmatch(identity['containerId']) or not IMAGE.fullmatch(identity['imageId']):reject()
        if type(row) is not dict or set(row)!=ROW or type(image) is not dict or set(image)!={'Id','Os','Architecture','Config'}:reject()
        if (row['Id']!=identity['containerId'] or row['Image']!=identity['imageId'] or row['Name']!='/'+identity['containerName']
                or image['Id']!=identity['imageId'] or image['Os']!='linux' or image['Architecture'] not in ('amd64','arm64')):reject()
        state=row['State']
        if any(state.get(k) is not False for k in ('Paused','Restarting','Dead')) or state.get('Running') is not True or state.get('Status')!='running' or state.get('Health',{}).get('Status')!='healthy':reject()
        if type(protected) is not list or len(protected)>32 or protected!=sorted(set(protected)) or row['Id'] in protected or any(type(x) is not str or not HEX.fullmatch(x) for x in protected):reject()
        context={key:identity[key] for key in ('project','service','containerId','containerName','imageId')}
        validated_config=deepcopy(row['Config']);validated_host=deepcopy(row['HostConfig'])
        validated_config['Healthcheck'].setdefault('StartPeriod',0)
        validated_host.setdefault('Tmpfs',{})
        map_config(validated_config,context);map_host_config(validated_host,context)
        if image['Config'].get('Labels',{}).get('org.opencontainers.image.revision')!=identity['sourceSha']:reject()
        if row['Mounts'] or row['Config']['Volumes'] not in (None,{}) or row['HostConfig'].get('Mounts') not in (None,[]):reject()
        host=row['HostConfig']
        if host['Privileged'] or host['AutoRemove'] or host['PublishAllPorts'] or host['PortBindings'] or host['Binds'] or host['VolumesFrom'] or host['Devices'] or host['CapAdd']:reject()
        if host['PidMode'] not in ('','private') or host['IpcMode']!='private' or host['NetworkMode'] not in nets:reject()
        if host['RestartPolicy'] not in ({'Name':'unless-stopped','MaximumRetryCount':0},{'Name':'no','MaximumRetryCount':0}):reject()
        if host['LogConfig']!={'Type':'json-file','Config':{'max-file':'3','max-size':'10m'}}:reject()
        if type(nets) is not dict or len(nets)!=1 or set(row['NetworkSettings']['Networks'])!=set(nets):reject()
        endpoints={}
        for name,nid in nets.items():
            if not NAME.fullmatch(name) or not HEX.fullmatch(nid):reject()
            observed=row['NetworkSettings']['Networks'][name];aliases=observed['Aliases']
            allowed={'IPAMConfig','Links','Aliases','NetworkID','EndpointID','Gateway','IPAddress','MacAddress','IPPrefixLen','IPv6Gateway','GlobalIPv6Address','GlobalIPv6PrefixLen','DriverOpts','DNSNames','GwPriority'}
            if type(observed) is not dict or set(observed)-allowed:reject()
            if observed.get('IPAMConfig') not in (None,{}) or observed.get('Links') not in (None,[]) or observed.get('DriverOpts') not in (None,{}):reject()
            if 'GwPriority' in observed and (type(observed['GwPriority']) is not int or observed['GwPriority']!=0):reject()
            if observed['NetworkID']!=nid or type(aliases) is not list or len(aliases)>32 or any(type(x) is not str or not NAME.fullmatch(x) for x in aliases):reject()
            endpoints[name]={'NetworkID':nid,'Aliases':deepcopy(aliases)}
        _inheritance(row['Config'],image)
        body=deepcopy(row['Config']);body['Image']=identity['imageId'];body['HostConfig']=deepcopy(host)
        body['NetworkingConfig']={'EndpointsConfig':endpoints}
        if 'ArgsEscaped' in image['Config']:body['ArgsEscaped']=image['Config']['ArgsEscaped']
        body_digest=hashlib.sha256(_encode(body)).hexdigest()
        if snapshot_digest(row,image,protected)!=original:reject()
        review=dict(identity=identity,snapshotDigest=original,bodyDigest=body_digest,protectedContainerIds=protected,
            sameImage=True,selectedServices=['frontend'],representabilityChecked=True,engineReconstructionVerified=False,
            freshnessVerified=False,authorityGranted=False,runtimePermit=False,executionAvailable=False,productionReady=False,
            executionBlockedReasons=list(BLOCKERS)+(['image-args-escaped-reconstruction-unverified'] if image['Config'].get('ArgsEscaped') else []))
        return dict(privateBody=body,publicReview=review)
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError,RecursionError):
        reject()
