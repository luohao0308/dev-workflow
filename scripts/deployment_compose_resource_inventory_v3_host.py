"""Fixed GET inventory projection, not a cleanup or authorization capability."""
import re

CONTAINERS='/v1.45/containers/json?all=true'
IMAGES='/v1.45/images/json?all=true'
NETWORKS='/v1.45/networks'
VOLUMES='/v1.45/volumes'
PATHS=frozenset((CONTAINERS,IMAGES,NETWORKS,VOLUMES))


def reject():raise ValueError('compose-resource-inventory-v3-rejected') from None


def _items(value,key,pattern):
    if type(value) is not list or len(value)>512:reject()
    result=[]
    for row in value:
        if (type(row) is not dict or type(row.get(key)) is not str
                or not re.fullmatch(pattern,row[key])):reject()
        result.append(row[key])
    if len(set(result))!=len(result):reject()
    return sorted(result)


def inventory(read_json):
    """Only the observer's bound reader is used by the manager, never caller data."""
    containers=_items(read_json(CONTAINERS),'Id','[0-9a-f]{64}')
    images=_items(read_json(IMAGES),'Id','sha256:[0-9a-f]{64}')
    networks=_items(read_json(NETWORKS),'Id','[0-9a-f]{64}')
    volumes=read_json(VOLUMES)
    if (type(volumes) is not dict or 'Volumes' not in volumes or 'Warnings' not in volumes
            or volumes['Warnings'] is not None and volumes['Warnings']!=[]):reject()
    names=_items(volumes['Volumes'],'Name','[A-Za-z0-9][A-Za-z0-9_.-]{0,254}')
    return dict(containers=containers,images=images,networks=networks,volumes=names)
