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


def inventory(read_json, *, include_definitions=False):
    """Only the observer's bound reader is used by the manager, never caller data."""
    containers=_items(read_json(CONTAINERS),'Id','[0-9a-f]{64}')
    images=_items(read_json(IMAGES),'Id','sha256:[0-9a-f]{64}')
    network_rows=read_json(NETWORKS)
    networks=_items(network_rows,'Id','[0-9a-f]{64}')
    volumes=read_json(VOLUMES)
    if (type(volumes) is not dict or 'Volumes' not in volumes or 'Warnings' not in volumes
            or volumes['Warnings'] is not None and volumes['Warnings']!=[]):reject()
    names=_items(volumes['Volumes'],'Name','[A-Za-z0-9][A-Za-z0-9_.-]{0,254}')
    result=dict(containers=containers,images=images,networks=networks,volumes=names)
    if include_definitions:
        result['networkDefinitions']={row['Id']:row for row in network_rows}
        result['volumeDefinitions']={
            row['Name']: {key:value for key,value in row.items() if key!='UsageData'}
            for row in volumes['Volumes']
        }
    return result
