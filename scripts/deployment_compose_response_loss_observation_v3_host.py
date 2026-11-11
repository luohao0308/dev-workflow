"""Bounded fixed-worker observations; never an Engine commit or authority proof."""
import hashlib
import json
import re

from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_recovery_profiles_v3_host import RESPONSE_LOSS_MARKER

KIND='diagnostic-observation'
FIELDS={'schemaVersion','diagnosticProfile','sourceSha','archiveDigest','hostId',
    'root','daemonId','requestHash','method','pathSha256','bodySha256','attempts',
    'requestReturned','responseSuppressed','originalResponseRead','engineOutcome',
    'authorityGranted','runtimePermit','productionReady'}


def reject():
    raise ValueError('compose-response-loss-observation-v3-rejected') from None


def validate_observation(value):
    if type(value) is not dict or set(value)!=FIELDS:reject()
    if (type(value['schemaVersion']) is not int or value['schemaVersion']!=1
            or type(value['diagnosticProfile']) is not str or value['diagnosticProfile']!=RESPONSE_LOSS_MARKER
            or type(value['attempts']) is not int or value['attempts']!=1
            or type(value['method']) is not str or value['method']!='POST'
            or type(value['engineOutcome']) is not str or value['engineOutcome']!='unknown'):reject()
    for key in ('sourceSha','archiveDigest','requestHash','pathSha256','bodySha256'):
        size=40 if key=='sourceSha' else 64
        if type(value[key]) is not str or not re.fullmatch('[0-9a-f]{'+str(size)+'}',value[key]):reject()
    if (type(value['hostId']) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',value['hostId'])
            or type(value['root']) is not str or not re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}',value['root'])
            or type(value['daemonId']) is not str or not 0<len(value['daemonId'])<=256):reject()
    for key in ('requestReturned','responseSuppressed'):
        if value[key] is not True:reject()
    for key in ('originalResponseRead','authorityGranted','runtimePermit','productionReady'):
        if value[key] is not False:reject()
    return json.loads(encode(value))


def observation_digest(value):
    return hashlib.sha256(encode(validate_observation(value))).hexdigest()
