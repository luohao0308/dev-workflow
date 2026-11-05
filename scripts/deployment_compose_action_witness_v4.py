"""Independent single-action witness. Accounting is not a Docker capability.

Private directory and HMAC key remain outside the actor. A persisted admitted
state never returns to prepared, including after acknowledgement loss.
"""
import base64
from copy import deepcopy
import hashlib
import hmac
import json
import os

from deployment_compose_witness_store import ComposeWitnessStore,canonical,pairs,hex_value,ZERO

DOMAIN=b'dev-workflow:compose-action-witness:v4\0'
HEAD_DOMAIN=b'dev-workflow:compose-action-event:v4\0'
BINDING={'requestHash','contextDigest','actionDigest','sessionHash','actorEpoch','supervisorBoot'}


def reject():raise ValueError('action-witness-v4-rejected')


class ActionWitnessStoreV4(ComposeWitnessStore):
    def _seal(self,state):
        return canonical(dict(state=state,hmac=hmac.new(self._key,DOMAIN+canonical(state),hashlib.sha256).hexdigest()))

    def _read(self):
        fd=os.open('state.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._dir)
        try:
            self._file_id(fd)
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(196609)
        finally:os.close(fd)
        if len(raw)>196608:reject()
        value=json.loads(raw,object_pairs_hook=pairs)
        if type(value) is not dict or set(value)!={'state','hmac'}:reject()
        state=value['state']
        if (type(state) is not dict or set(state)!={'schemaVersion','kind','binding','events'}
                or type(state['schemaVersion']) is not int or state['schemaVersion']!=4
                or state['kind']!='single-create-action-witness-v4' or not hmac.compare_digest(raw,self._seal(state))):reject()
        self._validate_binding(state['binding'])
        events=state['events']
        if type(events) is not list or not 1<=len(events)<=3:reject()
        previous=ZERO
        for index,event in enumerate(events):
            if (type(event) is not dict or set(event)!={'kind','data','head'}
                    or event['kind']!=('prepared','admitted','response')[index]
                    or event['head']!=hashlib.sha256(HEAD_DOMAIN+previous.encode('ascii')+canonical(
                        dict(kind=event['kind'],data=event['data']))).hexdigest()):reject()
            previous=event['head']
        return state

    @staticmethod
    def _validate_binding(binding):
        if type(binding) is not dict or set(binding)!=BINDING or any(not hex_value(v) for v in binding.values()):reject()

    @staticmethod
    def _cursor(state):return dict(seq=len(state['events']),head=state['events'][-1]['head'])

    @staticmethod
    def _append(state,kind,data):
        previous=state['events'][-1]['head'] if state['events'] else ZERO
        event=dict(kind=kind,data=deepcopy(data))
        event['head']=hashlib.sha256(HEAD_DOMAIN+previous.encode('ascii')+canonical(event)).hexdigest()
        state['events'].append(event)

    def read(self):
        with self._locked():return deepcopy(self._read())

    def register_once(self,binding):
        self._validate_binding(binding)
        with self._locked():
            if 'state.json' in os.listdir(self._dir):reject()
            state=dict(schemaVersion=4,kind='single-create-action-witness-v4',binding=deepcopy(binding),events=[])
            self._append(state,'prepared',{})
            self._persist(state)
            return self._cursor(state)

    def admit(self,cursor,*,host,authorization):
        # The only issuing host is the actual composite gate. A caller dict or
        # diagnostic witness event cannot satisfy its live identity registry.
        from deployment_compose_action_host_v4 import SingleActionHostV4
        if type(host) is not SingleActionHostV4:reject()
        with self._locked():
            state=self._read()
            if self._cursor(state)!=cursor or canonical(self._cursor(state))!=canonical(cursor) or len(state['events'])!=1:reject()
            facts=host._authorization_for_witness(authorization,self,state['binding'])
            self._append(state,'admitted',facts)
            self._persist(state)
            return self._cursor(state)

    def record_response(self,cursor,*,host,response_evidence):
        from deployment_compose_action_host_v4 import SingleActionHostV4
        if type(host) is not SingleActionHostV4:reject()
        with self._locked():
            state=self._read()
            if len(state['events'])!=2 or canonical(self._cursor(state))!=canonical(cursor):reject()
            data=host._response_for_witness(response_evidence,self,state['binding'],cursor)
            if (type(data) is not dict or set(data)!={'status','bodyBase64'}
                    or type(data['status']) is not int or not 100<=data['status']<=599):reject()
            body=base64.b64decode(data['bodyBase64'],validate=True)
            if len(body)>65536:reject()
            self._append(state,'response',data)
            self._persist(state)
            return self._cursor(state)

    def reserve(self,*args,**kwargs):reject()
