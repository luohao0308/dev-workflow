"""Offline create candidates never grant permission or establish reconstruction."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from tests.test_deployment_compose_recipe_v3 import value
from deployment_compose_create import compile_create, DOMAIN


def fixture():
    recipe = value()
    recipe['hostConfig']['logConfig'] = {'type': 'none', 'config': {}}
    recipe['ports'] = []
    return recipe, dict(baseline_image_id=recipe['imageId'],
        image_defaults={'ImageId': recipe['imageId'], 'Os': 'linux', 'Architecture': 'amd64', 'Env': ['API_KEY=image-default'], 'Labels': None,
            'Volumes': None, 'ExposedPorts': None, 'Healthcheck': None,
            'User': '', 'WorkingDir': '', 'Entrypoint': ['/image-entry'], 'Cmd': ['image-cmd'], 'StopSignal': ''},
        identity=dict(hostId='host-one', daemonId='daemon-one',project='blog',service='web',containerName='blog-web-1'),
        network_ids={'blog_default': recipe['networks'][0]['id']}, allowed_mounts=deepcopy(recipe['mounts']),
        hostname='approved-hostname')


class CreateTests(unittest.TestCase):
    def test_concrete_flat_payload_pins_resources_network_and_mounts(self):
        recipe, args = fixture()
        result = compile_create(recipe, **args)
        body = result['body']
        self.assertNotIn('Config', body)
        self.assertEqual(body['Image'], recipe['imageId'])
        self.assertEqual(body['Entrypoint'], recipe['process']['entrypoint'])
        self.assertEqual(body['Env'], recipe['process']['env'])
        self.assertEqual(body['HostConfig']['Memory'], 67108864)
        self.assertEqual(body['HostConfig']['PidMode'], '')
        self.assertEqual(body['HostConfig']['IpcMode'], 'private')
        self.assertEqual(body['HostConfig']['Mounts'][0]['VolumeOptions'], {'NoCopy': True})
        self.assertFalse(body['HostConfig']['Mounts'][1]['BindOptions']['CreateMountpoint'])
        endpoint = body['NetworkingConfig']['EndpointsConfig']['blog_default']
        self.assertEqual(endpoint, {'NetworkID': 'b' * 64, 'Aliases': ['web']})
        for field in ('authorityGranted','executionAvailable','reconstructionValidated','productionReady'):
            self.assertIs(result[field], False)
        self.assertIn('daemon-defaults-verification-required',result['validationBlockers'])
        digest = result.pop('candidateDigest')
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
        self.assertEqual(digest,hashlib.sha256(DOMAIN+raw).hexdigest())

    def test_image_change_implicit_commands_topology_and_publication_rejected(self):
        for mutate in (lambda r,a: a.update(baseline_image_id='sha256:'+'f'*64),
                       lambda r,a: r['process'].update(entrypoint=[]),
                       lambda r,a: r['process'].update(cmd=[]),
                       lambda r,a: r['process'].update(entrypoint=['']),
                       lambda r,a: a.update(network_ids={'other':'f'*64}),
                       lambda r,a: a.update(allowed_mounts=[]),
                       lambda r,a: r['ports'].append({'hostIp':'127.0.0.1','hostPort':18080,'containerPort':8080,'protocol':'tcp'}),
                       lambda r,a: a['identity'].update(service='other'),
                       lambda r,a: a.update(hostname='bad/hostname')):
            recipe,args=fixture();mutate(recipe,args)
            with self.subTest(mutate=mutate),self.assertRaisesRegex(ValueError,'^invalid-compose-create-candidate$'):
                compile_create(recipe,**args)

    def test_image_default_merge_hazards_rejected(self):
        for field,value_ in [('ImageId','sha256:'+'f'*64),('Os','windows'),('Architecture','unknown'),('Env',['OTHER=unapproved']),
            ('Env',['API_KEY=x','API_KEY=y']),('Labels',{'custom':'image-value'}),
            ('Volumes',{'/implicit':{}}),('ExposedPorts',{'80/tcp':{}}),
            ('Healthcheck',{'StartPeriod':1}),('StopSignal','SIGKILL')]:
            recipe,args=fixture();args['image_defaults'][field]=value_
            with self.subTest(field=field),self.assertRaises(ValueError):compile_create(recipe,**args)
        recipe,args=fixture();recipe['process']['user']='';args['image_defaults']['User']='1000'
        with self.assertRaises(ValueError):compile_create(recipe,**args)
        recipe,args=fixture();args['image_defaults'].pop('Healthcheck')
        with self.assertRaises(ValueError):compile_create(recipe,**args)

    def test_logging_unknown_fields_and_ineffective_resource_limits_rejected(self):
        for mutate in (lambda r:r['hostConfig'].update(logConfig={'type':'json-file','config':{'max-size':'10m','max-file':'3'}}),
                       lambda r:r['hostConfig']['resources'].update(memoryBytes=1,memorySwapBytes=1),
                       lambda r:r['hostConfig']['resources'].update(nanoCpus=1),
                       lambda r:r.update(unknown='private-secret')):
            recipe,args=fixture();mutate(recipe)
            with self.assertRaisesRegex(ValueError,'^invalid-compose-create-candidate$'):compile_create(recipe,**args)

    def test_payload_is_copied_and_digest_binds_identity_and_image_inputs(self):
        recipe,args=fixture();result=compile_create(recipe,**args)
        changed=deepcopy(args);changed['identity']['daemonId']='daemon-two'
        self.assertNotEqual(result['candidateDigest'],compile_create(recipe,**changed)['candidateDigest'])
        changed=deepcopy(args);changed['image_defaults']['Cmd']=['different-image-default']
        self.assertNotEqual(result['candidateDigest'],compile_create(recipe,**changed)['candidateDigest'])
        recipe['process']['env'][0]='API_KEY=changed'
        self.assertNotEqual(result['body']['Env'],recipe['process']['env'])


if __name__=='__main__':unittest.main()
