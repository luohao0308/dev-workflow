"""Authenticated compiler inputs remain non-executable and may be stale."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'packs/deployment/scripts'))
from tests.test_deployment_compose_create import fixture
from deployment_compose_image_defaults import commit_image_config
from deployment_compose_create import compile_create_with_image_proof

KEY=b'image-test-key-'+b'x'*32
REF='example.com/app@sha256:'+'c'*64


def setup():
    recipe,args=fixture()
    defaults=args.pop('image_defaults')
    image={'Id':recipe['imageId'],'Os':'linux','Architecture':'amd64','RepoDigests':[REF],
           'Config':{k:v for k,v in defaults.items() if k not in ('ImageId','Os','Architecture')}}
    args.update(image=image,image_commitment=commit_image_config(image,'image-key',KEY),image_key=KEY,
        expected_image_key_id='image-key',expected_registry_digest=REF,expected_architecture='amd64')
    return recipe,args


class CompilerProofTests(unittest.TestCase):
    def test_original_image_commitment_binds_candidate_without_opening_gates(self):
        recipe,args=setup(); result=compile_create_with_image_proof(recipe,**args)
        self.assertEqual(result['imageDefaultsVerification'],'hmac-verified-no-freshness')
        self.assertNotIn('trusted-image-defaults-required',result['validationBlockers'])
        for blocker in ('fresh-image-presence-required','image-build-provenance-required',
                        'daemon-defaults-verification-required','engine-reconstruction-required'):
            self.assertIn(blocker,result['validationBlockers'])
        for flag in ('authorityGranted','executionAvailable','reconstructionValidated','productionReady'):
            self.assertIs(result[flag],False)

    def test_tampering_and_foreign_scope_rejected(self):
        for mutate in (lambda a:a['image']['Config']['Env'].append('OTHER=secret'),
                       lambda a:a['image_commitment'].update(keyId='other-key'),
                       lambda a:a.update(image_key=b'z'*32),
                       lambda a:a.update(expected_registry_digest='other.example/app@sha256:'+'d'*64),
                       lambda a:a.update(expected_architecture='arm64')):
            recipe,args=setup();mutate(args)
            with self.assertRaisesRegex(ValueError,'^invalid-compose-create-candidate$'):
                compile_create_with_image_proof(recipe,**args)

    def test_valid_commitment_cannot_bypass_merge_hazards(self):
        recipe,args=setup();args['image']['Config']['Healthcheck']={'StartPeriod':1}
        args['image_commitment']=commit_image_config(args['image'],'image-key',KEY)
        with self.assertRaises(ValueError):compile_create_with_image_proof(recipe,**args)
        recipe,args=setup();args['image']['Config']['Unknown']='secret'
        args['image_commitment']=commit_image_config(args['image'],'image-key',KEY)
        with self.assertRaises(ValueError):compile_create_with_image_proof(recipe,**args)


if __name__=='__main__':unittest.main()
