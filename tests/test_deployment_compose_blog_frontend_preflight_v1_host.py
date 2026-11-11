"""Bounded read-only production preparation; no SSH credentials or Docker writes."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_compose_blog_frontend_preflight_v1_host as cli
from tests.test_deployment_compose_production_frontend_v3_host import material


class FrontendPreflightTests(unittest.TestCase):
    def test_host_daemon_pins_and_exact_frontend_are_required(self):
        row,image,args=material();pins=args['expected_identity']
        value=dict(daemonId=pins['daemonId'],row=row,image=image,protectedContainerIds=[])
        plan=cli.prepare_capture(value,pins)
        self.assertEqual(plan['privateBody']['HostConfig'],row['HostConfig'])
        self.assertFalse(plan['publicReview']['executionAvailable'])
        for field,value_ in (('daemonId','other'),('project','other'),('containerName','other')):
            other=deepcopy(pins);other[field]=value_
            with self.subTest(field=field),self.assertRaises(ValueError):cli.prepare_capture(value,other)
        with self.assertRaises(ValueError):cli.prepare_capture(dict(value,extra=True),pins)

    def test_invalid_ssh_alias_never_spawns(self):
        with patch.object(cli.subprocess,'Popen') as spawn:
            for alias in ('--help','x;touch file','x\ncommand','root@host'):
                with self.subTest(alias=alias),self.assertRaises(ValueError):cli.capture(alias)
            spawn.assert_not_called()

    @unittest.skipUnless(os.name=='posix','private POSIX artifact permissions required')
    def test_private_artifacts_refuse_existing_or_symlinked_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();out=root/'plan'
            cli.save_private(out,{'review.json':{'executionAvailable':False}})
            self.assertEqual(out.stat().st_mode&0o777,0o700)
            self.assertEqual((out/'review.json').stat().st_mode&0o777,0o600)
            self.assertFalse(json.loads((out/'review.json').read_text())['executionAvailable'])
            with self.assertRaises(FileExistsError):cli.save_private(out,{'review.json':{}})
            (root/'linked').symlink_to(out,target_is_directory=True)
            with self.assertRaises(ValueError):cli.save_private(root/'linked'/'nested',{'review.json':{}})

    @unittest.skipUnless(os.name=='posix','directory descriptors required')
    def test_directory_replacement_cannot_redirect_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();out=root/'plan';foreign=root/'foreign';foreign.mkdir()
            original_open=os.open
            def replace_on_file(name,*args,**kwargs):
                if name=='review.json':
                    out.rename(root/'retained-original')
                    out.symlink_to(foreign,target_is_directory=True)
                return original_open(name,*args,**kwargs)
            with patch.object(cli.os,'open',side_effect=replace_on_file),self.assertRaises(ValueError):
                cli.save_private(out,{'review.json':{'private':'fixture'}})
            self.assertFalse((foreign/'review.json').exists())
