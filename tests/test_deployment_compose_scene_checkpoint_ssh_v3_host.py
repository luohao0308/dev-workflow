"""Actual relay constructor/Unix authentication; SSH/source/kernel are doubles."""
import os
import unittest
from tests import test_deployment_compose_scene_control_ssh_v3_host as relay_fixture
import deployment_compose_scene_control_ssh_v3_host as relay


@unittest.skipUnless(os.name == 'posix', 'POSIX Unix sockets and pipes required')
class CheckpointSSHIdentityTests(unittest.TestCase):
    setUp = relay_fixture.RelayTests.setUp
    cleanup_service = relay_fixture.RelayTests.cleanup_service
    connect = relay_fixture.RelayTests.connect

    def test_only_original_handshake_client_can_supply_checkpoint_source(self):
        client = self.connect()
        seal = relay._issued_scene_ssh_client(client)
        forged = object.__new__(relay.SceneSSHClientV3)
        forged.__dict__.update(client.__dict__)
        with self.assertRaises(ValueError): relay._issued_scene_ssh_client(forged)
        process = client._process
        try:
            client._process = object()
            with self.assertRaises(ValueError): relay._issued_scene_ssh_client(client)
        finally:
            client._process = process
        client._read = lambda timeout: {}
        try:
            with self.assertRaises(ValueError): relay._issued_scene_ssh_client(client)
        finally:
            del client._read
        self.assertEqual(relay._issued_scene_ssh_client(client), seal)
        client.detach()
        # Detaching ends control, while the original archive provenance remains.
        self.assertEqual(relay._issued_scene_ssh_client(client), seal)
        self.connect().close_scene()
        self.assertEqual(self.process.wait(timeout=5), 0)
