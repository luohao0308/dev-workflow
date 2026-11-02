"""Independent-process live phase fixture: real SSHSIG/HMAC and Unix HTTP.

Systemd, proc identities, peer credentials and root UID are explicit doubles.
The parent owns the signing service, witness store, Engine double and cleanup.
Neither child receives a signing private key or witness-store HMAC key.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_restart_material_v3_host import reopen_material
from deployment_compose_live_phase_v3_host import LiveRecoveryPhaseCaptureV3
from deployment_compose_witness_store import canonical
import deployment_compose_recovery_daemon_v3_host as daemon
import deployment_compose_cold_writer_v3_host as cold

BOOT = '11111111-1111-1111-1111-111111111111'
READS = frozenset({'read', 'check', 'events_after', 'chain_status'})
GATE_KEY = b'g' * 32  # Externally provisioned test gate authentication only.
LIMIT = 4 * 1024 * 1024


def exact(stream, size):
    raw = bytearray()
    while len(raw) < size:
        chunk = stream.read(size-len(raw))
        if not chunk:
            raise ValueError('fixture-truncated')
        raw.extend(chunk)
    return bytes(raw)


def receive(stream):
    size = struct.unpack('!I', exact(stream, 4))[0]
    if not 0 < size <= LIMIT:
        raise ValueError('fixture-size')
    return decode(exact(stream, size))


def send(stream, value):
    raw = encode(value)
    if not 0 < len(raw) <= LIMIT:
        raise ValueError('fixture-size')
    stream.write(struct.pack('!I', len(raw))+raw)
    stream.flush()


def start_witness_server(case, path):
    """Serve only signed reads through the original parent's case.transport."""
    calls = []
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(5)
            value = receive(self.rfile)
            if type(value) is not dict or set(value) != {'method', 'request'} or value['method'] not in READS:
                raise ValueError('fixture-readonly')
            calls.append(value['method'])
            send(self.wfile, case.transport(value['method'], value['request']))
    class Server(socketserver.UnixStreamServer):
        def handle_error(self, request, client_address):
            pass
    server = Server(str(path), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, calls


def load(directory, *, material_path=None):
    config = json.loads((directory/'config.private.json').read_text())
    def path(key, default):
        return Path(config.get(key, str(directory/default)))
    pins = json.loads(path('pinsPath', 'pins.private.json').read_text())
    raw = (material_path if material_path is not None else path('materialPath', 'material.private.json')).read_bytes()
    public = path('publicPath', 'witness.pub').read_bytes()
    calls = []
    def transport(method, request):
        if method not in READS:
            raise ValueError('fixture-write-forbidden')
        calls.append(method)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(path('witnessSocket', 'witness.sock')))
            with connection.makefile('rwb', buffering=0) as stream:
                send(stream, dict(method=method, request=request))
                return receive(stream)
    gate = bytes.fromhex(config['gateKeyHex']) if 'gateKeyHex' in config else GATE_KEY
    context = reopen_material(raw, expected_digest=pins['expectedDigest'],
        expected_context=pins['expectedContext'], gate_key=gate,
        witness_public_key=public, witness_transport=transport)
    return config, pins, raw, context, calls


def record(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)


def produce(directory):
    config, pins, raw, context, calls = load(directory)
    record(directory/'validated-material.private.json', raw)
    record(directory/'validated-pins.private.json', canonical(pins))
    return dict(kind='producer-validated', producerPid=os.getpid(),
        historyDigest=context.snapshot.digest, readonlyRPC=calls,
        signingPrivateKeyReceived=False, witnessStoreKeyReceived=False)


def consume(directory):
    # New process rereads the producer-validated bytes against the same external pins.
    config, pins, raw, context, calls = load(directory, material_path=directory/'validated-material.private.json')
    if (directory/'validated-material.private.json').exists():
        assert raw == (directory/'validated-material.private.json').read_bytes()
        assert canonical(pins) == (directory/'validated-pins.private.json').read_bytes()
    root = Path(config['daemonRoot'])
    cgroup = Path(config['cgroupRoot'])
    unit = config['unit'];pid = config['pid'];main = config['main']
    invocation = config['invocation']
    original_connection = daemon._UnixDocker
    commands = []
    def command(argv, **kwargs):
        assert argv[:4] == ['/usr/bin/systemctl','--system','show',unit]
        assert '--all' in argv
        commands.append(argv)
        value = dict(LoadState='loaded', ActiveState='active', SubState='running', MainPID=str(main),
            ControlGroup='/system.slice/'+unit, InvocationID=invocation, Delegate='yes')
        return SimpleNamespace(stdout=''.join(k+'='+v+'\n' for k,v in value.items()).encode(), returncode=0)
    def identity(observed, group):
        assert group == '/system.slice/'+unit+'/supervisor'
        assert int(observed) in (main,pid)
        return int(observed), 123 if int(observed) == main else 456
    def connection(path, timeout):
        assert path.startswith('/proc/self/fd/') and path.endswith('/docker.sock')
        return original_connection(str(root/'docker.sock'), timeout)
    with tempfile.TemporaryDirectory(prefix='live-phase-proc-') as temporary, ExitStack() as stack:
        proc = Path(temporary)
        token = proc/'namespace';token.write_bytes(b'namespace-fixture')
        for name in ('self','1',str(pid)):
            (proc/name/'ns').mkdir(parents=True, exist_ok=True)
            (proc/name/'ns'/'pid').symlink_to(token)
        (proc/'self'/'stat').write_text(str(os.getpid())+' (consumer) S')
        for name in ('net','mnt'):
            (proc/str(pid)/'ns'/name).write_bytes(name.encode())
        for item in (patch.object(daemon,'_ROOT_UID',os.getuid()),
            patch.object(daemon.units,'_environment'),patch.object(daemon.units,'_boot',return_value=BOOT),
            patch.object(daemon.units,'CGROUP',cgroup),patch.object(daemon.units,'_pid_identity',side_effect=identity),
            patch.object(daemon,'_peer',return_value=(pid,os.getuid(),42)),
            patch.object(daemon,'_UnixDocker',side_effect=connection),
            patch.object(daemon,'subprocess',SimpleNamespace(run=command)),patch.object(cold,'PROC',proc)):
            stack.enter_context(item)
        observer = daemon.ObservedRecoveryDaemonV3(str(root), context.history._request.daemon_id, kernel_boot=BOOT)
        try:
            result = LiveRecoveryPhaseCaptureV3(original_history=context.history, baseline_bytes=context.baseline_bytes,
                daemon=observer, expected_version=config.get('expectedVersion', {'Version':'29.8.2','GitCommit':'8af9fe3'})).capture()
        finally:
            observer.close()
    return dict(kind='consumer-captured', consumerPid=os.getpid(), summary=result.public_summary(),
        readonlyRPC=calls, systemdShowCount=len(commands), systemdProcPeerRootDoubles=True,
        actualUnixHTTP=True, signingPrivateKeyReceived=False, witnessStoreKeyReceived=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('produce','consume'))
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps((produce if args.mode == 'produce' else consume)(args.directory)), flush=True)
