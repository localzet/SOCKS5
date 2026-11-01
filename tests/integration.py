# SPDX-FileCopyrightText: 2016-2026 Localzet Group
# SPDX-License-Identifier: AGPL-3.0
from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def receive(stream: socket.socket, length: int) -> bytes:
    data = b''
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError('Connection closed')
        data += chunk
    return data


class SocksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = tempfile.TemporaryDirectory(prefix='socks5-test-')
        cls.echo = socket.socket()
        cls.echo.bind(('127.0.0.1', 0))
        cls.echo.listen()
        cls.echo_port = cls.echo.getsockname()[1]
        def serve():
            while True:
                try:
                    stream, _ = cls.echo.accept()
                except OSError:
                    return
                def relay(stream=stream):
                    with stream:
                        while data := stream.recv(65536):
                            stream.sendall(data)
                threading.Thread(target=relay, daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        with socket.socket() as allocator:
            allocator.bind(('127.0.0.1', 0))
            cls.port = allocator.getsockname()[1]
        env = {**os.environ, 'SOCKS5_PORT': str(cls.port), 'SOCKS5_USERNAME': 'test-user', 'SOCKS5_PASSWORD': 'test-password',
               'SOCKS5_PID_FILE': str(Path(cls.runtime.name, 'server.pid')), 'SOCKS5_LOG_FILE': str(Path(cls.runtime.name, 'server.log')),
               'SOCKS5_MAX_CONNECTIONS': '8', 'SOCKS5_MAX_CONNECTIONS_PER_IP': '4',
               'SOCKS5_MAX_ATTEMPTS_PER_MINUTE': '30'}
        cls.log = open(Path(cls.runtime.name, 'stdout.log'), 'w')
        cls.process = subprocess.Popen(['php', 'start.php', 'start'], cwd=ROOT, env=env, stdout=cls.log, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(100):
            if cls.process.poll() is not None:
                raise RuntimeError('SOCKS server exited before listening')
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError('SOCKS server did not start')

    @classmethod
    def tearDownClass(cls):
        os.killpg(cls.process.pid, signal.SIGINT)
        try:
            cls.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(cls.process.pid, signal.SIGKILL)
            cls.process.wait(timeout=5)
        cls.echo.close()
        cls.log.close()
        cls.runtime.cleanup()

    def connect(self, source='127.0.0.1'):
        stream = socket.socket()
        stream.settimeout(2)
        stream.bind((source, 0))
        stream.connect(('127.0.0.1', self.port))
        stream.settimeout(2)
        self.addCleanup(stream.close)
        return stream

    def authenticate(self, stream, fragmented=False):
        greeting = b'\x05\x01\x02'
        auth = b'\x01\x09test-user\x0dtest-password'
        for packet, expected in [(greeting, b'\x05\x02'), (auth, b'\x01\x00')]:
            if fragmented:
                for byte in packet:
                    stream.sendall(bytes([byte]))
                    time.sleep(0.002)
            else:
                stream.sendall(packet)
            self.assertEqual(receive(stream, 2), expected)

    def test_fragmented_handshake_and_tcp_relay(self):
        stream = self.connect()
        self.authenticate(stream, fragmented=True)
        request = b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', self.echo_port)
        for byte in request:
            stream.sendall(bytes([byte]))
            time.sleep(0.002)
        response = receive(stream, 10)
        self.assertEqual(response[:4], b'\x05\x00\x00\x01')
        self.assertNotEqual(response[8:], b'\x00\x00')
        stream.sendall(b'echo payload')
        self.assertEqual(receive(stream, 12), b'echo payload')

    def test_coalesced_auth_request_and_early_payload(self):
        stream = self.connect()
        request = b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', self.echo_port)
        stream.sendall(b'\x05\x01\x02\x01\x09test-user\x0dtest-password' + request + b'early')
        self.assertEqual(receive(stream, 4), b'\x05\x02\x01\x00')
        self.assertEqual(receive(stream, 10)[:2], b'\x05\x00')
        self.assertEqual(receive(stream, 5), b'early')

    def test_anonymous_auth_is_not_offered(self):
        stream = self.connect()
        stream.sendall(b'\x05\x01\x00')
        self.assertEqual(receive(stream, 2), b'\x05\xff')

    def test_wrong_password_is_rejected(self):
        stream = self.connect()
        stream.sendall(b'\x05\x01\x02')
        receive(stream, 2)
        stream.sendall(b'\x01\x09test-user\x05wrong')
        self.assertEqual(receive(stream, 2), b'\x01\x01')

    def test_z_rate_limit(self):
        blocked = False
        accepted = 0
        for _ in range(40):
            stream = self.connect()
            stream.sendall(b'\x05\x01\x02')
            try:
                response = stream.recv(2)
            except ConnectionResetError:
                response = b''
            if response == b'':
                blocked = True
                stream.close()
                break
            accepted += 1
            stream.close()
            time.sleep(0.03)
        self.assertGreater(accepted, 0, 'some requests must pass before the rate threshold')
        self.assertTrue(blocked, 'connection attempts above the configured per-IP rate must be rejected')

    def test_udp_is_disabled(self):
        stream = self.connect()
        self.authenticate(stream)
        stream.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        self.assertEqual(receive(stream, 10)[:2], b'\x05\x07')

    def test_global_connection_limit(self):
        streams = [self.connect('127.0.0.1') for _ in range(4)]
        streams.extend(self.connect('127.0.0.2') for _ in range(4))
        streams.append(self.connect('127.0.0.3'))
        self.assertEqual(streams[-1].recv(1), b'')
        for stream in streams:
            stream.close()
        time.sleep(0.05)

    def test_per_ip_connection_limit(self):
        streams = [self.connect() for _ in range(5)]
        self.assertEqual(streams[-1].recv(1), b'')
        for stream in streams:
            stream.close()
        time.sleep(0.05)

    def test_invalid_greeting_is_rejected(self):
        stream = self.connect()
        stream.sendall(b'\x04\x01\x02')
        self.assertEqual(stream.recv(2), b'')


if __name__ == '__main__':
    unittest.main()
