"""Malformed synthetic HTTP/2 peers and real slow/black-hole socket deadlines."""
import hashlib
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from common import module, certificate_bundle

class BytesPeer:
    def __init__(self, data): self.data, self.sent = bytearray(data), bytearray()
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def sendall(self, data): self.sent.extend(data)
    def recv(self, count):
        out = bytes(self.data[:count]); del self.data[:count]; return out

class ProtocolFaultTests(unittest.TestCase):
    def setUp(self):
        self.h = module('VK_PAYLOAD_VK_WRITE_SELFSTEAL_CHECK')
        self.tmp = tempfile.TemporaryDirectory(prefix='vk-protocol-test-')
        self.addCleanup(self.tmp.cleanup)
        self.site = Path(self.tmp.name) / 'index.html'
        self.site.write_bytes(b'cover')

    def reject_h2(self, frames, reason):
        http1 = BytesPeer(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ncover')
        http2 = BytesPeer(frames)
        with patch.object(self.h, 'connect', side_effect=[http1, http2]):
            with self.assertRaisesRegex(ValueError, reason):
                self.h.check('node.example.test', site=self.site)

    def test_h2_non_200_even_with_expected_body_is_rejected(self):
        f = self.h.h2frame
        self.reject_h2(f(4, 0, 0) + f(1, 4, 1, b'\x8d') + f(0, 1, 1, b'cover'), 'HTTP2_STATUS')

    def test_h2_body_before_headers_is_rejected(self):
        self.reject_h2(self.h.h2frame(0, 1, 1, b'cover'), 'DATA_BEFORE_HEADERS')

    def test_h2_reset_stream_is_not_success(self):
        self.reject_h2(self.h.h2frame(3, 0, 1, b'\0' * 4), 'stream rejected')

    def test_h2_invalid_settings_ack_is_rejected(self):
        self.reject_h2(self.h.h2frame(4, 1, 0, b'\0' * 6), 'invalid HTTP/2 SETTINGS')

    def test_h2_oversized_frame_does_not_allocate_its_body(self):
        self.reject_h2((200000).to_bytes(3, 'big') + b'\0\0\0\0\0\1', 'oversized HTTP/2 frame')

    def test_h2_unsupported_continuation_is_not_a_false_pass(self):
        self.reject_h2(self.h.h2frame(1, 0, 1, b'\x88'), 'UNEXPECTED_HEADERS')

    def test_repeated_short_reads_cannot_extend_absolute_deadline(self):
        left, right = socket.socketpair()
        stop = threading.Event()
        def drip():
            while not stop.is_set():
                try: right.sendall(b'x')
                except OSError: break
                stop.wait(.02)
        worker = threading.Thread(target=drip, daemon=True)
        worker.start()
        started = time.monotonic()
        try:
            wrapped = self.h.DeadlineSocket(left, started + .12)
            with self.assertRaises(TimeoutError):
                self.h.read_exact(wrapped, 1000)
            self.assertLess(time.monotonic() - started, 1)
        finally:
            stop.set(); left.close(); right.close(); worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

    def test_tcp_accept_without_tls_response_is_not_api_success(self):
        h = module('VK_PAYLOAD_VK_WRITE_TLS_CHECK')
        bundle, _ = certificate_bundle()
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(1)
        stop = threading.Event()
        def blackhole():
            try:
                raw, _ = listener.accept()
                with raw: stop.wait(1)
            except OSError: pass
        worker = threading.Thread(target=blackhole, daemon=True); worker.start()
        started = time.monotonic()
        try:
            fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(bundle['nodeCertPem'])).digest()
            result = h.probe('127.0.0.1', listener.getsockname()[1], 'node.example.test',
                             bundle['caCertPem'], fp, timeout=.15)
            self.assertEqual(result[:2], (False, 'TLS_TIMEOUT'))
            self.assertLess(time.monotonic() - started, 1)
        finally:
            stop.set(); listener.close(); worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
