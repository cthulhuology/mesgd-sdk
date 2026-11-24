"""mesgd transport client.

One Mesgd == one wss connection == one path == one JWT; open several for several
topics or grants. on/send are the headline surface. Security is opt-in: plain,
signed (sig over body), or signed + sealed (body encrypted, routable fields left
in cleartext).

The WebSocket client is stdlib-only (socket + ssl, no third-party dependency),
implementing just the RFC 6455 client subset mesgd needs: a json subprotocol
with the bearer token as its second value, masked text frames, and ping/pong.
"""

import os
import ssl
import json
import struct
import socket
import base64
from urllib.parse import urlparse

from pki import PKI


class Mesgd:
    def __init__(self, sock, pki, server_pub):
        self._sock = sock
        self._pki = pki
        self._server_pub = server_pub
        self._handlers = {}
        self._buf = b''

    @classmethod
    def connect(cls, url, token=None, server_pub=None, pki=PKI, ssl_context=None):
        u = urlparse(url)
        port = u.port or (443 if u.scheme == 'wss' else 80)
        sock = socket.create_connection((u.hostname, port))
        if u.scheme == 'wss':
            ctx = ssl_context or ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
        proto = 'json' if not token else 'json, ' + token
        path = u.path or '/'
        if u.query:
            path += '?' + u.query
        sock.sendall((
            'GET %s HTTP/1.1\r\nHost: %s\r\n'
            'Upgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n'
            'Sec-WebSocket-Protocol: %s\r\n\r\n'
            % (path, u.netloc, base64.b64encode(os.urandom(16)).decode(), proto)
        ).encode())

        self = cls(sock, pki, server_pub)
        while b'\r\n\r\n' not in self._buf:
            self._buf += sock.recv(65536)
        head, self._buf = self._buf.split(b'\r\n\r\n', 1)
        status = head.split(b'\r\n', 1)[0]
        if b' 101 ' not in status:
            raise RuntimeError('mesgd: upgrade failed: ' + status.decode(errors='replace'))
        return self

    def on(self, typ, handler):
        self._handlers[typ] = handler
        return self

    def send(self, message, sign=False, seal=False):
        self._write_frame(self._frame(message, sign, seal).encode())

    def recv(self):
        self._dispatch(self._read_frame())

    def close(self):
        self._sock.close()

    # ── framing helpers ──────────────────────────────────────────────────

    def _frame(self, message, sign, seal):
        if not sign and not seal:
            return json.dumps(message)
        body = json.dumps(message['body'])
        if sign:
            message['sig'] = self._pki.sign(body)
        if seal:
            del message['body']
            message['enc'] = self._pki.seal(self._server_pub, body)
        return json.dumps(message)

    def _dispatch(self, raw):
        message = json.loads(raw)
        if 'enc' in message:
            message['body'] = json.loads(self._pki.open(message.pop('enc')))
        handler = self._handlers.get(message.get('type')) or self._handlers.get('*')
        if handler:
            handler(message)

    # ── RFC 6455 (client masks; server frames arrive unmasked) ────────────

    def _read(self, n):
        while len(self._buf) < n:
            self._buf += self._sock.recv(65536)
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def _read_frame(self):
        h = self._read(2)
        opcode = h[0] & 0x0F
        n = h[1] & 0x7F
        if n == 126:
            n = struct.unpack('!H', self._read(2))[0]
        elif n == 127:
            n = struct.unpack('!Q', self._read(8))[0]
        mask = self._read(4) if h[1] & 0x80 else b''
        payload = self._read(n)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x8:          # close
            raise ConnectionError('mesgd: connection closed')
        if opcode == 0x9:          # ping -> pong, then read the next frame
            self._write_frame(payload, 0xA)
            return self._read_frame()
        if opcode == 0xA:          # pong
            return self._read_frame()
        return payload

    def _write_frame(self, payload, opcode=0x1):
        n = len(payload)
        header = bytes([0x80 | opcode])
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0xFE]) + struct.pack('!H', n)
        else:
            header += bytes([0xFF]) + struct.pack('!Q', n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(header + mask + masked)
