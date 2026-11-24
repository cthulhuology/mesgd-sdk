import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mesgd/mesgd.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:test/test.dart';

const guid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

void main() {
  setUp(() => PKI.init('../fixtures/jwks.json'));

  test('handshake uses json, TOKEN and checks Sec-WebSocket-Accept', () async {
    final raw = await _oneRequest(
      (peer) async => _reject(peer),
      (port) => Mesgd.connect('ws://127.0.0.1:$port/inbox', token: 'grant-1'),
    );
    expect(raw, contains('Sec-WebSocket-Protocol: json, grant-1\r\n'));
  });

  test('bearerHeader sends Authorization and only the json subprotocol',
      () async {
    final raw = await _oneRequest(
      (peer) async => _reject(peer),
      (port) => Mesgd.connect(
        'ws://127.0.0.1:$port/inbox',
        token: 'grant-2',
        bearerHeader: true,
      ),
    );
    expect(raw, contains('Sec-WebSocket-Protocol: json\r\n'));
    expect(raw, contains('Authorization: Bearer grant-2\r\n'));
    expect(raw, isNot(contains('json, grant-2')));
  });

  test('plain, signed, and sealed frames round-trip', () async {
    final seen = <String>[];
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final serving = server.first.then((socket) async {
      final peer = _Peer(socket);
      await _accept(peer);
      final plain = utf8.decode((await peer.clientFrame()).payload);
      seen.add(plain);
      peer.send(0x1, utf8.encode(plain));
      final sealed = utf8.decode((await peer.clientFrame()).payload);
      seen.add(sealed);
      peer.send(0x1, utf8.encode(sealed));
      await socket.flush();
    });

    final conn = await Mesgd.connect(
      'ws://127.0.0.1:${server.port}/agents/alice/inbox',
      serverPub: PKI.pubJwk(),
    );
    addTearDown(() async {
      await conn.close();
      await server.close();
    });

    Map<String, dynamic>? got;
    conn.on('ping', (message) => got = message);
    await conn.send({
      'to': 'x/y',
      'type': 'ping',
      'body': {'a': 1}
    });
    await conn.recv();
    expect(got!['body'], {'a': 1});
    expect(got!.containsKey('enc'), isFalse);
    expect(got!.containsKey('sig'), isFalse);

    Map<String, dynamic>? task;
    conn.on('task.request', (message) => task = message);
    await conn.send(
      {
        'to': 'agents/alice/inbox',
        'type': 'task.request',
        'body': {'cap': 'summarize', 'n': 3},
      },
      sign: true,
      seal: true,
    );
    await conn.recv();
    await serving;
    expect(task!['to'], 'agents/alice/inbox');
    expect(task!['body'], {'cap': 'summarize', 'n': 3});
    expect(task!.containsKey('enc'), isFalse);
    expect(
      PKI.checkWithPub(
          PKI.pubJwk(), jsonEncode(task!['body']), task!['sig'] as String),
      isTrue,
    );
    final wire = jsonDecode(seen[1]) as Map<String, dynamic>;
    expect(wire.containsKey('body'), isFalse);
    expect(wire['enc'], isA<String>());
    expect(wire['to'], 'agents/alice/inbox');
  });

  test('reassembles fragments, answers ping, and reads a 16-bit frame',
      () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final pong = Completer<int>();
    server.listen((socket) async {
      final peer = _Peer(socket);
      await _accept(peer);
      peer.send(0x1, utf8.encode('{"type":"chat","body":"hello'), fin: false);
      peer.send(0x9, utf8.encode('zz'));
      peer.send(0x0, utf8.encode(' world"}'));
      await socket.flush();
      pong.complete((await peer.clientFrame()).opcode);
      peer.send(0x1, utf8.encode('{"type":"wide","body":"${'w' * 180}"}'));
      await socket.flush();
    });

    final conn = await Mesgd.connect('ws://127.0.0.1:${server.port}/topic');
    addTearDown(() async {
      await conn.close();
      await server.close();
    });
    Map<String, dynamic>? first;
    Map<String, dynamic>? second;
    conn.on('chat', (message) => first = message);
    conn.on('wide', (message) => second = message);
    await conn.recv();
    expect(await pong.future, 0xA);
    await conn.recv();
    expect(first!['body'], 'hello world');
    expect((second!['body'] as String).length, 180);
  });

  test('a server close frame completes the handshake', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final sawClose = Completer<int>();
    server.listen((socket) async {
      final peer = _Peer(socket);
      await _accept(peer);
      peer.send(0x8, [0x03, 0xE8]);
      await socket.flush();
      sawClose.complete((await peer.clientFrame()).opcode);
    });

    final conn = await Mesgd.connect('ws://127.0.0.1:${server.port}/topic');
    addTearDown(server.close);
    await expectLater(conn.recv(), throwsA(isA<MesgdException>()));
    expect(await sawClose.future, 0x8);
  });
}

/// Run a connect that is expected to fail the handshake, and return the raw
/// client request captured by the server.
Future<String> _oneRequest(
  Future<void> Function(_Peer peer) respond,
  Future<Mesgd> Function(int port) connect,
) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final request = Completer<String>();
  server.listen((socket) async {
    final peer = _Peer(socket);
    request.complete(await peer.headers());
    await respond(peer);
    await socket.close();
    await server.close();
  });
  await expectLater(connect(server.port), throwsA(isA<MesgdException>()));
  return request.future;
}

class _Frame {
  _Frame(this.opcode, this.payload);
  final int opcode;
  final Uint8List payload;
}

class _Peer {
  _Peer(this.socket) : pull = _Pull(socket);
  final Socket socket;
  final _Pull pull;
  String? _headers;

  Future<String> headers() async {
    final acc = BytesBuilder(copy: false);
    while (true) {
      acc.add(await pull.read(1));
      final bytes = acc.toBytes();
      if (bytes.length >= 4 &&
          bytes[bytes.length - 4] == 13 &&
          bytes[bytes.length - 3] == 10 &&
          bytes[bytes.length - 2] == 13 &&
          bytes[bytes.length - 1] == 10) {
        _headers = utf8.decode(bytes);
        return _headers!;
      }
      if (bytes.length > 65536) throw StateError('handshake too large');
    }
  }

  void send(int opcode, List<int> payload, {bool fin = true}) {
    final n = payload.length;
    final header = BytesBuilder();
    header.addByte((fin ? 0x80 : 0) | opcode);
    if (n < 126) {
      header.addByte(n);
    } else if (n < 65536) {
      header.addByte(126);
      header.addByte((n >> 8) & 0xff);
      header.addByte(n & 0xff);
    } else {
      header.addByte(127);
      for (var shift = 56; shift >= 0; shift -= 8) {
        header.addByte((n >> shift) & 0xff);
      }
    }
    header.add(payload);
    socket.add(header.toBytes());
  }

  Future<_Frame> clientFrame() async {
    final header = await pull.read(2);
    var n = header[1] & 0x7F;
    if (n == 126) {
      final ext = await pull.read(2);
      n = (ext[0] << 8) | ext[1];
    } else if (n == 127) {
      final ext = await pull.read(8);
      n = 0;
      for (final b in ext) {
        n = (n << 8) | b;
      }
    }
    final mask = header[1] & 0x80 != 0 ? await pull.read(4) : null;
    final payload = await pull.read(n);
    if (mask != null) {
      for (var i = 0; i < payload.length; i++) {
        payload[i] ^= mask[i % 4];
      }
    }
    return _Frame(header[0] & 0x0F, payload);
  }
}

Future<void> _reject(_Peer peer) async {
  peer.socket.add(utf8.encode('HTTP/1.1 101 Switching Protocols\r\n'
      'Upgrade: websocket\r\n'
      'Connection: Upgrade\r\n'
      'Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n'
      '\r\n'));
  await peer.socket.flush();
}

Future<void> _accept(_Peer peer) async {
  final request = peer._headers ?? await peer.headers();
  final key =
      RegExp(r'Sec-WebSocket-Key: (.+)\r\n').firstMatch(request)!.group(1)!;
  final digest = SHA1Digest();
  final data = utf8.encode('$key$guid');
  digest.update(data, 0, data.length);
  final out = Uint8List(digest.digestSize);
  digest.doFinal(out, 0);
  peer.socket.add(utf8.encode('HTTP/1.1 101 Switching Protocols\r\n'
      'Upgrade: websocket\r\n'
      'Connection: Upgrade\r\n'
      'Sec-WebSocket-Accept: ${base64.encode(out)}\r\n'
      'Sec-WebSocket-Protocol: json\r\n'
      '\r\n'));
  await peer.socket.flush();
}

class _Pull {
  _Pull(Socket socket) {
    socket.listen((data) {
      _chunks.add(data);
      _wake();
    }, onDone: () {
      _done = true;
      _wake();
    }, onError: (Object error) {
      _error = error;
      _wake();
    });
  }

  final _chunks = <Uint8List>[];
  var _offset = 0;
  var _done = false;
  Object? _error;
  Completer<void>? _wait;

  void _wake() {
    final wait = _wait;
    if (wait != null && !wait.isCompleted) wait.complete();
  }

  Future<Uint8List> read(int n) async {
    while (_available() < n) {
      if (_error != null) throw _error!;
      if (_done) throw StateError('socket closed');
      final wait = Completer<void>();
      _wait = wait;
      await wait.future;
    }
    final out = Uint8List(n);
    var filled = 0;
    while (filled < n) {
      final chunk = _chunks.first;
      final take = n - filled < chunk.length - _offset
          ? n - filled
          : chunk.length - _offset;
      out.setRange(filled, filled + take, chunk, _offset);
      filled += take;
      _offset += take;
      if (_offset == chunk.length) {
        _chunks.removeAt(0);
        _offset = 0;
      }
    }
    return out;
  }

  int _available() {
    var n = -_offset;
    for (final chunk in _chunks) {
      n += chunk.length;
    }
    return n;
  }
}
