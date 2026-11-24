// MIT License
// Copyright 2026 David J Goehrig <dave@dloh.org>
//
// mesgd transport client. One Mesgd == one WebSocket == one subscription path
// == one bearer. send/on are the headline surface. Security is opt-in: plain,
// signed (sig over the serialized body), or sealed (body replaced by enc).
//
// The socket is an RFC 6455 client: it checks Sec-WebSocket-Accept, masks
// outbound frames, reassembles fragmented data, answers ping, and completes
// the close handshake. It does not negotiate permessage-deflate. The bearer
// is the second subprotocol value ("json, TOKEN"), which is the spacing the
// broker expects. Set bearerHeader to send Authorization instead and offer
// only the "json" subprotocol.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha1.dart';

import 'pki.dart';

const _wsGuid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const _maxPayload = 8 * 1024 * 1024;

class MesgdException implements Exception {
  MesgdException(this.message);
  final String message;

  @override
  String toString() => 'mesgd: $message';
}

typedef MesgdHandler = void Function(Map<String, dynamic> message);

/// JSON WebSocket connection to one mesgd subscription.
class Mesgd {
  Mesgd._(this._socket, this._reader, {Map<String, dynamic>? serverPub})
      : serverPub = serverPub;

  final Socket _socket;
  final _Reader _reader;
  final Map<String, MesgdHandler> _handlers = {};
  Map<String, dynamic>? serverPub;
  bool _closed = false;
  bool _closeSent = false;
  final BytesBuilder _fragment = BytesBuilder(copy: false);
  int? _fragmentOpcode;

  /// Dial `ws://` or `wss://`. [token] is sent as the second WebSocket
  /// subprotocol unless [bearerHeader] is set, in which case it is
  /// `Authorization: Bearer`. [serverPub] is the recipient public JWK used
  /// when sealing. [keyFile] or [keys] loads the PKI identity used to sign
  /// and open.
  static Future<Mesgd> connect(
    String url, {
    String? token,
    Map<String, dynamic>? serverPub,
    String? keyFile,
    List<dynamic>? keys,
    SecurityContext? securityContext,
    Map<String, String>? headers,
    bool bearerHeader = false,
    Duration timeout = const Duration(seconds: 15),
  }) async {
    if (keys != null) {
      PKI.importJwks(keys);
    } else if (keyFile != null) {
      PKI.init(keyFile);
    }
    final uri = Uri.parse(url);
    final secure = uri.scheme == 'wss';
    if (!secure && uri.scheme != 'ws') {
      throw ArgumentError('mesgd URL must be ws:// or wss://');
    }
    if (token != null && (token.contains('\r') || token.contains('\n'))) {
      throw ArgumentError('invalid bearer token');
    }
    final host = uri.host;
    final port = uri.hasPort ? uri.port : (secure ? 443 : 80);
    Socket socket = await Socket.connect(host, port, timeout: timeout);
    _Reader? reader;
    try {
      if (secure) {
        socket = await SecureSocket.secure(socket,
            host: host, context: securityContext);
      }
      reader = _Reader(socket);
      return await _handshake(
        socket,
        reader,
        uri,
        host,
        token,
        serverPub,
        headers,
        bearerHeader,
        timeout,
      );
    } catch (error) {
      await reader?.cancel();
      try {
        await socket.close();
      } catch (_) {}
      if (error is MesgdException || error is ArgumentError) rethrow;
      throw MesgdException('connect failed: $error');
    }
  }

  static Future<Mesgd> _handshake(
    Socket socket,
    _Reader reader,
    Uri uri,
    String host,
    String? token,
    Map<String, dynamic>? serverPub,
    Map<String, String>? headers,
    bool bearerHeader,
    Duration timeout,
  ) async {
    final nonce = base64.encode(_nonce());
    final path = uri.path.isEmpty ? '/' : uri.path;
    final target = uri.hasQuery ? '$path?${uri.query}' : path;
    final hostHeader = uri.hasPort ? '$host:${uri.port}' : host;
    final protocol = (token == null || token.isEmpty || bearerHeader)
        ? 'json'
        : 'json, $token';
    final request = StringBuffer()
      ..write('GET $target HTTP/1.1\r\n')
      ..write('Host: $hostHeader\r\n')
      ..write('Upgrade: websocket\r\n')
      ..write('Connection: Upgrade\r\n')
      ..write('Sec-WebSocket-Key: $nonce\r\n')
      ..write('Sec-WebSocket-Version: 13\r\n')
      ..write('Sec-WebSocket-Protocol: $protocol\r\n');
    if (bearerHeader && token != null && token.isNotEmpty) {
      request.write('Authorization: Bearer $token\r\n');
    }
    headers?.forEach((name, value) {
      if (name.contains('\r') ||
          name.contains('\n') ||
          value.contains('\r') ||
          value.contains('\n')) {
        throw ArgumentError('invalid WebSocket header');
      }
      request.write('$name: $value\r\n');
    });
    request.write('\r\n');
    socket.add(utf8.encode(request.toString()));
    await socket.flush();

    final head = utf8.decode(
        await reader.readUntil(const [13, 10, 13, 10]).timeout(timeout));
    final lines = head.split('\r\n');
    if (lines.isEmpty || !lines.first.contains(' 101 ')) {
      throw MesgdException(
          'upgrade failed: ${lines.isEmpty ? head : lines.first}');
    }
    final responseHeaders = <String, String>{};
    for (final line in lines.skip(1)) {
      final colon = line.indexOf(':');
      if (colon <= 0) continue;
      responseHeaders[line.substring(0, colon).trim().toLowerCase()] =
          line.substring(colon + 1).trim();
    }
    final accept = responseHeaders['sec-websocket-accept'];
    if (accept == null || accept != _accept(nonce)) {
      throw MesgdException('bad Sec-WebSocket-Accept');
    }
    final selected = responseHeaders['sec-websocket-protocol'];
    if (selected != null && selected != 'json') {
      throw MesgdException('broker selected unexpected subprotocol $selected');
    }
    return Mesgd._(socket, reader, serverPub: serverPub);
  }

  /// Register a local handler for [type]. `*` receives messages with no
  /// handler of their own. This does not subscribe at the broker.
  Mesgd on(String type, MesgdHandler handler) {
    _handlers[type] = handler;
    return this;
  }

  /// Publish one JSON text frame. With [sign], `sig` covers the JSON body.
  /// With [seal], `body` is removed and replaced by hybrid `enc`.
  Future<void> send(Map<String, dynamic> message,
      {bool sign = false, bool seal = false}) async {
    _ensureOpen();
    _writeFrame(utf8.encode(_frame(message, sign: sign, seal: seal)), 0x1);
    await _socket.flush();
  }

  /// Read one data message, open a sealed body, and dispatch it.
  Future<void> recv() async {
    _ensureOpen();
    _dispatch(utf8.decode(await _readData()));
  }

  /// Dispatch messages until the peer closes the socket.
  Future<void> listen() async {
    try {
      while (!_closed) {
        await recv();
      }
    } on MesgdException {
      if (!_closed) rethrow;
    }
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      if (!_closeSent) {
        _closeSent = true;
        _writeFrame(Uint8List(0), 0x8);
        await _socket.flush();
      }
    } catch (_) {}
    try {
      await _socket.close();
    } catch (_) {}
    await _reader.cancel();
  }

  String _frame(Map<String, dynamic> message,
      {required bool sign, required bool seal}) {
    if (!sign && !seal) return jsonEncode(message);
    final body = jsonEncode(message['body']);
    final out = Map<String, dynamic>.from(message);
    if (sign) out['sig'] = PKI.sign(body);
    if (seal) {
      final pub = serverPub;
      if (pub == null) throw StateError('seal requires serverPub');
      out.remove('body');
      out['enc'] = PKI.seal(pub, body);
    }
    return jsonEncode(out);
  }

  void _dispatch(String raw) {
    final decoded = jsonDecode(raw);
    if (decoded is! Map) throw MesgdException('message is not a JSON object');
    final message = Map<String, dynamic>.from(decoded);
    final enc = message.remove('enc');
    if (enc is String) {
      message['body'] = jsonDecode(PKI.open(enc));
    }
    final typeValue = message['type'];
    final type = typeValue == null ? '*' : typeValue.toString();
    final handler = _handlers[type] ?? _handlers['*'];
    if (handler != null) handler(message);
  }

  Future<Uint8List> _readData() async {
    while (!_closed) {
      final header = await _reader.read(2);
      final fin = header[0] & 0x80 != 0;
      if (header[0] & 0x70 != 0) throw MesgdException('RSV bits must be clear');
      final opcode = header[0] & 0x0F;
      var length = header[1] & 0x7F;
      final masked = header[1] & 0x80 != 0;
      if (length == 126) {
        final ext = await _reader.read(2);
        length = (ext[0] << 8) | ext[1];
      } else if (length == 127) {
        final ext = await _reader.read(8);
        length = 0;
        for (final byte in ext) {
          length = (length << 8) | byte;
        }
      }
      if (length < 0 || length > _maxPayload)
        throw MesgdException('frame too large');
      if (opcode >= 8 && (!fin || length > 125))
        throw MesgdException('bad control frame');
      final mask = masked ? await _reader.read(4) : null;
      final payload = await _reader.read(length);
      if (mask != null) {
        for (var i = 0; i < payload.length; i++) {
          payload[i] ^= mask[i % 4];
        }
      }

      if (opcode == 0x8) {
        _closeSent = true;
        try {
          _writeFrame(
              payload.length >= 2 ? payload.sublist(0, 2) : Uint8List(0), 0x8);
        } catch (_) {}
        await close();
        throw MesgdException('connection closed');
      }
      if (opcode == 0x9) {
        _writeFrame(payload, 0xA);
        await _socket.flush();
        continue;
      }
      if (opcode == 0xA) continue;

      if (opcode == 0x0) {
        if (_fragmentOpcode == null)
          throw MesgdException('unexpected continuation');
        _fragment.add(payload);
        if (fin) return _finishFragment();
        continue;
      }
      if (opcode == 0x1) {
        if (_fragmentOpcode != null)
          throw MesgdException('data frame during a fragment');
        if (!fin) {
          _fragment.add(payload);
          _fragmentOpcode = opcode;
          continue;
        }
        return payload;
      }
      throw MesgdException('unsupported opcode $opcode');
    }
    throw MesgdException('connection closed');
  }

  Uint8List _finishFragment() {
    final opcode = _fragmentOpcode;
    final data = _fragment.takeBytes();
    _fragmentOpcode = null;
    if (opcode != 0x1) throw MesgdException('binary frames are not used');
    return data;
  }

  void _writeFrame(List<int> payload, int opcode) {
    final length = payload.length;
    final header = BytesBuilder();
    header.addByte(0x80 | opcode);
    if (length < 126) {
      header.addByte(0x80 | length);
    } else if (length < 65536) {
      header.addByte(0xFE);
      header.addByte((length >> 8) & 0xFF);
      header.addByte(length & 0xFF);
    } else {
      header.addByte(0xFF);
      for (var shift = 56; shift >= 0; shift -= 8) {
        header.addByte((length >> shift) & 0xFF);
      }
    }
    final mask = _nonce(4);
    header.add(mask);
    final masked = Uint8List(length);
    for (var i = 0; i < length; i++) {
      masked[i] = payload[i] ^ mask[i % 4];
    }
    header.add(masked);
    _socket.add(header.toBytes());
  }

  void _ensureOpen() {
    if (_closed) throw MesgdException('connection closed');
  }
}

String _accept(String nonce) {
  final digest = SHA1Digest();
  final data = utf8.encode('$nonce$_wsGuid');
  digest.update(data, 0, data.length);
  final out = Uint8List(digest.digestSize);
  digest.doFinal(out, 0);
  return base64.encode(out);
}

final _random = Random.secure();

Uint8List _nonce([int n = 16]) {
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = _random.nextInt(256);
  }
  return out;
}

class _Reader {
  _Reader(Socket socket) {
    _sub = socket.listen(
      (data) {
        _chunks.add(data);
        _signal();
      },
      onError: (Object error) {
        _error = error;
        _signal();
      },
      onDone: () {
        _done = true;
        _signal();
      },
      cancelOnError: true,
    );
  }

  final List<Uint8List> _chunks = [];
  int _offset = 0;
  bool _done = false;
  Object? _error;
  Completer<void>? _waiting;
  late final StreamSubscription<Uint8List> _sub;

  void _signal() {
    final waiting = _waiting;
    if (waiting != null && !waiting.isCompleted) waiting.complete();
  }

  int _available() {
    var n = -_offset;
    for (final chunk in _chunks) {
      n += chunk.length;
    }
    return n;
  }

  Future<void> _need(int n) async {
    while (_available() < n) {
      if (_error != null) throw MesgdException('socket error: $_error');
      if (_done) throw MesgdException('connection closed');
      final waiting = Completer<void>();
      _waiting = waiting;
      await waiting.future;
    }
  }

  Future<Uint8List> read(int n) async {
    if (n == 0) return Uint8List(0);
    await _need(n);
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

  Future<Uint8List> readUntil(List<int> marker) async {
    final acc = BytesBuilder(copy: false);
    while (true) {
      acc.add(await read(1));
      final bytes = acc.toBytes();
      if (bytes.length >= marker.length && _endsWith(bytes, marker)) {
        return Uint8List.sublistView(bytes, 0, bytes.length - marker.length);
      }
      if (bytes.length > 65536) throw MesgdException('handshake too large');
    }
  }

  Future<void> cancel() async {
    _done = true;
    _signal();
    await _sub.cancel();
  }
}

bool _endsWith(List<int> bytes, List<int> marker) {
  final start = bytes.length - marker.length;
  for (var i = 0; i < marker.length; i++) {
    if (bytes[start + i] != marker[i]) return false;
  }
  return true;
}
