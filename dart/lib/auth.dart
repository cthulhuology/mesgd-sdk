// MIT License
// Copyright 2026 David J Goehrig <dave@dloh.org>
//
// mesgd password + OTP authentication. This library does not store secrets
// and does not depend on the PKI module. The transport contract is
// (method, path, jsonBodyOrNull, bearerOrNull) -> (status, jsonObject).

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

const _privateFields = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/// HTTP status from `/auth` without the response body or credentials.
class AuthError implements Exception {
  AuthError(this.status);
  final int status;

  @override
  String toString() => 'mesgd authentication HTTP $status';
}

/// Injected HTTP call. [body] is the already-decoded JSON object, or null.
typedef AuthTransport = Future<(int, Map<String, dynamic>)> Function(
  String method,
  String path,
  Map<String, dynamic>? body,
  String? token,
);

/// One outbound request produced by [httpsTransport]. Tests inject [http] to
/// inspect these fields; the default sender is verified HTTPS.
class AuthRequest {
  AuthRequest({
    required this.method,
    required this.url,
    required this.headers,
    required this.body,
    required this.followRedirects,
    required this.timeout,
  });

  final String method;
  final Uri url;
  final Map<String, String> headers;
  final String? body;
  final bool followRedirects;
  final Duration timeout;
}

class AuthReply {
  AuthReply(this.status, this.body);
  final int status;
  final String body;
}

typedef AuthHttp = Future<AuthReply> Function(AuthRequest request);

/// HTTPS origin transport. Rejects non-HTTPS origins, redirects, and disabled
/// certificate checks. [context] can add a private CA; hostname verification
/// stays on.
AuthTransport httpsTransport(
  String baseUrl, {
  SecurityContext? context,
  Duration timeout = const Duration(seconds: 15),
  AuthHttp? http,
}) {
  final origin = Uri.parse(baseUrl);
  if (origin.scheme != 'https' ||
      origin.host.isEmpty ||
      origin.userInfo.isNotEmpty ||
      origin.hasQuery ||
      origin.hasFragment ||
      (origin.path.isNotEmpty && origin.path != '/')) {
    throw ArgumentError('expected an HTTPS server origin');
  }
  final send = http ?? ((request) => _https(request, context));
  return (method, path, body, token) async {
    if (token != null && (token.contains('\r') || token.contains('\n'))) {
      throw ArgumentError('invalid bearer token');
    }
    final headers = <String, String>{'Accept': 'application/json'};
    if (token != null) headers['Authorization'] = 'Bearer $token';
    String? payload;
    if (body != null) {
      headers['Content-Type'] = 'application/json';
      payload = jsonEncode(body);
    }
    final reply = await send(AuthRequest(
      method: method,
      url: origin.replace(path: path),
      headers: headers,
      body: payload,
      followRedirects: false,
      timeout: timeout,
    ));
    if (reply.status < 200 || reply.status >= 300) {
      return (reply.status, <String, dynamic>{});
    }
    if (reply.body.length > 1048576) {
      throw ArgumentError('authentication response too large');
    }
    Object? decoded;
    try {
      decoded = jsonDecode(reply.body);
    } catch (_) {
      throw ArgumentError('invalid authentication response');
    }
    if (decoded is! Map) throw ArgumentError('invalid authentication response');
    return (reply.status, Map<String, dynamic>.from(decoded));
  };
}

Future<AuthReply> _https(AuthRequest request, SecurityContext? context) async {
  final client = HttpClient(context: context);
  client.connectionTimeout = request.timeout;
  try {
    final req = await client
        .openUrl(request.method, request.url)
        .timeout(request.timeout);
    req.followRedirects = request.followRedirects;
    req.headers.set(HttpHeaders.acceptHeader, 'application/json');
    request.headers.forEach((name, value) {
      if (name.toLowerCase() != 'accept') req.headers.set(name, value);
    });
    if (request.body != null) {
      final bytes = utf8.encode(request.body!);
      req.contentLength = bytes.length;
      req.add(bytes);
    }
    final res = await req.close().timeout(request.timeout);
    final builder = BytesBuilder(copy: false);
    await for (final chunk in res.timeout(request.timeout)) {
      if (builder.length + chunk.length > 1048576) {
        throw ArgumentError('authentication response too large');
      }
      builder.add(chunk);
    }
    return AuthReply(res.statusCode, utf8.decode(builder.takeBytes()));
  } finally {
    client.close(force: true);
  }
}

class AuthClient {
  AuthClient(this.transport);
  final AuthTransport transport;

  Future<Map<String, dynamic>> signup(
    String user,
    String email,
    String password, [
    Object? keys = const [],
  ]) async {
    return _request('POST', '/auth/signup', {
      'user': user,
      'email': email,
      'password': password,
      'public_keys': _publicKeys(keys),
    });
  }

  Future<Map<String, dynamic>> confirm(
      String user, String enrollmentToken, Object? code) async {
    return _request('POST', '/auth/signup/confirm', {
      'user': user,
      'enrollment_token': enrollmentToken,
      'otp': _otp(code),
    });
  }

  Future<Map<String, dynamic>> login(
      String user, String password, Object? code) async {
    return _request('POST', '/auth/login', {
      'user': user,
      'password': password,
      'otp': _otp(code),
    });
  }

  Future<Map<String, dynamic>> resetPassword(
    String user,
    String recoveryCode,
    String newPassword,
    Object? code,
  ) async {
    return _request('POST', '/auth/password/reset', {
      'user': user,
      'recovery_code': recoveryCode,
      'new_password': newPassword,
      'otp': _otp(code),
    });
  }

  Future<Map<String, dynamic>> keys(String token) {
    return _request('GET', '/auth/keys', null, token);
  }

  Future<Map<String, dynamic>> setKeys(
      String token, String password, Object? code, Object? keys) async {
    return _request(
      'PUT',
      '/auth/keys',
      {
        'password': password,
        'otp': _otp(code),
        'public_keys': _publicKeys(keys),
      },
      token,
    );
  }

  Future<Map<String, dynamic>> logout(String token) {
    return _request('POST', '/auth/logout', null, token);
  }

  Future<Map<String, dynamic>> _request(
    String method,
    String path,
    Map<String, dynamic>? body, [
    String? token,
  ]) async {
    final (status, result) = await transport(method, path, body, token);
    if (status < 200 || status >= 300) throw AuthError(status);
    return result;
  }
}

String _otp(Object? code) {
  if (code is! String || !RegExp(r'^[0-9]{6}$').hasMatch(code)) {
    throw ArgumentError('OTP must be a six-digit string');
  }
  return code;
}

List<Map<String, dynamic>> _publicKeys(Object? keys) {
  if (keys is! List || keys.length > 2) {
    throw ArgumentError(
        'expected at most two public JWKs without private fields');
  }
  final out = <Map<String, dynamic>>[];
  for (final item in keys) {
    if (item is! Map) {
      throw ArgumentError(
          'expected at most two public JWKs without private fields');
    }
    final map = Map<String, dynamic>.from(item);
    for (final field in _privateFields) {
      if (map.containsKey(field)) {
        throw ArgumentError(
            'expected at most two public JWKs without private fields');
      }
    }
    out.add(map);
  }
  return out;
}
