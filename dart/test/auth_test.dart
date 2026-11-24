import 'dart:convert';
import 'dart:io';

import 'package:mesgd/auth.dart';
import 'package:test/test.dart';

void main() {
  final rows =
      jsonDecode(File('../fixtures/auth_contract.json').readAsStringSync())
          as List<dynamic>;

  test('auth contract', () async {
    for (final item in rows) {
      final row = Map<String, dynamic>.from(item as Map);
      final client = AuthClient((method, path, body, token) async {
        expect([method, path, body, token],
            [row['method'], row['path'], row['body'], row['token']]);
        return (200, Map<String, dynamic>.from(row['result'] as Map));
      });
      final result = await _call(
          client, row['op'] as String, row['args'] as List<dynamic>);
      expect(result, row['result']);
    }
  });

  test('rejects bad OTPs and private keys before transport', () async {
    final client = AuthClient((method, path, body, token) async {
      fail('invalid input reached transport');
    });
    for (final code in [123456, '12345', '01234x', '012345\n', '１２３４５６']) {
      await expectLater(client.login('u', 'p', code), throwsArgumentError);
    }
    for (final field in ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
      await expectLater(
          client.signup('u', 'e', 'p', [
            {field: 'PRIVATE'}
          ]),
          throwsArgumentError);
    }
    expect(() => httpsTransport('http://localhost'), throwsArgumentError);
    expect(() => httpsTransport('https://user:password@example.com'),
        throwsArgumentError);
  });

  test('errors carry status and omit the response body', () async {
    final client = AuthClient(
        (method, path, body, token) async => (401, {'secret': 'DO_NOT_LOG'}));
    try {
      await client.login('u', 'p', '012345');
      fail('expected AuthError');
    } on AuthError catch (error) {
      expect(error.status, 401);
      expect(error.toString(), isNot(contains('DO_NOT_LOG')));
    }
  });

  test('httpsTransport builds the login request', () async {
    final transport =
        httpsTransport('https://example.com', http: (request) async {
      expect(request.url.toString(), 'https://example.com/auth/login');
      expect(request.followRedirects, isFalse);
      expect(request.method, 'POST');
      expect(jsonDecode(request.body!)['otp'], '012345');
      expect(request.headers.containsKey('Authorization'), isFalse);
      expect(request.headers['Content-Type'], 'application/json');
      expect(request.timeout, const Duration(seconds: 15));
      return AuthReply(200, jsonEncode({'access_token': 'token'}));
    });
    final session = await AuthClient(transport).login('u', 'p', '012345');
    expect(session['access_token'], 'token');
  });

  test('httpsTransport sends the bearer and refuses to follow redirects',
      () async {
    final dir = await Directory.systemTemp.createTemp('mesgd-dart-auth-');
    addTearDown(() => dir.delete(recursive: true));
    final cert = File('${dir.path}/cert.pem');
    final key = File('${dir.path}/key.pem');
    final generated = await Process.run('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-keyout',
      key.path,
      '-out',
      cert.path,
      '-days',
      '1',
      '-nodes',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ]);
    expect(generated.exitCode, 0, reason: generated.stderr.toString());

    final context = SecurityContext()
      ..useCertificateChain(cert.path)
      ..usePrivateKey(key.path);
    final server =
        await HttpServer.bindSecure(InternetAddress.loopbackIPv4, 0, context);
    addTearDown(server.close);
    server.listen((request) async {
      if (request.uri.path == '/redirect') {
        await request.response.redirect(Uri.parse('/elsewhere'),
            status: HttpStatus.movedTemporarily);
        return;
      }
      if (request.uri.path == '/auth/keys') {
        expect(request.headers.value(HttpHeaders.authorizationHeader),
            'Bearer session-token');
        request.response.statusCode = 200;
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode({'public_keys': <Object>[]}));
        await request.response.close();
        return;
      }
      final body = await utf8.decodeStream(request);
      expect(jsonDecode(body)['otp'], '012345');
      expect(request.headers.value(HttpHeaders.authorizationHeader), isNull);
      request.response.statusCode = 200;
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({'access_token': 'issued'}));
      await request.response.close();
    });

    final trust = SecurityContext()..setTrustedCertificates(cert.path);
    final origin = 'https://localhost:${server.port}';
    final client = AuthClient(httpsTransport(origin, context: trust));
    expect((await client.login('alice', 'pw', '012345'))['access_token'],
        'issued');
    expect(await client.keys('session-token'), {'public_keys': <Object>[]});
    final redirected = await httpsTransport(origin, context: trust)(
        'GET', '/redirect', null, null);
    expect(redirected.$1, 302);
  });
}

Future<Map<String, dynamic>> _call(
    AuthClient client, String op, List<dynamic> args) {
  switch (op) {
    case 'signup':
      return client.signup(
          args[0] as String, args[1] as String, args[2] as String, args[3]);
    case 'confirm':
      return client.confirm(args[0] as String, args[1] as String, args[2]);
    case 'login':
      return client.login(args[0] as String, args[1] as String, args[2]);
    case 'reset_password':
      return client.resetPassword(
          args[0] as String, args[1] as String, args[2] as String, args[3]);
    case 'keys':
      return client.keys(args[0] as String);
    case 'set_keys':
      return client.setKeys(
          args[0] as String, args[1] as String, args[2], args[3]);
    case 'logout':
      return client.logout(args[0] as String);
  }
  throw ArgumentError('unknown auth op $op');
}
