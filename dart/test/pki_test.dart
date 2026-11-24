import 'dart:convert';
import 'dart:io';

import 'package:mesgd/pki.dart';
import 'package:test/test.dart';

final fixtures = Directory.current.path.endsWith('/dart') ||
        Directory.current.path.endsWith(r'\dart')
    ? '../fixtures'
    : 'fixtures';
final jwksFile = '$fixtures/jwks.json';
final genFile = '$fixtures/test_dart.json';
final sigOut = '$fixtures/sig_dart.json';
final ctOut = '$fixtures/ct_dart.json';

const crossLangs = [
  'erlang',
  'python',
  'javascript',
  'ruby',
  'rust',
  'go',
  'c',
  'java',
  'csharp',
  'php',
];

void main() {
  setUp(() => PKI.init(jwksFile));

  test('sign/verify round-trip', () {
    final sig = PKI.sign('Hello World');
    expect(PKI.check('Hello World', sig), isTrue);
    expect(PKI.check('Wrong message', sig), isFalse);
  });

  test('signature is JSON with 32-byte r and s', () {
    final obj = jsonDecode(PKI.sign('Hello World')) as Map<String, dynamic>;
    expect(obj.containsKey('r'), isTrue);
    expect(obj.containsKey('s'), isTrue);
    expect((obj['r'] as String).length, 43);
    expect((obj['s'] as String).length, 43);
  });

  test('encrypt/decrypt round-trip', () {
    final enc = PKI.encrypt('Secret message');
    expect(PKI.decrypt(enc), 'Secret message');
  });

  test('generate writes a four-key JWK array', () {
    final file = File(genFile);
    if (file.existsSync()) file.deleteSync();
    PKI.generate(genFile);
    final jwks = jsonDecode(file.readAsStringSync()) as List<dynamic>;
    expect(jwks, hasLength(4));
    final ops = jwks
        .map((j) => '${(j as Map)['use']}:${(j['key_ops'] as List).first}')
        .toSet();
    expect(ops,
        containsAll(['sig:verify', 'sig:sign', 'enc:decrypt', 'enc:encrypt']));
  });

  test('generated keys sign and encrypt', () {
    PKI.generate(genFile);
    PKI.init(genFile);
    final sig = PKI.sign('Hello World');
    expect(PKI.check('Hello World', sig), isTrue);
    expect(PKI.decrypt(PKI.encrypt('Secret')), 'Secret');
  });

  test('seal opens payloads past the RSA-OAEP cap', () {
    final plain = 'x' * 400;
    expect(PKI.open(PKI.seal(PKI.pubJwk(), plain)), plain);
  });

  test('write cross-lang signature', () {
    final sig = PKI.sign('Hello World');
    File(sigOut).writeAsStringSync(jsonEncode({
      'lang': 'dart',
      'message': 'Hello World',
      'signature': sig,
    }));
  });

  test('verify cross-lang signatures', () {
    for (final lang in crossLangs) {
      final file = File('$fixtures/sig_$lang.json');
      if (!file.existsSync()) continue;
      final rec = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      expect(
        PKI.check(rec['message'] as String, rec['signature'] as String),
        isTrue,
        reason: 'failed to verify $lang signature',
      );
    }
  });

  test('write cross-lang ciphertext', () {
    File(ctOut).writeAsStringSync(jsonEncode({
      'lang': 'dart',
      'message': 'Secret message',
      'ciphertext': PKI.encrypt('Secret message'),
    }));
  });

  test('decrypt cross-lang ciphertexts', () {
    for (final lang in crossLangs) {
      final file = File('$fixtures/ct_$lang.json');
      if (!file.existsSync()) continue;
      final rec = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      expect(
        PKI.decrypt(rec['ciphertext'] as String),
        rec['message'],
        reason: 'failed to decrypt $lang ciphertext',
      );
    }
  });
}
