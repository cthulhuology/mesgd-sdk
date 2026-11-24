import 'dart:convert';
import 'dart:io';

import 'package:mesgd/pki.dart';
import 'package:test/test.dart';

final fixtures = '../fixtures';
final jwksFile = '$fixtures/jwks.json';
final alice = '$fixtures/test_mesgd_alice.json';
final bob = '$fixtures/test_mesgd_bob.json';
final server = '$fixtures/test_mesgd_server.json';

void main() {
  tearDown(() {
    for (final path in [alice, bob, server]) {
      final file = File(path);
      if (file.existsSync()) file.deleteSync();
    }
    PKI.init(jwksFile);
  });

  test('register public JWKs and the server can open them', () {
    PKI.generate(server);
    final serverPub = PKI.pubJwk();
    PKI.generate(alice);
    final alicePub = PKI.pubJwk();
    final blob = PKI.register(serverPub);
    PKI.init(server);
    final envelope = jsonDecode(PKI.open(blob)) as Map<String, dynamic>;
    final payload = envelope['payload'] as String;
    expect(PKI.checkWithPub(alicePub, payload, envelope['signature'] as String),
        isTrue);
    final decoded = jsonDecode(payload) as Map<String, dynamic>;
    expect(decoded['signing_pub'], isA<Map>());
    expect(decoded['encrypting_pub'], isA<Map>());
  });

  test('two-party encryptWith / decrypt', () {
    PKI.generate(alice);
    final alicePub = PKI.pubJwk();
    PKI.generate(bob);
    final ct = PKI.encryptWith(alicePub, 'secret from bob');
    PKI.init(alice);
    expect(PKI.decrypt(ct), 'secret from bob');
  });

  test('signed encrypted message', () {
    PKI.generate(alice);
    final alicePub = PKI.pubJwk();
    PKI.generate(bob);
    const plain = 'ping';
    final sig = PKI.sign(plain);
    final envelope = jsonEncode({'payload': plain, 'signature': sig});
    final ct = PKI.encryptWith(alicePub, envelope);
    PKI.init(alice);
    final opened = jsonDecode(PKI.decrypt(ct)) as Map<String, dynamic>;
    expect(opened['payload'], plain);
    expect(
        PKI.checkWithPub(alicePub, opened['payload'] as String,
            opened['signature'] as String),
        isFalse);
    PKI.init(bob);
    expect(PKI.check(plain, sig), isTrue);
  });

  test('compact register envelope', () {
    PKI.init(jwksFile);
    final mesgdPub = PKI.pubJwk();
    PKI.generate(alice);
    final payload = jsonEncode({'name': 'alice'});
    final envelope =
        jsonEncode({'payload': payload, 'signature': PKI.sign(payload)});
    final ct = PKI.encryptWith(mesgdPub, envelope);
    final alicePub = PKI.pubJwk();
    PKI.init(jwksFile);
    final opened = jsonDecode(PKI.decrypt(ct)) as Map<String, dynamic>;
    expect((jsonDecode(opened['payload'] as String) as Map)['name'], 'alice');
    expect(
        PKI.checkWithPub(alicePub, opened['payload'] as String,
            opened['signature'] as String),
        isTrue);
  });
}
