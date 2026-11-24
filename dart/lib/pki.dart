// MIT License
// Copyright 2026 David J Goehrig <dave@dloh.org>
//
// mesgd PKI. One isolate holds one identity: a P-256 signing key and a
// 2048-bit RSA-OAEP encryption key. The on-disk format is the flat JWK array
// used by the other SDKs (use + key_ops). Signatures are JSON
// {"r":"<base64url>","s":"<base64url>"} over SHA-256. RSA-OAEP uses SHA-256
// for both the label hash and MGF1. seal/open is the hybrid
// RSA-OAEP+A256GCM envelope from the Erlang reference.

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

/// Process-wide mesgd identity. Call [init] or [generate] before use.
class PKI {
  static const defaultFile = 'mesgd_keys.json';

  static ECPrivateKey? _sigPriv;
  static ECPublicKey? _sigPub;
  static RSAPrivateKey? _encPriv;
  static RSAPublicKey? _encPub;

  /// Load [keyFile], or `MESGD_KEY_FILE`, or [defaultFile]. Generates that
  /// file when it does not exist.
  static void init([String? keyFile]) {
    final path =
        keyFile ?? Platform.environment['MESGD_KEY_FILE'] ?? defaultFile;
    final file = File(path);
    if (file.existsSync()) {
      importJwks(jsonDecode(file.readAsStringSync()) as List<dynamic>);
    } else {
      generate(path);
    }
  }

  /// Generate a P-256 signing key and a 2048-bit RSA encryption key.
  /// Writes the flat JWK array when [path] is given.
  static List<Map<String, dynamic>> generate([String? path]) {
    final rng = _fortuna();
    final domain = ECCurve_secp256r1();
    final ec = ECKeyGenerator()
      ..init(ParametersWithRandom(ECKeyGeneratorParameters(domain), rng));
    final ecPair = ec.generateKeyPair();
    _sigPriv = ecPair.privateKey;
    _sigPub = ecPair.publicKey;

    final rsa = RSAKeyGenerator()
      ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64),
        rng,
      ));
    final rsaPair = rsa.generateKeyPair();
    _encPriv = rsaPair.privateKey;
    _encPub = rsaPair.publicKey;

    final jwks = exportJwks();
    if (path != null) {
      File(path).writeAsStringSync(jsonEncode(jwks));
    }
    return jwks;
  }

  /// Load a flat JWK array. Keys are selected by `use` and `key_ops`.
  static void importJwks(List<dynamic> jwks) {
    final pubSig = _find(jwks, 'sig', 'verify');
    final privSig = _find(jwks, 'sig', 'sign');
    final pubEnc = _find(jwks, 'enc', 'decrypt');
    final privEnc = _find(jwks, 'enc', 'encrypt');

    final curve = ECCurve_secp256r1();
    final point = curve.curve.createPoint(
      _b64urlInt(pubSig['x'] as String),
      _b64urlInt(pubSig['y'] as String),
    );
    _sigPub = ECPublicKey(point, curve);
    _sigPriv = ECPrivateKey(_b64urlInt(privSig['d'] as String), curve);

    final n = _b64urlInt(pubEnc['n'] as String);
    final e = _b64urlInt(pubEnc['e'] as String);
    _encPub = RSAPublicKey(n, e);
    _encPriv = RSAPrivateKey(
      n,
      _b64urlInt(privEnc['d'] as String),
      _b64urlInt(privEnc['p'] as String),
      _b64urlInt(privEnc['q'] as String),
    );
  }

  /// Four-key JWK array: signing public, encrypting public, signing private,
  /// encrypting private.
  static List<Map<String, dynamic>> exportJwks() {
    final pubs = pubJwk();
    final ecPub = Map<String, dynamic>.from(pubs['signing_pub'] as Map);
    final rsaPub = Map<String, dynamic>.from(pubs['encrypting_pub'] as Map);
    final ecPriv = Map<String, dynamic>.from(ecPub);
    ecPriv['key_ops'] = ['sign'];
    ecPriv['d'] = _b64url(_fixed(_signing.d!, 32));
    final rsaPriv = Map<String, dynamic>.from(rsaPub);
    rsaPriv['key_ops'] = ['encrypt'];
    final priv = _encryptionPriv;
    final p = priv.p!;
    final q = priv.q!;
    final d = priv.privateExponent!;
    rsaPriv['d'] = _b64url(_unsigned(d));
    rsaPriv['p'] = _b64url(_unsigned(p));
    rsaPriv['q'] = _b64url(_unsigned(q));
    rsaPriv['dp'] = _b64url(_unsigned(d % (p - BigInt.one)));
    rsaPriv['dq'] = _b64url(_unsigned(d % (q - BigInt.one)));
    rsaPriv['qi'] = _b64url(_unsigned(q.modInverse(p)));
    return [ecPub, rsaPub, ecPriv, rsaPriv];
  }

  /// `{"signing_pub": EC JWK, "encrypting_pub": RSA JWK}`.
  static Map<String, dynamic> pubJwk() {
    final pub = _signingPub.Q!;
    final ecPub = <String, dynamic>{
      'kty': 'EC',
      'crv': 'P-256',
      'use': 'sig',
      'key_ops': ['verify'],
      'x': _b64url(_fixed(pub.x!.toBigInteger()!, 32)),
      'y': _b64url(_fixed(pub.y!.toBigInteger()!, 32)),
    };
    final rsa = _encryptionPub;
    final rsaPub = <String, dynamic>{
      'kty': 'RSA',
      'use': 'enc',
      'key_ops': ['decrypt'],
      'n': _b64url(_unsigned(rsa.modulus!)),
      'e': _b64url(_unsigned(rsa.exponent!)),
    };
    return {'signing_pub': ecPub, 'encrypting_pub': rsaPub};
  }

  /// Sign [message] and return `{"r","s"}` JSON. [message] is hashed with SHA-256.
  static String sign(String message) {
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64));
    signer.init(true, PrivateKeyParameter<ECPrivateKey>(_signing));
    final sig =
        signer.generateSignature(Uint8List.fromList(utf8.encode(message)))
            as ECSignature;
    return jsonEncode({
      'r': _b64url(_fixed(sig.r, 32)),
      's': _b64url(_fixed(sig.s, 32)),
    });
  }

  /// Verify [signatureJson] with the loaded signing public key.
  static bool check(String message, String signatureJson) =>
      _verify(_signingPub, message, signatureJson);

  /// Verify [signatureJson] with a public JWK, or a `pubJwk()` map.
  static bool checkWithPub(
      Map<String, dynamic> pubJwk, String message, String signatureJson) {
    final jwk = _signingJwk(pubJwk);
    final curve = ECCurve_secp256r1();
    final point = curve.curve.createPoint(
      _b64urlInt(jwk['x'] as String),
      _b64urlInt(jwk['y'] as String),
    );
    return _verify(ECPublicKey(point, curve), message, signatureJson);
  }

  /// RSA-OAEP-SHA256 encrypt with the loaded public key. Standard base64.
  static String encrypt(String message) => base64.encode(
      _rsaEncrypt(_encryptionPub, Uint8List.fromList(utf8.encode(message))));

  /// Decrypt a standard-base64 RSA-OAEP ciphertext to a UTF-8 string.
  static String decrypt(String ciphertextBase64) => utf8
      .decode(_rsaDecrypt(_encryptionPriv, base64.decode(ciphertextBase64)));

  /// Encrypt for someone else's public JWK (or a `pubJwk()` map).
  /// [message] may be a string or raw bytes.
  static String encryptWith(Map<String, dynamic> pubJwk, Object message) {
    final jwk = _encryptingJwk(pubJwk);
    final key = RSAPublicKey(
        _b64urlInt(jwk['n'] as String), _b64urlInt(jwk['e'] as String));
    final bytes = message is String
        ? Uint8List.fromList(utf8.encode(message))
        : Uint8List.fromList(message as List<int>);
    return base64.encode(_rsaEncrypt(key, bytes));
  }

  /// Hybrid seal: AES-256-GCM key wrapped with RSA-OAEP-SHA256.
  /// Returns the JSON object `{alg,k,iv,ct,tag}` as a string.
  static String seal(Map<String, dynamic> pubJwk, Object plain) {
    final key = _random(32);
    final iv = _random(12);
    final raw = plain is String
        ? Uint8List.fromList(utf8.encode(plain))
        : Uint8List.fromList(plain as List<int>);
    final gcm = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
    final sealed = gcm.process(raw);
    final split = sealed.length - 16;
    return jsonEncode({
      'alg': 'RSA-OAEP+A256GCM',
      'k': encryptWith(pubJwk, key),
      'iv': base64.encode(iv),
      'ct': base64.encode(sealed.sublist(0, split)),
      'tag': base64.encode(sealed.sublist(split)),
    });
  }

  /// Open a [seal] envelope with the loaded private key. A value without the
  /// hybrid `alg` is treated as a raw RSA-OAEP ciphertext, matching Erlang.
  static String open(String bin) {
    Object? decoded;
    try {
      decoded = jsonDecode(bin);
    } catch (_) {
      return decrypt(bin);
    }
    if (decoded is Map && decoded['alg'] == 'RSA-OAEP+A256GCM') {
      final key =
          _rsaDecrypt(_encryptionPriv, base64.decode(decoded['k'] as String));
      final iv = base64.decode(decoded['iv'] as String);
      final ct = base64.decode(decoded['ct'] as String);
      final tag = base64.decode(decoded['tag'] as String);
      final sealed = Uint8List(ct.length + tag.length)
        ..setRange(0, ct.length, ct)
        ..setRange(ct.length, ct.length + tag.length, tag);
      final gcm = GCMBlockCipher(AESEngine())
        ..init(false, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
      return utf8.decode(gcm.process(sealed));
    }
    return decrypt(bin);
  }

  /// Sign the public JWKs and seal them for [mesgdPub] (a public JWK map).
  static String register(Map<String, dynamic> mesgdPub) {
    final payload = jsonEncode(pubJwk());
    final envelope =
        jsonEncode({'payload': payload, 'signature': sign(payload)});
    return seal(mesgdPub, envelope);
  }

  static Map<String, dynamic> _find(List<dynamic> jwks, String use, String op) {
    for (final item in jwks) {
      if (item is! Map) continue;
      final jwk = Map<String, dynamic>.from(item);
      final ops = jwk['key_ops'];
      if (jwk['use'] == use && ops is List && ops.contains(op)) return jwk;
    }
    throw StateError('JWK array is missing $use/$op');
  }

  static Map<String, dynamic> _signingJwk(Map<String, dynamic> pubJwk) {
    final inner = pubJwk['signing_pub'];
    if (inner is Map) return Map<String, dynamic>.from(inner);
    return pubJwk;
  }

  static Map<String, dynamic> _encryptingJwk(Map<String, dynamic> pubJwk) {
    final inner = pubJwk['encrypting_pub'];
    if (inner is Map) return Map<String, dynamic>.from(inner);
    return pubJwk;
  }

  static bool _verify(ECPublicKey key, String message, String signatureJson) {
    try {
      final obj = jsonDecode(signatureJson) as Map<String, dynamic>;
      final r = _b64urlInt(obj['r'] as String);
      final s = _b64urlInt(obj['s'] as String);
      final verifier = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64));
      verifier.init(false, PublicKeyParameter<ECPublicKey>(key));
      return verifier.verifySignature(
        Uint8List.fromList(utf8.encode(message)),
        ECSignature(r, s),
      );
    } catch (_) {
      return false;
    }
  }

  static Uint8List _rsaEncrypt(RSAPublicKey key, Uint8List data) {
    final engine = OAEPEncoding.withSHA256(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(key));
    return engine.process(data);
  }

  static Uint8List _rsaDecrypt(RSAPrivateKey key, List<int> data) {
    final engine = OAEPEncoding.withSHA256(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(key));
    return engine.process(Uint8List.fromList(data));
  }

  static ECPrivateKey get _signing {
    final key = _sigPriv;
    if (key == null)
      throw StateError('PKI.init or PKI.generate must be called first');
    return key;
  }

  static ECPublicKey get _signingPub {
    final key = _sigPub;
    if (key == null)
      throw StateError('PKI.init or PKI.generate must be called first');
    return key;
  }

  static RSAPublicKey get _encryptionPub {
    final key = _encPub;
    if (key == null)
      throw StateError('PKI.init or PKI.generate must be called first');
    return key;
  }

  static RSAPrivateKey get _encryptionPriv {
    final key = _encPriv;
    if (key == null)
      throw StateError('PKI.init or PKI.generate must be called first');
    return key;
  }
}

final _randomSource = Random.secure();

Uint8List _random(int n) {
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = _randomSource.nextInt(256);
  }
  return out;
}

FortunaRandom _fortuna() {
  final rng = FortunaRandom();
  rng.seed(KeyParameter(_random(32)));
  return rng;
}

String _b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List _b64urlDec(String value) {
  final pad = (4 - value.length % 4) % 4;
  return base64Url.decode(value + ('=' * pad));
}

BigInt _b64urlInt(String value) => _unsignedInt(_b64urlDec(value));

BigInt _unsignedInt(List<int> bytes) {
  var n = BigInt.zero;
  for (final b in bytes) {
    n = (n << 8) | BigInt.from(b & 0xff);
  }
  return n;
}

Uint8List _unsigned(BigInt n) {
  if (n.isNegative) throw ArgumentError('negative integer');
  if (n == BigInt.zero) return Uint8List.fromList([0]);
  final size = (n.bitLength + 7) >> 3;
  final out = Uint8List(size);
  var v = n;
  for (var i = size - 1; i >= 0; i--) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return out;
}

Uint8List _fixed(BigInt n, int length) {
  final raw = _unsigned(n);
  if (raw.length > length)
    throw StateError('integer does not fit in $length bytes');
  if (raw.length == length) return raw;
  final out = Uint8List(length);
  out.setRange(length - raw.length, length, raw);
  return out;
}
