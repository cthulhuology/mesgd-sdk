require 'openssl'
require 'base64'
require 'json'

module PKI
  FILE  = 'pki_keys.json'.freeze
  CURVE = 'prime256v1'.freeze
  # SHA-256 for both OAEP digest and MGF1 — requires openssl gem 3.0+ (Ruby 3.1+)
  OAEP_OPTS = { 'rsa_padding_mode' => 'oaep', 'rsa_oaep_md' => 'sha256', 'rsa_mgf1_md' => 'sha256' }.freeze

  # --- base64url helpers ---

  def self.b64url_encode(bin)
    Base64.urlsafe_encode64(bin, padding: false)
  end

  def self.b64url_decode(str)
    str = str.encode('ASCII') if str.respond_to?(:encode)
    Base64.urlsafe_decode64(str + '=' * ((4 - str.length % 4) % 4))
  end

  def self.bn_to_b64url(bn)
    b64url_encode(bn.to_s(2))
  end

  def self.b64url_to_bn(str)
    OpenSSL::BN.new(b64url_decode(str), 2)
  end

  # --- DER construction helpers (OpenSSL 3.0 compatible) ---

  def self._ec_spki_der(point_bytes)
    OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
        OpenSSL::ASN1::ObjectId('prime256v1')
      ]),
      OpenSSL::ASN1::BitString(point_bytes)
    ]).to_der
  end

  def self._ec_pkcs8_der(d_bytes, point_bytes)
    sec1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(OpenSSL::BN.new(1)),
      OpenSSL::ASN1::OctetString(d_bytes),
      OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId('prime256v1')], 0, :CONTEXT_SPECIFIC),
      OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString(point_bytes)], 1, :CONTEXT_SPECIFIC)
    ]).to_der
    OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(OpenSSL::BN.new(0)),
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
        OpenSSL::ASN1::ObjectId('prime256v1')
      ]),
      OpenSSL::ASN1::OctetString(sec1)
    ]).to_der
  end

  def self._rsa_spki_der(n, e)
    rsa_pub = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(n),
      OpenSSL::ASN1::Integer(e)
    ]).to_der
    OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId('rsaEncryption'),
        OpenSSL::ASN1::Null.new(nil)
      ]),
      OpenSSL::ASN1::BitString(rsa_pub)
    ]).to_der
  end

  def self._rsa_pkcs8_der(n, e, d, p, q, dp, dq, qi)
    pkcs1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(OpenSSL::BN.new(0)),
      OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e),
      OpenSSL::ASN1::Integer(d), OpenSSL::ASN1::Integer(p),
      OpenSSL::ASN1::Integer(q), OpenSSL::ASN1::Integer(dp),
      OpenSSL::ASN1::Integer(dq), OpenSSL::ASN1::Integer(qi)
    ]).to_der
    OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(OpenSSL::BN.new(0)),
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId('rsaEncryption'),
        OpenSSL::ASN1::Null.new(nil)
      ]),
      OpenSSL::ASN1::OctetString(pkcs1)
    ]).to_der
  end

  # --- JWK array load/export ---

  def self._find_jwk(jwks, use, op)
    jwks.find { |j| j['use'] == use && Array(j['key_ops']).include?(op) }
  end

  def self._load_jwk_array(jwks)
    pub_sig  = _find_jwk(jwks, 'sig', 'verify')
    priv_sig = _find_jwk(jwks, 'sig', 'sign')
    pub_enc  = _find_jwk(jwks, 'enc', 'decrypt')
    priv_enc = _find_jwk(jwks, 'enc', 'encrypt')

    x = b64url_decode(pub_sig['x']).rjust(32, "\x00")
    y = b64url_decode(pub_sig['y']).rjust(32, "\x00")
    d = b64url_decode(priv_sig['d']).rjust(32, "\x00")
    point = "\x04" + x + y

    @signing_pub  = OpenSSL::PKey.read(_ec_spki_der(point))
    @signing_priv = OpenSSL::PKey.read(_ec_pkcs8_der(d, point))

    n  = b64url_to_bn(pub_enc['n'])
    e  = b64url_to_bn(pub_enc['e'])
    d2 = b64url_to_bn(priv_enc['d'])
    p  = b64url_to_bn(priv_enc['p'])
    q  = b64url_to_bn(priv_enc['q'])
    dp = b64url_to_bn(priv_enc['dp'])
    dq = b64url_to_bn(priv_enc['dq'])
    qi = b64url_to_bn(priv_enc['qi'])

    @encrypting_pub  = OpenSSL::PKey.read(_rsa_spki_der(n, e))
    @encrypting_priv = OpenSSL::PKey.read(_rsa_pkcs8_der(n, e, d2, p, q, dp, dq, qi))
  end

  def self._export_jwk_array
    # Extract EC point from SubjectPublicKeyInfo DER
    spki    = OpenSSL::ASN1.decode(@signing_priv.public_to_der)
    point   = spki.value[1].value          # BIT STRING payload: 0x04 || x || y
    x = point[1, 32]
    y = point[33, 32]

    # Extract d from PKCS#8 DER → SEC1 inner sequence
    pkcs8   = OpenSSL::ASN1.decode(@signing_priv.private_to_der)
    sec1    = OpenSSL::ASN1.decode(pkcs8.value[2].value)
    d_bytes = sec1.value[1].value.rjust(32, "\x00")

    ec_pub  = { 'kty' => 'EC', 'crv' => 'P-256', 'use' => 'sig', 'key_ops' => ['verify'],
                'x' => b64url_encode(x), 'y' => b64url_encode(y) }
    ec_priv = ec_pub.merge('key_ops' => ['sign'], 'd' => b64url_encode(d_bytes))

    # RSA components accessible as read-only BN attributes in OpenSSL 3.0
    rp = @encrypting_priv
    rsa_pub  = { 'kty' => 'RSA', 'use' => 'enc', 'key_ops' => ['decrypt'],
                 'n' => bn_to_b64url(rp.n), 'e' => bn_to_b64url(rp.e) }
    rsa_priv = rsa_pub.merge('key_ops' => ['encrypt'],
                 'd'  => bn_to_b64url(rp.d),
                 'p'  => bn_to_b64url(rp.p),
                 'q'  => bn_to_b64url(rp.q),
                 'dp' => bn_to_b64url(rp.dmp1),
                 'dq' => bn_to_b64url(rp.dmq1),
                 'qi' => bn_to_b64url(rp.iqmp))
    [ec_pub, rsa_pub, ec_priv, rsa_priv]
  end

  # --- Public API ---

  def self.init(path = FILE)
    if File.exist?(path)
      _load_jwk_array(JSON.parse(File.read(path)))
    else
      generate(path)
    end
  end

  def self.generate(path = FILE)
    @signing_priv    = OpenSSL::PKey::EC.generate(CURVE)
    @signing_pub     = OpenSSL::PKey.read(@signing_priv.public_to_der)
    @encrypting_priv = OpenSSL::PKey::RSA.generate(2048)
    @encrypting_pub  = OpenSSL::PKey.read(@encrypting_priv.public_to_der)
    File.write(path, JSON.generate(_export_jwk_array))
  end

  # Returns JSON {"r":"<base64url>","s":"<base64url>"}
  def self.sign(message)
    raise 'Keys not initialized' unless @signing_priv
    der   = @signing_priv.sign(OpenSSL::Digest::SHA256.new, message)
    asn1  = OpenSSL::ASN1.decode(der)
    r_bn  = asn1.value[0].value
    s_bn  = asn1.value[1].value
    r = r_bn.to_s(2).rjust(32, "\x00")
    s = s_bn.to_s(2).rjust(32, "\x00")
    JSON.generate({ 'r' => b64url_encode(r), 's' => b64url_encode(s) })
  end

  # Accepts {"r":"<base64url>","s":"<base64url>"}
  def self.check(message, signature_json)
    raise 'Keys not initialized' unless @signing_pub
    obj   = JSON.parse(signature_json)
    r_bn  = OpenSSL::BN.new(b64url_decode(obj['r']), 2)
    s_bn  = OpenSSL::BN.new(b64url_decode(obj['s']), 2)
    der   = OpenSSL::ASN1::Sequence([
              OpenSSL::ASN1::Integer(r_bn),
              OpenSSL::ASN1::Integer(s_bn)
            ]).to_der
    @signing_pub.verify(OpenSSL::Digest::SHA256.new, der, message)
  rescue OpenSSL::PKey::PKeyError
    false
  end

  def self.encrypt(message)
    raise 'Keys not initialized' unless @encrypting_pub
    Base64.strict_encode64(@encrypting_pub.encrypt(message, OAEP_OPTS))
  end

  def self.decrypt(ciphertext_b64)
    raise 'Keys not initialized' unless @encrypting_priv
    @encrypting_priv.decrypt(Base64.strict_decode64(ciphertext_b64), OAEP_OPTS)
  end

  def self.pub_jwk
    arr = _export_jwk_array
    { 'signing_pub' => arr[0], 'encrypting_pub' => arr[1] }
  end

  def self._unwrap_jwk(pub_jwk, inner)
    return pub_jwk[inner] if pub_jwk.is_a?(Hash) && pub_jwk[inner].is_a?(Hash)
    pub_jwk
  end

  def self.encrypt_with(pub_jwk, message)
    jwk = _unwrap_jwk(pub_jwk, 'encrypting_pub')
    n = b64url_to_bn(jwk['n'])
    e = b64url_to_bn(jwk['e'])
    key = OpenSSL::PKey.read(_rsa_spki_der(n, e))
    Base64.strict_encode64(key.encrypt(message, OAEP_OPTS))
  end

  def self.check_with_pub(pub_jwk, message, signature_json)
    jwk = _unwrap_jwk(pub_jwk, 'signing_pub')
    x = b64url_decode(jwk['x']).rjust(32, "\x00")
    y = b64url_decode(jwk['y']).rjust(32, "\x00")
    key = OpenSSL::PKey.read(_ec_spki_der("\x04" + x + y))
    obj = JSON.parse(signature_json)
    r_bn = OpenSSL::BN.new(b64url_decode(obj['r']), 2)
    s_bn = OpenSSL::BN.new(b64url_decode(obj['s']), 2)
    der = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(r_bn),
      OpenSSL::ASN1::Integer(s_bn)
    ]).to_der
    key.verify(OpenSSL::Digest::SHA256.new, der, message)
  rescue OpenSSL::PKey::PKeyError, JSON::ParserError
    false
  end

  # Hybrid seal matching the reference wire format {alg,k,iv,ct,tag}: a random
  # AES-256-GCM key wrapped with RSA-OAEP-SHA256, so payloads exceed OAEP's cap.
  def self.seal(pub_jwk, plain)
    cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
    key = cipher.random_key
    iv = cipher.random_iv
    ct = cipher.update(plain) + cipher.final
    JSON.generate(
      'alg' => 'RSA-OAEP+A256GCM',
      'k'   => encrypt_with(pub_jwk, key),
      'iv'  => Base64.strict_encode64(iv),
      'ct'  => Base64.strict_encode64(ct),
      'tag' => Base64.strict_encode64(cipher.auth_tag)
    )
  end

  def self.open(sealed_json)
    m = JSON.parse(sealed_json)
    key = @encrypting_priv.decrypt(Base64.strict_decode64(m['k']), OAEP_OPTS)
    cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
    cipher.key = key
    cipher.iv = Base64.strict_decode64(m['iv'])
    cipher.auth_tag = Base64.strict_decode64(m['tag'])
    cipher.update(Base64.strict_decode64(m['ct'])) + cipher.final
  end
end
