require 'openssl'
require 'base64'
require 'json'

module PKI
  FILE   = 'pki_keys.json'.freeze
  CURVE  = 'prime256v1'.freeze
  # SHA-256 for both OAEP digest and MGF1 — requires openssl gem 3.0+ (Ruby 3.1+)
  OAEP_OPTS = { 'rsa_padding_mode' => 'oaep', 'rsa_oaep_md' => 'sha256', 'rsa_mgf1_md' => 'sha256' }.freeze

  def self.b64url_encode(bin)
    Base64.urlsafe_encode64(bin, padding: false)
  end

  def self.b64url_decode(str)
    Base64.urlsafe_decode64(str + '=' * ((4 - str.length % 4) % 4))
  end

  def self.bn_to_b64url(bn)
    b64url_encode(bn.to_s(2).bytes.pack('C*'))
  end

  def self.b64url_to_bn(str)
    OpenSSL::BN.new(b64url_decode(str), 2)
  end

  def self._find_jwk(jwks, use, op)
    jwks.find { |j| j['use'] == use && Array(j['key_ops']).include?(op) }
  end

  def self._load_jwk_array(jwks)
    pub_sig  = _find_jwk(jwks, 'sig', 'verify')
    priv_sig = _find_jwk(jwks, 'sig', 'sign')
    pub_enc  = _find_jwk(jwks, 'enc', 'decrypt')
    priv_enc = _find_jwk(jwks, 'enc', 'encrypt')

    group = OpenSSL::PKey::EC::Group.new(CURVE)
    x = b64url_decode(pub_sig['x'])
    y = b64url_decode(pub_sig['y'])
    point = OpenSSL::PKey::EC::Point.new(group,
      OpenSSL::BN.new("\x04" + x + y, 2))
    @signing_pub = OpenSSL::PKey::EC.new(group)
    @signing_pub.public_key = point

    d = b64url_to_bn(priv_sig['d'])
    @signing_priv = OpenSSL::PKey::EC.new(group)
    @signing_priv.public_key = point
    @signing_priv.private_key = d

    n  = b64url_to_bn(pub_enc['n'])
    e  = b64url_to_bn(pub_enc['e'])
    d2 = b64url_to_bn(priv_enc['d'])
    p  = b64url_to_bn(priv_enc['p'])
    q  = b64url_to_bn(priv_enc['q'])
    dp = b64url_to_bn(priv_enc['dp'])
    dq = b64url_to_bn(priv_enc['dq'])
    qi = b64url_to_bn(priv_enc['qi'])

    pub_nums  = OpenSSL::PKey::RSA.new
    pub_nums.set_key(n, e, nil)
    @encrypting_pub = pub_nums

    rsa = OpenSSL::PKey::RSA.new
    rsa.set_key(n, e, d2)
    rsa.set_factors(p, q)
    rsa.set_crt_params(dp, dq, qi)
    @encrypting_priv = rsa
  end

  def self._export_jwk_array
    pub = @signing_priv.public_key.to_bn.to_s(2)
    # uncompressed point: 0x04 || x(32) || y(32)
    x = pub[1, 32]
    y = pub[33, 32]
    d = @signing_priv.private_key.to_s(2).bytes.pack('C*')
    d = d.rjust(32, "\x00")

    ec_pub  = { 'kty' => 'EC', 'crv' => 'P-256', 'use' => 'sig', 'key_ops' => ['verify'],
                'x' => b64url_encode(x), 'y' => b64url_encode(y) }
    ec_priv = ec_pub.merge('key_ops' => ['sign'], 'd' => b64url_encode(d))

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

  def self.init(path = FILE)
    if File.exist?(path)
      _load_jwk_array(JSON.parse(File.read(path)))
    else
      generate(path)
    end
  end

  def self.generate(path = FILE)
    @signing_priv    = OpenSSL::PKey::EC.generate(CURVE)
    @signing_pub     = @signing_priv
    @encrypting_priv = OpenSSL::PKey::RSA.generate(2048)
    @encrypting_pub  = @encrypting_priv
    File.write(path, JSON.generate(_export_jwk_array))
  end

  def self.sign(message)
    raise 'Keys not initialized' unless @signing_priv
    digest = OpenSSL::Digest::SHA256.new
    der    = @signing_priv.sign(digest, message)
    # Parse DER SEQUENCE { INTEGER r, INTEGER s } → {"r":b64url,"s":b64url}
    asn1   = OpenSSL::ASN1.decode(der)
    r = asn1.value[0].value.to_s(2).bytes.pack('C*').rjust(32, "\x00")
    s = asn1.value[1].value.to_s(2).bytes.pack('C*').rjust(32, "\x00")
    JSON.generate({ 'r' => b64url_encode(r), 's' => b64url_encode(s) })
  end

  def self.verify(message, signature_json)
    raise 'Keys not initialized' unless @signing_pub
    sig   = JSON.parse(signature_json)
    r_bn  = OpenSSL::BN.new(b64url_decode(sig['r']), 2)
    s_bn  = OpenSSL::BN.new(b64url_decode(sig['s']), 2)
    der   = OpenSSL::ASN1::Sequence([
              OpenSSL::ASN1::Integer(r_bn),
              OpenSSL::ASN1::Integer(s_bn)
            ]).to_der
    digest = OpenSSL::Digest::SHA256.new
    @signing_pub.verify(digest, der, message)
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
end
