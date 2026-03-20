require 'minitest/autorun'
require 'json'
require_relative 'pki'

FIXTURES    = File.join(__dir__, '..', 'fixtures')
JWKS_FILE   = File.join(FIXTURES, 'jwks.json')
GEN_FILE    = File.join(FIXTURES, 'test_ruby.json')
SIG_OUT     = File.join(FIXTURES, 'sig_ruby.json')
CROSS_LANGS = %w[erlang python javascript rust go c java].freeze

class TestPKI < Minitest::Test
  def setup
    PKI.init(JWKS_FILE)
  end

  def test_sign_verify_roundtrip
    sig = PKI.sign('Hello World')
    assert PKI.verify('Hello World', sig)
    refute PKI.verify('Wrong message', sig)
  end

  def test_signature_is_json
    sig = PKI.sign('Hello World')
    obj = JSON.parse(sig)
    assert obj.key?('r')
    assert obj.key?('s')
  end

  def test_encrypt_decrypt_roundtrip
    enc = PKI.encrypt('Secret message')
    assert_equal 'Secret message', PKI.decrypt(enc)
  end

  def test_generate_creates_json_file
    File.delete(GEN_FILE) if File.exist?(GEN_FILE)
    PKI.generate(GEN_FILE)
    assert File.exist?(GEN_FILE)
    jwks = JSON.parse(File.read(GEN_FILE))
    assert_instance_of Array, jwks
    assert_equal 4, jwks.length
    ops = jwks.map { |j| j['key_ops'][0] }.to_set
    assert ops.superset?(%w[sign verify encrypt decrypt].to_set)
  end

  def test_generated_keys_work
    PKI.generate(GEN_FILE)
    PKI.init(GEN_FILE)
    sig = PKI.sign('Hello World')
    assert PKI.verify('Hello World', sig)
    enc = PKI.encrypt('Secret')
    assert_equal 'Secret', PKI.decrypt(enc)
    PKI.init(JWKS_FILE)
  end

  def test_write_cross_lang_signature
    PKI.init(JWKS_FILE)
    sig = PKI.sign('Hello World')
    File.write(SIG_OUT, JSON.generate({ lang: 'ruby', message: 'Hello World', signature: sig }))
  end

  def test_verify_cross_lang_signatures
    PKI.init(JWKS_FILE)
    CROSS_LANGS.each do |lang|
      path = File.join(FIXTURES, "sig_#{lang}.json")
      next unless File.exist?(path)
      rec = JSON.parse(File.read(path))
      assert PKI.verify(rec['message'], rec['signature']), "failed to verify #{lang} signature"
    end
  end
end
