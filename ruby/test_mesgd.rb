require 'minitest/autorun'
require 'json'
require_relative 'pki'

FIXTURES = File.join(__dir__, '..', 'fixtures')
JWKS_FILE = File.join(FIXTURES, 'jwks.json')
ALICE = File.join(FIXTURES, 'test_mesgd_alice.json')
BOB = File.join(FIXTURES, 'test_mesgd_bob.json')

class TestMesgdProtocol < Minitest::Test
  def teardown
    [ALICE, BOB].each { |p| File.delete(p) if File.exist?(p) }
    PKI.init(JWKS_FILE)
  end

  def test_two_party_encrypt
    PKI.generate(ALICE)
    alice_pub = PKI.pub_jwk
    PKI.generate(BOB)
    ct = PKI.encrypt_with(alice_pub, 'secret from bob')
    PKI.init(ALICE)
    assert_equal 'secret from bob', PKI.decrypt(ct)
  end

  def test_signed_encrypted_message
    PKI.generate(ALICE)
    alice_pub = PKI.pub_jwk
    PKI.generate(BOB)
    plain = 'ping'
    sig = PKI.sign(plain)
    envelope = JSON.generate('payload' => plain, 'signature' => sig)
    ct = PKI.encrypt_with(alice_pub, envelope)
    PKI.init(ALICE)
    opened = JSON.parse(PKI.decrypt(ct))
    assert_equal plain, opened['payload']
    refute PKI.check_with_pub(alice_pub, opened['payload'], opened['signature'])
    PKI.init(BOB)
    assert PKI.check(plain, sig)
  end

  def test_compact_register_envelope
    PKI.init(JWKS_FILE)
    mesgd_pub = PKI.pub_jwk
    PKI.generate(ALICE)
    payload = JSON.generate('name' => 'alice')
    envelope = JSON.generate('payload' => payload, 'signature' => PKI.sign(payload))
    ct = PKI.encrypt_with(mesgd_pub, envelope)
    alice_pub = PKI.pub_jwk
    PKI.init(JWKS_FILE)
    opened = JSON.parse(PKI.decrypt(ct))
    assert_equal 'alice', JSON.parse(opened['payload'])['name']
    assert PKI.check_with_pub(alice_pub, opened['payload'], opened['signature'])
  end

  def test_live_register_auth_message
    skip 'set MESGD_URL for live mesgd' unless ENV['MESGD_URL']
    skip 'mesgd HTTP JWK registration is not wired yet'
  end
end
