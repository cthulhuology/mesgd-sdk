# pki.rb (from earlier)
require 'openssl'
require 'base64'
require 'fileutils'

module PKI
  # ... (full module from original Ruby implementation)
end

# test_pki.rb
require 'minitest/autorun'
require_relative 'pki'

class TestPKI < Minitest::Test
  def setup
    PKI.init
  end

  def test_sign_verify
    message = 'Hello World'
    sig = PKI.sign(message)
    assert PKI.verify(message, sig)
    refute PKI.verify('Wrong message', sig)
  end

  def test_encrypt_decrypt
    message = 'Secret message'
    enc = PKI.encrypt(message)
    dec = PKI.decrypt(enc)
    assert_equal message, dec
    # Test invalid
    wrong_enc = PKI.encrypt('Different')
    assert_raises { PKI.decrypt(wrong_enc + 'invalid') }
  end

  def test_init_twice
    original_size = File.size(PKI::FILE)
    PKI.init
    assert_equal original_size, File.size(PKI::FILE)
  end
end
