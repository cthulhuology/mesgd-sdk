require 'openssl'
require 'base64'
require 'fileutils'

module PKI
  FILE = 'pki_keys.bin'.freeze
  CURVE = 'prime256v1'.freeze
  RSA_OPTS = OpenSSL::RSA::PKCS1_OAEP_PADDING
  RSA_BITS = 2048

  def self.init
    if File.exist?(FILE)
      keys = Marshal.load(File.binread(FILE))
      @signing_priv = keys[:signing_priv]
      @signing_pub = keys[:signing_pub]
      @encrypting_priv = keys[:encrypting_priv]
      @encrypting_pub = keys[:encrypting_pub]
    else
      @signing_priv = OpenSSL::PKey::EC.new(CURVE)
      @signing_priv.generate_key
      @signing_pub = @signing_priv.public_key

      @encrypting_priv = OpenSSL::PKey::RSA.generate(RSA_BITS)
      @encrypting_pub = @encrypting_priv.public_key

      keys = {
        signing_priv: @signing_priv,
        signing_pub: @signing_pub,
        encrypting_priv: @encrypting_priv,
        encrypting_pub: @encrypting_pub
      }
      File.binwrite(FILE, Marshal.dump(keys))
    end
  end

  def self.sign(message)
    raise 'Keys not initialized' unless @signing_priv
    digest = OpenSSL::Digest::SHA256.new
    signature = @signing_priv.sign(digest, message)
    Base64.strict_encode64(signature)
  end

  def self.verify(message, signature_b64)
    raise 'Keys not initialized' unless @signing_pub
    digest = OpenSSL::Digest::SHA256.new
    signature = Base64.strict_decode64(signature_b64)
    @signing_pub.verify(digest, signature, message)
  end

  def self.encrypt(message)
    raise 'Keys not initialized' unless @encrypting_pub
    @encrypting_pub.public_encrypt(message, RSA_OPTS)
    Base64.strict_encode64(@encrypting_pub.public_encrypt(message, RSA_OPTS))
  end

  def self.decrypt(ciphertext_b64)
    raise 'Keys not initialized' unless @encrypting_priv
    ciphertext = Base64.strict_decode64(ciphertext_b64)
    @encrypting_priv.private_decrypt(ciphertext, RSA_OPTS)
  end
end
