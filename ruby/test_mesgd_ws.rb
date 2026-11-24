# Transport framing tests (no server): plain / signed / sealed frame building
# and decode+dispatch, exercising the seal/open path.

require 'minitest/autorun'
require 'json'
require_relative 'pki'
require_relative 'mesgd'

JWKS_FILE = File.join(__dir__, '..', 'fixtures', 'jwks.json')

class TestMesgdTransport < Minitest::Test
  def setup
    PKI.init(JWKS_FILE)
    @conn = Mesgd.new(nil, PKI, PKI.pub_jwk) # socket unused; drive frame/dispatch directly
  end

  def test_plain_frame
    wire = JSON.parse(@conn.__send__(:frame,
      { 'to' => 'x/y', 'type' => 'ping', 'body' => { 'a' => 1 } }, false, false))
    assert wire.key?('body')
    refute wire.key?('enc')
    refute wire.key?('sig')
  end

  def test_signed_sealed_roundtrip
    wire_str = @conn.__send__(:frame,
      { 'to' => 'agents/alice/inbox', 'type' => 'task.request',
        'body' => { 'cap' => 'summarize', 'n' => 3 } }, true, true)
    wire = JSON.parse(wire_str)
    assert wire.key?('enc')                        # sealed
    refute wire.key?('body')                       # body hidden
    assert_equal 'agents/alice/inbox', wire['to']  # routable cleartext
    assert wire.key?('sig')

    got = nil
    @conn.on('task.request') { |m| got = m }
    @conn.__send__(:dispatch, wire_str)
    assert_equal 'task.request', got['type']
    assert_equal 'summarize', got['body']['cap']   # sealed body recovered
    assert PKI.check_with_pub(PKI.pub_jwk, JSON.generate(got['body']), got['sig'])
  end
end
