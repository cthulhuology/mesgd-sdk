# mesgd transport client.
#
# One Mesgd == one wss connection == one path == one JWT; open several for
# several topics or grants. #send/#on are the headline surface. Security is
# opt-in: plain, signed (sig over body), or signed + sealed (body encrypted,
# routable fields left in cleartext).
#
# The WebSocket client is stdlib-only (socket + openssl, no gem), implementing
# just the RFC 6455 client subset mesgd needs: a json subprotocol with the
# bearer token as its second value, masked text frames, and ping/pong.

require 'socket'
require 'openssl'
require 'uri'
require 'json'
require 'base64'
require 'securerandom'
require_relative 'pki'

class Mesgd
  def self.connect(url, token: nil, server_pub: nil, pki: PKI, ssl_context: nil)
    u = URI(url)
    port = u.port || (u.scheme == 'wss' ? 443 : 80)
    sock = TCPSocket.new(u.host, port)
    if u.scheme == 'wss'
      sock = OpenSSL::SSL::SSLSocket.new(sock, ssl_context || OpenSSL::SSL::SSLContext.new)
      sock.hostname = u.host
      sock.connect
    end
    proto = token ? "json, #{token}" : 'json'
    path = u.path.empty? ? '/' : u.path
    path += "?#{u.query}" if u.query
    sock.write("GET #{path} HTTP/1.1\r\nHost: #{u.host}\r\n" \
               "Upgrade: websocket\r\nConnection: Upgrade\r\n" \
               "Sec-WebSocket-Key: #{Base64.strict_encode64(SecureRandom.bytes(16))}\r\n" \
               "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: #{proto}\r\n\r\n")
    conn = new(sock, pki, server_pub)
    conn.__send__(:read_handshake)
    conn
  end

  def initialize(sock, pki, server_pub)
    @sock = sock
    @pki = pki
    @server_pub = server_pub
    @handlers = {}
    @buf = +''.b
  end

  def on(type, &handler)
    @handlers[type] = handler
    self
  end

  def send(message, sign: false, seal: false)
    write_frame(frame(message, sign, seal))
  end

  def recv
    dispatch(read_frame)
  end

  def close
    @sock.close
  end

  private

  def frame(message, sign, seal)
    return JSON.generate(message) unless sign || seal
    body = JSON.generate(message['body'])
    message['sig'] = @pki.sign(body) if sign
    if seal
      message.delete('body')
      message['enc'] = @pki.seal(@server_pub, body)
    end
    JSON.generate(message)
  end

  def dispatch(raw)
    message = JSON.parse(raw)
    message['body'] = JSON.parse(@pki.open(message.delete('enc'))) if message.key?('enc')
    handler = @handlers[message['type']] || @handlers['*']
    handler&.call(message)
  end

  # --- RFC 6455 (client masks; server frames arrive unmasked) ---

  def read_handshake
    @buf << @sock.readpartial(65_536) until @buf.include?("\r\n\r\n")
    head, @buf = @buf.split("\r\n\r\n", 2)
    status = head.split("\r\n", 2)[0]
    raise "mesgd: upgrade failed: #{status}" unless status.include?(' 101 ')
  end

  def read_exact(n)
    @buf << @sock.readpartial(65_536) while @buf.bytesize < n
    data = @buf.byteslice(0, n)
    @buf = @buf.byteslice(n..) || +''.b
    data
  end

  def read_frame
    h = read_exact(2).bytes
    opcode = h[0] & 0x0F
    n = h[1] & 0x7F
    n = read_exact(2).unpack1('n') if n == 126
    n = read_exact(8).unpack1('Q>') if n == 127
    mask = ((h[1] & 0x80) != 0) ? read_exact(4).bytes : nil
    payload = read_exact(n)
    payload = payload.bytes.each_with_index.map { |b, i| b ^ mask[i % 4] }.pack('C*') if mask
    case opcode
    when 0x8 then raise 'mesgd: connection closed'
    when 0x9 then write_frame(payload, 0xA); return read_frame
    when 0xA then return read_frame
    end
    payload
  end

  def write_frame(payload, opcode = 0x1)
    payload = payload.b
    n = payload.bytesize
    head = [0x80 | opcode].pack('C')
    if n < 126
      head += [0x80 | n].pack('C')
    elsif n < 65_536
      head += [0xFE].pack('C') + [n].pack('n')
    else
      head += [0xFF].pack('C') + [n].pack('Q>')
    end
    mask = SecureRandom.bytes(4).bytes
    masked = payload.bytes.each_with_index.map { |b, i| b ^ mask[i % 4] }.pack('C*')
    @sock.write(head + mask.pack('C*') + masked)
  end
end
