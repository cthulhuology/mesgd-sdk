# mesgd authentication; tokens and enrollment secrets are caller-owned.
require 'json'
require 'net/http'
require 'uri'
require 'openssl'
module Mesgd
  class AuthError < StandardError
    attr_reader :status
    def initialize(status); @status = status; super("mesgd authentication HTTP #{status}"); end
  end
  class AuthClient
    def initialize(transport); @transport = transport; end
    def self.https_transport(base_url, ca_file: nil)
      uri = URI(base_url)
      raise ArgumentError, 'expected an HTTPS server origin' unless uri.is_a?(URI::HTTPS) && uri.host && !uri.userinfo && !uri.query && !uri.fragment && ['', '/'].include?(uri.path)
      lambda do |method, path, body, token|
        headers = {'Accept' => 'application/json'}
        headers['Authorization'] = "Bearer #{token}" if token
        headers['Content-Type'] = 'application/json' unless body.nil?
        request = Net::HTTPGenericRequest.new(method, !body.nil?, true, path, headers)
        request.body = JSON.generate(body) unless body.nil?
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.ca_file = ca_file if ca_file
        http.open_timeout = 15; http.read_timeout = 15; http.write_timeout = 15
        response = http.request(request)
        status = response.code.to_i
        next [status, {}] unless (200...300).include?(status)
        begin
          result = JSON.parse(response.body)
          raise JSON::ParserError unless result.is_a?(Hash)
        rescue JSON::ParserError
          raise 'invalid authentication response'
        end
        [status, result]
      end
    end
    def request(method, path, body = nil, token = nil)
      status, result = @transport.call(method, path, body, token)
      raise AuthError.new(status) unless (200...300).include?(status)
      result
    end
    def otp(code)
      raise ArgumentError, 'OTP must be a six-digit string' unless code.is_a?(String) && /\A[0-9]{6}\z/.match?(code)
      code
    end
    def public_keys(keys)
      private_fields = %w[d p q dp dq qi oth k]
      raise ArgumentError, 'expected public JWKs' unless keys.is_a?(Array) && keys.length <= 2 && keys.all? { |k| k.is_a?(Hash) && (k.keys.map(&:to_s) & private_fields).empty? }
      keys
    end
    def signup(user, email, password, keys = [])
      request('POST', '/auth/signup', {user: user, email: email, password: password, public_keys: public_keys(keys)})
    end
    def confirm(user, enrollment_token, code)
      request('POST', '/auth/signup/confirm', {user: user, enrollment_token: enrollment_token, otp: otp(code)})
    end
    def login(user, password, code)
      request('POST', '/auth/login', {user: user, password: password, otp: otp(code)})
    end
    def reset_password(user, recovery_code, new_password, code)
      request('POST', '/auth/password/reset', {user: user, recovery_code: recovery_code, new_password: new_password, otp: otp(code)})
    end
    def keys(token); request('GET', '/auth/keys', nil, token); end
    def set_keys(token, password, code, keys)
      request('PUT', '/auth/keys', {password: password, otp: otp(code), public_keys: public_keys(keys)}, token)
    end
    def logout(token); request('POST', '/auth/logout', nil, token); end
  end
end
