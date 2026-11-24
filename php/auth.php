<?php
/** mesgd authentication. Decoded secrets/tokens remain caller-owned. */
class MesgdAuthError extends RuntimeException {
    public int $status;
    public function __construct(int $status) { $this->status = $status; parent::__construct("mesgd authentication HTTP $status"); }
}
class MesgdAuthClient {
    private $transport;
    public function __construct(callable $transport) { $this->transport = $transport; }
    public static function httpsTransport(string $origin): callable {
        $u = parse_url($origin);
        if (!$u || ($u['scheme'] ?? '') !== 'https' || empty($u['host']) || isset($u['user']) || isset($u['pass']) || isset($u['query']) || isset($u['fragment']) || !in_array($u['path'] ?? '', ['', '/'], true)) throw new InvalidArgumentException('expected an HTTPS server origin');
        return function($method, $path, $body, $token) use ($origin) {
            $headers = "Accept: application/json\r\n";
            if ($token !== null) {
                if (strpbrk($token, "\r\n") !== false) throw new InvalidArgumentException('invalid bearer token');
                $headers .= "Authorization: Bearer $token\r\n";
            }
            $payload = $body === null ? '' : json_encode($body, JSON_THROW_ON_ERROR);
            if ($body !== null) $headers .= "Content-Type: application/json\r\n";
            $headers .= 'Content-Length: '.strlen($payload)."\r\n";
            $context = stream_context_create(['http' => ['method' => $method, 'header' => $headers, 'content' => $payload, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 15], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
            $stream = @fopen(rtrim($origin, '/').$path, 'rb', false, $context);
            if ($stream === false) throw new RuntimeException('authentication transport failed');
            try {
                $meta = stream_get_meta_data($stream);
                $responseHeaders = $meta['wrapper_data'] ?? [];
                if (!preg_match('/^HTTP\/\S+ ([0-9]{3})/', $responseHeaders[0] ?? '', $m)) throw new RuntimeException('invalid authentication response');
                $status = (int)$m[1];
                if ($status < 200 || $status >= 300) return [$status, []];
                $length = null;
                foreach ($responseHeaders as $header) {
                    if (preg_match('/^Content-Length: *([0-9]+)$/i', $header, $match)) $length = (int)$match[1];
                }
                if ($length === null || $length > 1048576) throw new RuntimeException('invalid authentication response length');
                $raw = '';
                while (strlen($raw) < $length) {
                    $part = fread($stream, $length - strlen($raw));
                    if ($part === false || $part === '') throw new RuntimeException('incomplete authentication response');
                    $raw .= $part;
                }
            } finally { fclose($stream); }
            try { $result = json_decode($raw, true, 512, JSON_THROW_ON_ERROR); } catch (JsonException $e) { throw new RuntimeException('invalid authentication response'); }
            if (!is_array($result)) throw new RuntimeException('invalid authentication response');
            return [$status, $result];
        };
    }
    private function request($method, $path, $body = null, $token = null) {
        [$status, $result] = ($this->transport)($method, $path, $body, $token);
        if ($status < 200 || $status >= 300) throw new MesgdAuthError($status);
        return $result;
    }
    private function otp($code) {
        if (!is_string($code) || !preg_match('/\A[0-9]{6}\z/', $code)) throw new InvalidArgumentException('OTP must be a six-digit string');
        return $code;
    }
    private function publicKeys(array $keys): array {
        if (count($keys) > 2) throw new InvalidArgumentException('expected at most two public JWKs');
        foreach ($keys as $key) {
            if (!is_array($key) || array_intersect(array_keys($key), ['d','p','q','dp','dq','qi','oth','k'])) throw new InvalidArgumentException('expected public JWKs');
        }
        return array_values($keys);
    }
    public function signup($user, $email, $password, array $keys = []) { return $this->request('POST', '/auth/signup', ['user'=>$user,'email'=>$email,'password'=>$password,'public_keys'=>$this->publicKeys($keys)]); }
    public function confirm($user, $enrollment, $code) { return $this->request('POST', '/auth/signup/confirm', ['user'=>$user,'enrollment_token'=>$enrollment,'otp'=>$this->otp($code)]); }
    public function login($user, $password, $code) { return $this->request('POST', '/auth/login', ['user'=>$user,'password'=>$password,'otp'=>$this->otp($code)]); }
    public function resetPassword($user, $recovery, $password, $code) { return $this->request('POST', '/auth/password/reset', ['user'=>$user,'recovery_code'=>$recovery,'new_password'=>$password,'otp'=>$this->otp($code)]); }
    public function keys($token) { return $this->request('GET', '/auth/keys', null, $token); }
    public function setKeys($token, $password, $code, array $keys) { return $this->request('PUT', '/auth/keys', ['password'=>$password,'otp'=>$this->otp($code),'public_keys'=>$this->publicKeys($keys)], $token); }
    public function logout($token) { return $this->request('POST', '/auth/logout', null, $token); }
}
