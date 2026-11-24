// Standalone browser/Node authentication client; no secret storage or PKI dependency.
export class AuthError extends Error {
  constructor(status) { super(`mesgd authentication HTTP ${status}`); this.status = status; }
}
const privateFields = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
function publicKeys(keys) {
  if (!Array.isArray(keys) || keys.length > 2 || keys.some(k => !k || typeof k !== 'object' || Array.isArray(k) || privateFields.some(f => f in k)))
    throw new TypeError('expected at most two public JWKs without private fields');
  return keys;
}
function otp(code) {
  if (typeof code !== 'string' || !/^[0-9]{6}$/.test(code)) throw new TypeError('OTP must be a six-digit string');
  return code;
}
export function httpsTransport(baseURL, fetchImpl = globalThis.fetch) {
  const origin = new URL(baseURL);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/')
    throw new TypeError('expected an HTTPS server origin');
  return async (method, path, body, token) => {
    const headers = {Accept: 'application/json'};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== null) headers['Content-Type'] = 'application/json';
    const response = await fetchImpl(new URL(path, origin), {method, headers,
      body: body === null ? undefined : JSON.stringify(body), redirect: 'error',
      credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(15000)});
    if (!response.ok) return [response.status, {}];
    let result;
    try { result = await response.json(); } catch { throw new Error('invalid authentication response'); }
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('invalid authentication response');
    return [response.status, result];
  };
}
export class AuthClient {
  constructor(transport) { this.transport = transport; }
  async request(method, path, body = null, token = null) {
    const [status, result] = await this.transport(method, path, body, token);
    if (status < 200 || status >= 300) throw new AuthError(status);
    return result;
  }
  signup(user, email, password, keys = []) { return this.request('POST', '/auth/signup', {user, email, password, public_keys: publicKeys(keys)}); }
  confirm(user, enrollment_token, code) { return this.request('POST', '/auth/signup/confirm', {user, enrollment_token, otp: otp(code)}); }
  login(user, password, code) { return this.request('POST', '/auth/login', {user, password, otp: otp(code)}); }
  resetPassword(user, recovery_code, new_password, code) { return this.request('POST', '/auth/password/reset', {user, recovery_code, new_password, otp: otp(code)}); }
  keys(token) { return this.request('GET', '/auth/keys', null, token); }
  setKeys(token, password, code, keys) { return this.request('PUT', '/auth/keys', {password, otp: otp(code), public_keys: publicKeys(keys)}, token); }
  logout(token) { return this.request('POST', '/auth/logout', null, token); }
}
