"""mesgd password + OTP authentication. Secrets are never persisted by this module."""
import json
import re
import ssl
from urllib.parse import urlsplit
from http.client import HTTPSConnection

class AuthError(Exception):
    def __init__(self, status):
        self.status = status
        super().__init__(f"mesgd authentication HTTP {status}")

PRIVATE = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

def public_keys(keys):
    if not isinstance(keys, list) or len(keys) > 2:
        raise ValueError("expected at most two public JWKs")
    if any(not isinstance(k, dict) or PRIVATE.intersection(k) for k in keys):
        raise ValueError("private JWKs are not accepted")
    return keys

def otp(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{6}", value):
        raise ValueError("OTP must be a six-digit string")
    return value

def https_transport(base_url, *, context=None, timeout=15):
    url = urlsplit(base_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("expected an HTTPS server origin")
    context = context or ssl.create_default_context()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ValueError("TLS certificate and hostname verification are required")
    def send(method, path, body, token):
        headers = {"Accept": "application/json"}
        if token:
            if "\r" in token or "\n" in token: raise ValueError("invalid bearer token")
            headers["Authorization"] = "Bearer " + token
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        if payload is not None: headers["Content-Type"] = "application/json"
        conn = HTTPSConnection(url.hostname, url.port or 443, context=context, timeout=timeout)
        try:
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            raw = response.read(1048577)
            if len(raw) > 1048576: raise ValueError("authentication response too large")
            if not 200 <= response.status < 300: return response.status, {}
            try: result = json.loads(raw)
            except (ValueError, UnicodeError): raise ValueError("invalid authentication response") from None
            if not isinstance(result, dict): raise ValueError("invalid authentication response")
            return response.status, result
        finally: conn.close()
    return send

class AuthClient:
    def __init__(self, transport): self._transport = transport
    def _request(self, method, path, body=None, token=None):
        status, result = self._transport(method, path, body, token)
        if not 200 <= status < 300: raise AuthError(status)
        return result
    def signup(self, user, email, password, keys=None):
        return self._request("POST", "/auth/signup", dict(user=user, email=email, password=password, public_keys=public_keys([] if keys is None else keys)))
    def confirm(self, user, enrollment_token, code):
        return self._request("POST", "/auth/signup/confirm", dict(user=user, enrollment_token=enrollment_token, otp=otp(code)))
    def login(self, user, password, code):
        return self._request("POST", "/auth/login", dict(user=user, password=password, otp=otp(code)))
    def reset_password(self, user, recovery_code, new_password, code):
        return self._request("POST", "/auth/password/reset", dict(user=user, recovery_code=recovery_code, new_password=new_password, otp=otp(code)))
    def keys(self, token): return self._request("GET", "/auth/keys", token=token)
    def set_keys(self, token, password, code, keys):
        return self._request("PUT", "/auth/keys", dict(password=password, otp=otp(code), public_keys=public_keys(keys)), token)
    def logout(self, token): return self._request("POST", "/auth/logout", token=token)
