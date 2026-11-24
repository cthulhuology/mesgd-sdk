# User authentication with OTP 2FA

The SDK includes standalone auth modules for mesgd's `/auth` JSON API. They
support signup, authenticator enrollment confirmation, password + OTP login,
password reset, bearer sessions, logout, and credential-linked public keys.
Existing PKI APIs and key-file formats are preserved.

## Languages

| Language | Module | HTTP transport | Test coverage |
|---|---|---|---|
| Python | `python/auth.py` — `AuthClient` | Built-in verified HTTPS | Contract and live HTTPS tests |
| JavaScript | `javascript/auth.mjs` — `AuthClient` | Browser/Node fetch | Contract and live HTTPS tests |
| Erlang | `erlang/mesgd_auth_client.erl` | Built-in httpc HTTPS | Contract and live HTTPS tests |
| Go | `go/auth.go` — `pki.AuthClient` | Built-in net/http HTTPS | Contract and live HTTPS tests |
| Ruby | `ruby/auth.rb` — `Mesgd::AuthClient` | Built-in Net::HTTP HTTPS | Contract and live HTTPS tests |
| PHP | `php/auth.php` — `MesgdAuthClient` | Built-in HTTPS streams | Contract and live HTTPS tests |
| C | `c/auth.h`, `auth.c`, `auth_curl.h`, `auth_curl.c` | libcurl or callback | Contract and live HTTPS tests |
| Dart | `dart/lib/auth.dart` — `AuthClient` | Built-in `dart:io` HTTPS | Contract tests and a loopback TLS check; not in `test-auth-live` |
| C++ | `cpp/auth.hpp` — `mesgd::AuthClient` | C libcurl bridge or callback | Contract tests; shares C transport |
| Rust | `mesgd_pki::auth::AuthClient` | Inject a `Transport` implementation | Contract tests |
| Lua | `lua/auth.lua` | Inject a transport function | Contract tests |
| Perl | `perl/MesgdAuth.pm` | Inject a transport coderef | Contract tests |
| Java | `java/MesgdAuth.java` | Inject `MesgdAuth.Transport` | Source provided; not included in the auth test runner |
| C# | `csharp/auth.cs` — `Mesgd.AuthClient` | Inject async `Transport` | Source provided; not included in the auth test runner |
| Kotlin | `kotlin/MesgdAuth.kt` | Inject a transport lambda | Source provided; not included in the auth test runner |
| Swift | `swift/MesgdAuth.swift` | Inject async `Transport` | Source provided; not included in the auth test runner |
| OCaml | `ocaml/auth.ml` — `Auth` | Inject a transport function | Source provided; not included in the auth test runner |
| Haskell | `haskell/MesgdAuth.hs` | Inject `Transport` | Source provided; not included in the auth test runner |
| Forth | `forth/auth.f` | Deferred JSON/HTTPS transport word | Source provided; not included in the auth test runner |

Auth modules are independent of the PKI implementations in the other language
folders. Java/Kotlin use the existing org.json dependency; C# uses
System.Text.Json; Swift uses Foundation; OCaml uses Yojson.Safe; Haskell uses
aeson, containers and text. C/C++ use the bundled cJSON; compile `c/auth.c` and
`3rd-party/cJSON/cJSON.c` into your application, and optionally `c/auth_curl.c`
with libcurl. Rust reuses serde_json, without adding an HTTP crate. Dart's
auth client uses `dart:io` only; `pointycastle` is a dependency of the PKI
library in the same package, not of auth. The OCaml `mesgd_auth` library is
separate from its PKI library.

## Python example

```python
from auth import AuthClient, https_transport

client = AuthClient(https_transport("https://mesgd.example.com"))
enrollment = client.signup("alice", "alice@example.com", password)
# Display enrollment["qr_png_base64"] or enrollment["otpauth_uri"].
# The manual Base32 enrollment key is enrollment["secret"].
session = client.confirm("alice", enrollment["enrollment_token"], "012345")
recovery_codes = session["recovery_codes"]  # Show once for separate safekeeping.
token = session["access_token"]
keys = client.keys(token)
client.logout(token)

# Later, use a fresh code from the authenticator:
session = client.login("alice", password, otp_from_authenticator)
# A forgotten-password reset needs BOTH a saved recovery code and a fresh OTP:
reset = client.reset_password("alice", recovery_code, new_password, fresh_otp)
# Store the replacement recovery codes; all earlier sessions/codes are revoked.
```

`https_transport(..., context=ssl.create_default_context(cafile="ca.pem"))`
can trust a private CA. It still requires certificate and hostname verification.

## JavaScript example

```javascript
import {AuthClient, httpsTransport, AuthError} from './auth.mjs';
const client = new AuthClient(httpsTransport('https://mesgd.example.com'));
try {
  const session = await client.login('alice', password, '012345');
  const publicKeys = await client.keys(session.access_token);
  await client.logout(session.access_token);
} catch (error) {
  if (error instanceof AuthError && error.status === 401) {
    // Ask the user to check their password/authenticator code.
  } else throw error;
}
```

The auth JavaScript module works with browser fetch without importing the
Node-specific PKI module. Browser applications should use the same origin as
mesgd, or configure explicit server-side CORS support for their origin.

## Shared operations and return values

Operation names follow each language's normal casing (e.g. `reset_password`,
`resetPassword`, `ResetPassword`). Erlang takes its transport as the first
argument; C functions take `mesgd_auth *` first and `cJSON **out` last.

| Operation | Arguments, after client/transport | Server endpoint |
|---|---|---|
| signup | user, email, password, public_keys | POST `/auth/signup` |
| confirm | user, enrollment_token, otp | POST `/auth/signup/confirm` |
| login | user, password, otp | POST `/auth/login` |
| reset password | user, recovery_code, new_password, otp | POST `/auth/password/reset` |
| keys | access_token | GET `/auth/keys` |
| set keys | access_token, current_password, fresh_otp, public_keys | PUT `/auth/keys` |
| logout | access_token | POST `/auth/logout` |

Swift names its GET operation `publicKeys` (the remaining method names match
the table). Java and C# require an explicit public-key array for signup;
several other implementations default to an empty array.

Responses are decoded server JSON objects, including the enrollment URI/PNG,
recovery codes, session expiry, and public JWKs. Erlang returns `{ok, Object}`
or `{error, {http, Status}}`; Go/Rust return their normal Result/error forms;
C returns HTTP status (negative for local errors), transfers ownership of a
successful `cJSON *` to the caller, and sets `*out = NULL` on errors. Other
structured clients raise an auth error carrying the HTTP status. Error messages
omit response bodies and credentials; distinguish 400, 401, 409, 429 and 503
using the status. Never automatically retry login/reset/key updates: each
successful OTP is single-use, including across different auth operations.

OTPs are six ASCII digits as strings, such as `"012345"`. Structured clients
validate this before transport; numeric conversion would lose leading zeroes.
Perl stringifies its scalar OTP before JSON encoding. No SDK module generates
or stores authenticator secrets automatically. Applications own enrollment,
recovery-code display, token storage and user prompts. Treat those responses
as secrets and avoid logging or persisting them accidentally.

Sessions are explicit arguments: signup/login/reset send no bearer header;
keys/key updates/logout send the supplied token. The clients never keep a
password, OTP, seed, recovery code, or session token in a key file or singleton.
A reset invalidates existing tokens on the server; discard them in your app.
Send `access_token` as `Authorization: Bearer TOKEN` for HTTP calls, or use
`['json', token]` as the browser WebSocket subprotocol list. A login session
establishes identity without carrying path restrictions. Use an issued grant
token when delivery should be limited to currently assigned patterns. The
server documentation describes the distinction in `docs/messaging/routing.md`.

## Link the user's existing PKI keys

Pass an array containing only the two public JWKs to signup or set_keys.
For example:

```python
pub = PKI.pub_jwk()
client.set_keys(token, password, fresh_otp,
                [pub['signing_pub'], pub['encrypting_pub']])
```

JavaScript uses `Object.values(await PKI.pubJwk())`; Go uses the two values in
`PKI.PubJWK()`. An empty array removes linked keys. Structured clients reject
private JWK fields (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`). The server
validates algorithm, curve and key size and returns canonical public keys.
Never send the full private JWK export/key-file array.

## Supply your application's HTTP stack

Every structured client accepts an injected transport. The common contract is:

```
transport(method, fixed_path, decoded_json_body_or_null, bearer_or_null)
    -> (HTTP_status, decoded_JSON_object)
```

Use each language's declared signature: Go additionally returns an error;
Rust returns Result; Erlang uses method atoms and `undefined`; Java uses Reply;
C/C++ use cJSON pointers and return status; Dart returns
`Future<(int, Map<String, dynamic>)>`; other async clients return a promise or task.
The transport must serialize the body as JSON, set Content-Type and the correct
UTF-8 Content-Length, attach Authorization only when given a token, verify the
server's TLS certificate/hostname, reject redirects, and apply finite timeouts.
The built-in transports implement these rules and do not follow redirects.
C's optional libcurl transport requires curl_global_init before concurrent use.
Lua transports must encode `public_keys` as an array, including its empty table.
Forth accepts pre-encoded JSON bodies and does not parse or validate their
contents; its stack contract and seven endpoint words are documented in auth.f.

Erlang: `T = mesgd_auth_client:https("https://mesgd.example.com")`, then
`mesgd_auth_client:login(T, <<"alice">>, Password, <<"012345">>)`. `https/2`
accepts a list of DER CA certificates for a private CA without disabling checks.
Go: `T, err := pki.HTTPSAuthTransport(origin)` and `client := pki.AuthClient{Transport:T}`.
Ruby: `Mesgd::AuthClient.new(Mesgd::AuthClient.https_transport(origin, ca_file: path))`.
PHP: `new MesgdAuthClient(MesgdAuthClient::httpsTransport(origin))`.
Dart: `AuthClient(httpsTransport('https://mesgd.example.com'))`. Pass a
`SecurityContext` to trust a private CA; certificate and hostname checks stay on.
C: initialize `mesgd_auth_curl_config` with origin/CA, then
`mesgd_auth client = {mesgd_auth_curl_transport, &config}`.

## Tests

`make test-auth` runs the shared seven-operation contract, OTP preservation,
private-key rejection, and error handling for 12 languages: Python, JavaScript,
Ruby, PHP, Perl, Lua, Go, Rust, Erlang, C, C++, and Dart.
It performs no network requests or dependency downloads. Missing tools are
reported as skips. Rust dependencies must already be in the Cargo cache. Dart
packages must already be in the pub cache (`dart pub get`, also run by
`make deps` and `make test-dart`).
Use `python3 tests/test_auth.py --language python` to select a language.
Seven adapters are source-only and are not in that runner: Java, C#, Kotlin,
Swift, OCaml, Haskell, and Forth.

`make test-auth-live` uses installed mesgd beams in `~/.beamer` and launches a
short-lived server bound to loopback with temporary database, keys and a trusted
localhost certificate. It tests the seven native HTTPS clients that have live
drivers (Python, JavaScript, Erlang, Go, Ruby, PHP, and C), including successful
key updates, bad/replayed OTPs, logout, recovery-code rotation and revoked
sessions. Dart's built-in HTTPS client is checked by the contract runner against
a loopback certificate and is not part of this live mesgd pass. Requires Erlang,
OpenSSL, local language runtimes and libcurl development files for C. Everything
it creates is under a temporary directory; it never targets a deployed service.
