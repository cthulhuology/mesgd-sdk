\ Transport-level auth adapter for applications supplying JSON/HTTPS.
\ Install an xt with: ' my-https-transport is mesgd-auth-transport
\ xt stack: ( json-a json-u token-a token-u method-a method-u path-a path-u
\             -- response-a response-u http-status )
\ Transport must copy/consume borrowed input during the call, verify TLS,
\ serialize Content-Length, reject redirects, and never log credentials.
\ Use complete JSON objects with OTP as a quoted six-digit string.
\ Public keys must exclude all private JWK fields. This layer does not parse JSON.
defer mesgd-auth-transport
: auth-signup ( json-a json-u -- response-a response-u status )
  0 0 s" POST" s" /auth/signup" mesgd-auth-transport ;
: auth-confirm ( json-a json-u -- response-a response-u status )
  0 0 s" POST" s" /auth/signup/confirm" mesgd-auth-transport ;
: auth-login ( json-a json-u -- response-a response-u status )
  0 0 s" POST" s" /auth/login" mesgd-auth-transport ;
: auth-reset-password ( json-a json-u -- response-a response-u status )
  0 0 s" POST" s" /auth/password/reset" mesgd-auth-transport ;
: auth-keys ( token-a token-u -- response-a response-u status )
  0 0 2swap s" GET" s" /auth/keys" mesgd-auth-transport ;
: auth-set-keys ( json-a json-u token-a token-u -- response-a response-u status )
  s" PUT" s" /auth/keys" mesgd-auth-transport ;
: auth-logout ( token-a token-u -- response-a response-u status )
  0 0 2swap s" POST" s" /auth/logout" mesgd-auth-transport ;
