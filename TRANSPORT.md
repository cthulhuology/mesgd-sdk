# mesgd transport layer

The message transport is implemented in seven SDK languages: C, Dart, Go, JavaScript, Python, Ruby, and Rust. `erlang/mesgd.erl` is the process-based reference. These wrappers sit alongside `auth` and `pki`: account clients obtain sessions, PKI libraries hold identities, and the transport publishes and receives JSON over WebSocket.

Each connection owns one subscription path and one bearer. Incoming messages match that path at the broker; local `on` handlers then select a callback by `type`. Open a separate connection for each additional subscription or credential. A local handler registration is not a broker subscribe request.

## Current interfaces

| Language | Source | Connect | Publish | Dispatch registration | Receive | Close |
| --- | --- | --- | --- | --- | --- | --- |
| C | `c/mesgd.h`, `c/mesgd.c` | `mesgd_connect` | `mesgd_send` | `mesgd_on` | `mesgd_recv` | `mesgd_close` |
| Dart | `dart/lib/transport.dart` | `Mesgd.connect` | `send` | `on` | `recv` / `listen` | `close` |
| Go | `go/mesgd.go` | `Connect` | `Conn.Send` | `Conn.On` | `Conn.Recv` | `Conn.Close` |
| JavaScript | `javascript/mesgd.mjs` | `Mesgd.connect` | `send` | `on` | Runtime events | `close` |
| Python | `python/mesgd.py` | `Mesgd.connect` | `send` | `on` | `recv` | `close` |
| Ruby | `ruby/mesgd.rb` | `Mesgd.connect` | `send` | `on` | `recv` | `close` |
| Rust | `rust/mesgd.rs` | `mesgd::connect` | `Conn::send` | `Conn::on` | `Conn::recv` | `Conn::close` |
| Erlang reference | `erlang/mesgd.erl` | `connect/1,2` | `send/2,3` | `on/3` | Connection process | `close/1` |

The Dart library is package `mesgd` (`package:mesgd/mesgd.dart`). The Go package is still named `pki` within module `mesgd-sdk`; applications may alias the import to `mesgd`. The Rust module is `mesgd_pki::mesgd`.

Per-function definitions, option types, and complete service/client programs are maintained in the mesgd documentation source under `docs/sdk/` in the mesgd repository and rendered into the mesgd.org static documentation:

- [Transport contract](https://mesgd.org/docs/sdk/transport.html)
- [Pub/sub setup and programs](https://mesgd.org/docs/sdk/pubsub.html)
- [C](https://mesgd.org/docs/sdk/c.html)
- [Go](https://mesgd.org/docs/sdk/go.html)
- [JavaScript](https://mesgd.org/docs/sdk/javascript.html)
- [Python](https://mesgd.org/docs/sdk/python.html)
- [Ruby](https://mesgd.org/docs/sdk/ruby.html)
- [Rust](https://mesgd.org/docs/sdk/rust.html)

Those pages cover C, Go, JavaScript, Python, Ruby, and Rust. Dart's interface is the table above and `dart/lib/transport.dart`; a mesgd.org page for it is not published yet.

## Wire contract

Connect to `wss://HOST[:PORT]/<subscription-pattern>`. Publish a JSON text frame with visible routing fields. A subscriber at `/to=service` receives a message whose top-level `to` equals `service`. The `type` field chooses the local callback; `body` carries application data.

Authentication travels as the second `json` subprotocol value or as an HTTP bearer header where the underlying client permits it. The current broker's subprotocol parsing requires the exact `json, TOKEN` spacing, and some WebSocket header lookups are case-sensitive. Dart sends `Sec-WebSocket-Protocol: json, TOKEN` by default. `Mesgd.connect(..., bearerHeader: true)` sends `Authorization: Bearer TOKEN` and offers only `json`. The complete JavaScript program injects a `ws` adapter that does the same bearer-header selection, avoiding that incompatibility. The unmodified JavaScript module also imports Node filesystem code through PKI, so it is not directly browser-loadable.

## Cryptographic options

Signing and sealing default off. Enabling signing adds `sig` over the serialized `body`. Enabling sealing replaces `body` with hybrid-encrypted `enc`, leaving routing fields visible. The key named `server_pub`, `serverPub`, or `ServerPub` is the outgoing recipient public encryption key; it need not belong to the broker.

Receive dispatch opens an incoming sealed body but does not verify its signature. Applications select the expected sender key and call the PKI verification operation themselves. Signatures cover body bytes, not routing fields, and the wrappers do not define canonical JSON across languages. Verify the exact serialization used by the sender rather than assuming any reserialization is equivalent.

## Limits and remaining work

The socket wrappers in Python, Go, Ruby, and Rust implement a limited RFC6455 subset: they do not validate the expected upgrade accept value or assemble fragmented data messages. JavaScript delegates those operations to its WebSocket implementation. Dart implements them in the client: it checks `Sec-WebSocket-Accept`, reassembles fragmented data frames, and answers ping with pong. It does not negotiate permessage-deflate. C delegates connection setup to libcurl but does not accumulate receive chunks, handle control metadata at the wrapper layer, or resume partial writes; its receive return code also combines would-block and transport failures. The C example therefore uses small frames and bounded retries.

HTTPS message publish/long-poll, SSE, automatic reconnection, delivery acknowledgments, session refresh, and automatic signature verification are not exposed by the current wrapper APIs. Account HTTPS is a separate implemented interface. The old ping/pong sample registration workflow is not required by these wrappers and has not been implemented by the server merely by adding them.

## Validation

| Language | Status |
| --- | --- |
| Erlang | Process reference. Protocol tests cover register, two-party encrypt, and signed envelopes. |
| C, Go, JavaScript, Python, Ruby, Rust | Built or syntax-checked and run as both service and caller against an isolated mesgd broker with a temporary account and private CA. Each service also received a request from another language. Plain, signed, and sealed framing and dispatch were checked separately. |
| Dart | Implemented. Local tests cover handshake accept validation, `json, TOKEN` and bearer-header authentication, plain/signed/sealed framing, fragmented delivery, ping/pong, and close. Not included in the isolated-broker pass above. |

These checks establish the demonstrated local flows, not full WebSocket conformance or production recovery behavior.
