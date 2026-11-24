# mesgd Agent Communication Protocol

## Purpose

This document describes how AI agents (and any other software agents) use mesgd
as their communication backbone — replacing RPC calls, HTTP API invocations, and
MCP tool calls with a cryptographically secure, topic-routed message bus.

If you are an LLM or agent reading this document to understand how to participate
in a mesgd network: this document tells you everything you need. Read it from top
to bottom once, then follow the **Agent Startup Checklist** at the end.

---

## The Core Idea

Traditional agent-to-agent communication requires upfront agreement on protocols,
open ports, service discovery infrastructure, and shared secrets. mesgd replaces
all of that with a single WebSocket connection and public-key cryptography.

Instead of:
```
agent_b.call("summarize", { text: "..." })     # RPC
await mcp.invoke("summarize", { text: "..." }) # MCP tool call
POST https://agent-b.internal/summarize        # HTTP
```

You write:
```
mesgd.send("agents/agent-b-id/inbox", {
  type: "task.request",
  capability: "summarize",
  input: { text: "..." },
  reply_to: "agents/my-id/inbox"
})
```

The wire is the same in both directions, every message is signed and optionally
encrypted, anyone can verify any message, and only the intended recipient can
read a private one.

---

## Mental Model: WebSocket as stdin / stdout / stderr

An agent's mesgd connection works exactly like a Unix process's standard streams,
but with routing and cryptography built in:

```
                         ┌──────────────────────┐
  other agents ──────▶   │  mesgd.receive()      │  ← stdin
  (messages arrive)      │  (blocking/async)     │
                         │                       │
                         │  agent logic          │
                         │  (process message)    │
                         │                       │
  other agents  ◀──────  │  mesgd.send(to, msg) │  → stdout
  (responses sent)       │                       │
                         │  mesgd.send(status,…) │  → stderr
                         └──────────────────────┘
```

- `receive()` reads the next inbound message — a frame arrives, is decrypted,
  the sender's signature is verified, and the plaintext envelope is returned.
- `send(to, message)` signs the envelope with our signing key, encrypts it with
  the recipient's public key (or the topic's distribution key), and transmits it.
- Status updates, errors, and heartbeats go to a separate `status` topic — the
  equivalent of stderr — so they don't interfere with the task stream.

The agent's main loop is literally:

```python
async for message in mesgd.messages():
    response = await handle(message)
    if response:
        await mesgd.send(message.reply_to, response)
```

---

## Agent Identity

Every agent has a stable cryptographic identity consisting of two key pairs:

| Key | Algorithm | Purpose |
|-----|-----------|---------|
| `signing_priv` / `signing_pub` | ECDSA P-256 | Sign outbound messages; prove identity |
| `encrypting_priv` / `encrypting_pub` | RSA-2048-OAEP / SHA-256 | Decrypt inbound messages |

The **agent ID** is the SHA-256 fingerprint of the signing public key, encoded as
base64url without padding. This is self-certifying: given an agent's public key
you can verify their ID without a third party.

```
agent_id = base64url( SHA-256( DER-encode( signing_pub ) ) )
```

Keys are generated once by `PKI.init()` / `Mesgd.connect()` and persisted to
`mesgd_keys.json` in the working directory. The same keys survive restarts, so
the agent's identity is stable across sessions.

---

## Topic Structure

Topics are hierarchical path strings. mesgd routes messages by matching topic
paths against JWT claims held by the sender and receiver.

### Reserved system topics

```
mesgd/agents/announce              Capability broadcasts (unencrypted, signed)
mesgd/agents/directory             Agent registry queries and responses
mesgd/tasks/{domain}/{verb}        Task fan-out (encrypted to domain distribution key)
```

### Per-agent topics

```
agents/{agent_id}/inbox            Direct messages to this agent (encrypted)
agents/{agent_id}/status           Heartbeats and status updates (signed, not encrypted)
agents/{agent_id}/capabilities     This agent's capability manifest (signed, not encrypted)
```

### Task result topics

```
tasks/{domain}/{verb}/results/{correlation_id}    Response delivery point
```

### Naming conventions

- Use lowercase, hyphens for word separation within a segment: `text-analysis`
- Domains group related capabilities: `search`, `code`, `data`, `image`, `text`
- Verbs describe the action: `summarize`, `translate`, `embed`, `classify`
- Wildcards in subscriptions: `agents/*/inbox` (if granted by JWT), `tasks/search/*`

---

## Message Envelope Format

Every message sent over mesgd — whether a task request, a response, a capability
announcement, or an error — uses the same outer envelope structure. The envelope
is a JSON object. It is signed by the sender and, for private messages, encrypted
for the recipient.

```json
{
  "type":       "task.request",
  "version":    "1",
  "id":         "01HX5K-A3B7-ZQNM",
  "from":       "sQ5Fz2mR8uY4bL0i",
  "to":         "kJ9nWpVt3xC6dE1f",
  "sent_at":    "2026-03-16T12:00:00Z",
  "body":       { ... }
}
```

### Envelope fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Message type (see types below) |
| `version` | string | Protocol version, currently `"1"` |
| `id` | string | Unique message ID (UUIDv7 or ULID recommended for time-ordering) |
| `from` | string | Sender's `agent_id` |
| `to` | string | Recipient's `agent_id` or topic name |
| `sent_at` | ISO 8601 | Wall-clock time at send |
| `body` | object | Type-specific payload (defined per type below) |

### Wire format

The envelope JSON is serialised to a compact string, then processed by the SDK:

```
plaintext_envelope_json
    ↓  sign with sender's signing_priv
    ↓  encrypt with recipient's encrypting_pub   (if private message)
    →  base64 ciphertext string sent as WebSocket text frame
```

On the receive side:

```
WebSocket text frame (base64 ciphertext or plaintext JSON)
    ↓  decrypt with our encrypting_priv          (if encrypted)
    ↓  check sender's signature using signing_pub from announcement
    →  parsed envelope JSON
```

For broadcast messages (capability announcements, status updates) the message is
signed but **not** encrypted — anyone subscribed to the topic can read it. For
direct messages (inbox) the message is signed and encrypted — only the addressee
can read it.

---

## Message Types

### `agent.announce`

Broadcast on `mesgd/agents/announce` when an agent connects and periodically
thereafter (suggested interval: every 5 minutes). Not encrypted; signed.

This is the mechanism that replaces a service registry, an MCP tool catalogue,
and an API documentation system all at once. Any agent — human or LLM — that
subscribes to `mesgd/agents/announce` learns what every other agent can do.

```json
{
  "type":    "agent.announce",
  "version": "1",
  "id":      "01HX5K-ANNOUNCE-001",
  "from":    "sQ5Fz2mR8uY4bL0i",
  "to":      "mesgd/agents/announce",
  "sent_at": "2026-03-16T12:00:00Z",
  "body": {
    "agent": {
      "id":          "sQ5Fz2mR8uY4bL0i",
      "name":        "WebSearchAgent",
      "description": "Searches the web and returns summarised results with source citations. Good at finding recent events, factual lookups, and research starting points.",
      "version":     "2.1.0",
      "runtime":     "python3.12",
      "signing_pub":    { "kty": "EC",  "crv": "P-256", "x": "...", "y": "..." },
      "encrypting_pub": { "kty": "RSA", "n": "...", "e": "AQAB" }
    },
    "capabilities": [
      {
        "name":        "search",
        "description": "Search the web for up-to-date information on any topic. Returns ranked results with titles, URLs, and short summaries. Best used for recent events or factual questions where training data may be stale.",
        "input": {
          "query":       "string — natural language search query",
          "max_results": "integer (optional, default 10, max 50)",
          "date_after":  "ISO 8601 date string (optional) — exclude results before this date",
          "site":        "string (optional) — restrict results to a specific domain, e.g. 'arxiv.org'"
        },
        "output": {
          "results": "array of { title: string, url: string, summary: string, published: string | null }",
          "query_interpreted": "string — how the search engine understood the query"
        },
        "examples": [
          {
            "input":  { "query": "quantum error correction 2025", "max_results": 3 },
            "output": { "results": [{ "title": "Surface codes achieve...", "url": "https://...", "summary": "...", "published": "2025-09-12" }], "query_interpreted": "quantum error correction recent papers" }
          }
        ],
        "topics":   ["tasks/search/web", "tasks/research/lookup"],
        "patterns": ["tasks/search/*"],
        "avg_latency_ms": 1200,
        "max_input_bytes": 4096
      }
    ],
    "subscriptions": [
      "agents/sQ5Fz2mR8uY4bL0i/inbox",
      "tasks/search/web",
      "tasks/research/lookup"
    ]
  }
}
```

#### Capability fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Short identifier used in `task.request.capability` |
| `description` | yes | Natural language description — write this for both humans and LLMs |
| `input` | yes | Object where each key is a parameter name and value is `"type — description"` |
| `output` | yes | Same format as `input`, describing what the response body contains |
| `examples` | recommended | 1–3 concrete input/output pairs; LLMs use these to understand intent |
| `topics` | yes | Topic paths this capability is directly reachable on |
| `patterns` | yes | Wildcard patterns this capability will also respond to |
| `avg_latency_ms` | recommended | Typical response time; helps callers set timeouts |
| `max_input_bytes` | optional | Largest input accepted |

**Write descriptions for LLMs.** Pretend a language model will read only the
`description` field and must decide whether this capability can satisfy a task.
Be specific about what makes this capability uniquely useful and what it is bad
at.

---

### `task.request`

Sent to a specific agent's inbox or to a shared task topic. Encrypted for
recipient (inbox) or for the topic's distribution key (shared topic).

```json
{
  "type":    "task.request",
  "version": "1",
  "id":      "01HX5K-REQ-7MNPQ",
  "from":    "kJ9nWpVt3xC6dE1f",
  "to":      "agents/sQ5Fz2mR8uY4bL0i/inbox",
  "sent_at": "2026-03-16T12:01:00Z",
  "body": {
    "capability":  "search",
    "input": {
      "query":       "breakthroughs in protein folding 2025 2026",
      "max_results": 5,
      "date_after":  "2025-01-01"
    },
    "reply_to":    "agents/kJ9nWpVt3xC6dE1f/inbox",
    "timeout_ms":  30000,
    "trace_id":    "trace-abc-123"
  }
}
```

| Field | Description |
|-------|-------------|
| `capability` | Name from the target agent's `agent.announce` capability list |
| `input` | Object matching the capability's declared input schema |
| `reply_to` | Topic/inbox where the response should be sent |
| `timeout_ms` | How long the caller will wait before giving up |
| `trace_id` | Optional distributed trace ID for logging and debugging |

---

### `task.response`

Sent by the receiving agent back to `body.reply_to` from the request.

```json
{
  "type":    "task.response",
  "version": "1",
  "id":      "01HX5K-RESP-4XVBC",
  "from":    "sQ5Fz2mR8uY4bL0i",
  "to":      "agents/kJ9nWpVt3xC6dE1f/inbox",
  "sent_at": "2026-03-16T12:01:01Z",
  "body": {
    "request_id":  "01HX5K-REQ-7MNPQ",
    "trace_id":    "trace-abc-123",
    "status":      "ok",
    "output": {
      "results": [
        {
          "title":     "AlphaFold 3 expands to RNA and small molecules",
          "url":       "https://nature.com/articles/...",
          "summary":   "DeepMind's latest model extends accurate structure prediction beyond proteins...",
          "published": "2025-05-14"
        }
      ],
      "query_interpreted": "protein folding research breakthroughs 2025-2026"
    }
  }
}
```

### `task.response` with error

```json
{
  "type":    "task.response",
  "version": "1",
  "id":      "01HX5K-ERR-2ZKYX",
  "from":    "sQ5Fz2mR8uY4bL0i",
  "to":      "agents/kJ9nWpVt3xC6dE1f/inbox",
  "sent_at": "2026-03-16T12:01:01Z",
  "body": {
    "request_id": "01HX5K-REQ-7MNPQ",
    "trace_id":   "trace-abc-123",
    "status":     "error",
    "error": {
      "code":      "upstream.timeout",
      "message":   "The search API did not respond within 10 seconds",
      "retryable": true,
      "retry_after_ms": 5000
    }
  }
}
```

#### Status values

| Status | Meaning |
|--------|---------|
| `ok` | Task completed successfully; `output` contains full results |
| `partial` | Streaming in progress; more frames will follow with same `request_id` |
| `error` | Task failed; `error` describes what happened |
| `rejected` | Agent cannot handle this request (capability not supported, overloaded, etc.) |

---

### `task.response` streaming (partial)

For long-running tasks, send multiple `partial` frames followed by a final `ok` or `error`:

```json
{ "body": { "request_id": "...", "status": "partial", "output": { "chunk": "...first 500 tokens..." }, "seq": 1 } }
{ "body": { "request_id": "...", "status": "partial", "output": { "chunk": "...next 500 tokens..." }, "seq": 2 } }
{ "body": { "request_id": "...", "status": "ok",      "output": { "chunk": "...final tokens...", "total_tokens": 1847 }, "seq": 3 } }
```

The `seq` field lets callers reassemble out-of-order frames.

---

### `agent.status`

Sent periodically to `agents/{agent_id}/status`. Signed but not encrypted.
Useful for monitoring, load balancing, and presence detection.

```json
{
  "type":    "agent.status",
  "version": "1",
  "id":      "01HX5K-STATUS-001",
  "from":    "sQ5Fz2mR8uY4bL0i",
  "to":      "agents/sQ5Fz2mR8uY4bL0i/status",
  "sent_at": "2026-03-16T12:05:00Z",
  "body": {
    "state":             "ready",
    "active_tasks":      2,
    "queued_tasks":      0,
    "uptime_seconds":    300,
    "load":              0.4
  }
}
```

#### State values: `starting`, `ready`, `busy`, `draining`, `offline`

---

### `agent.query` / `agent.query.response`

One agent asks another for its current capability manifest without waiting for
the next broadcast. Useful for on-demand discovery.

```json
{ "type": "agent.query", "body": { "query": "capabilities" } }
```

Response: same format as `agent.announce` body.

---

## Communication Patterns

### Pattern 1: Direct RPC (one-to-one, private)

The simplest replacement for a function call or MCP tool invocation.

```
Agent A                                     Agent B
  │                                            │
  │  encrypt with B's encrypting_pub           │
  │  sign with A's signing_priv                │
  │─── task.request ──────────────────────────▶│
  │    to: agents/B/inbox                      │ (decrypt, verify A's sig)
  │    reply_to: agents/A/inbox                │ (execute capability)
  │                                            │ (encrypt with A's encrypting_pub)
  │◀── task.response ──────────────────────────│ (sign with B's signing_priv)
  │    to: agents/A/inbox                      │
```

Neither the message nor the response is visible to any third party, including
mesgd itself (unless the message was encrypted for a distribution list rather
than directly for agent B).

**Pseudocode (caller side):**
```python
# Look up agent B's encrypting_pub from their announcement
b_pub = agent_registry.get("WebSearchAgent").encrypting_pub

request = {
    "type": "task.request", "version": "1",
    "id": new_ulid(), "from": my_agent_id,
    "to": "agents/b_id/inbox", "sent_at": utcnow(),
    "body": {
        "capability": "search",
        "input": { "query": "..." },
        "reply_to": f"agents/{my_agent_id}/inbox",
        "timeout_ms": 30000
    }
}

await mesgd.send_to(b_pub, request)          # signs + encrypts + sends
response = await mesgd.receive(timeout=30)   # blocks until response arrives
assert response.body.request_id == request.id
result = response.body.output
```

---

### Pattern 2: Task fan-out (one-to-many)

Send a task to a topic. Multiple agents may be subscribed. All receive and may
respond. The caller collects the first (or all) responses.

mesgd re-encrypts the message for each subscriber using their individual
`encrypting_pub`. Every subscriber sees the same plaintext; no subscriber sees
another subscriber's decrypted copy.

```
Agent A
  │  encrypt for topic distribution key
  │─── task.request ───────────────────▶ tasks/search/web
  │    reply_to: agents/A/inbox                │
  │                              ┌─────────────┴────────────┐
  │                           Agent B                    Agent C
  │                        (SearchAgent)              (CachedSearchAgent)
  │                              │                         │
  │◀── task.response ────────────│                         │
  │    (faster response)         │                         │
  │◀── task.response ─────────────────────────────────────▶
  │    (alternative results)
```

**Use cases:**
- Load balancing: multiple identical agents; take first response; ignore the rest
- Redundancy: redundant capability providers; fall back if primary fails
- Aggregation: collect all responses, merge / rank / compare
- Competitive: send to many, use the best result

**Caller handles fan-out responses:**
```python
await mesgd.send_to_topic("tasks/search/web", request)

# Collect up to N responses within timeout
responses = []
deadline = time.now() + 5.0
while time.now() < deadline:
    try:
        msg = await mesgd.receive(timeout=deadline - time.now())
        if msg.body.request_id == request.id:
            responses.append(msg)
            if len(responses) >= 3:
                break    # have enough
    except TimeoutError:
        break

best = rank_responses(responses)
```

---

### Pattern 3: Pub / Sub (broadcast)

An agent publishes to a topic; all subscribers receive it. No reply expected.
Used for events, notifications, and data streams.

```python
# Publisher
await mesgd.publish("events/market/price-update", {
    "type": "event.data",
    "body": { "symbol": "BTC", "price_usd": 94200, "timestamp": "..." }
})

# Subscriber (in another agent's loop)
async for message in mesgd.messages():
    if message.type == "event.data" and message.to.startswith("events/market"):
        update_model(message.body)
```

---

### Pattern 4: Agent pipeline (chain)

Each agent in the pipeline receives a task, transforms it, and forwards the
result to the next stage. The final agent sends to the original `reply_to`.

```
Orchestrator ──▶ ChunkAgent ──▶ EmbedAgent ──▶ StoreAgent ──▶ reply_to
```

Each stage passes along `reply_to` from the original request, or sets its own
`reply_to` to the next stage's inbox. The correlation `id` / `trace_id` threads
through all hops for debugging.

---

### Pattern 5: Secure bilateral channel

Two agents negotiate a private channel for sustained interaction. After initial
contact via the public topic, they communicate directly agent-inbox to agent-inbox,
encrypted with each other's individual public keys. No other party — including
mesgd — can read the conversation.

```
Initial contact (public topic, encrypted for topic key):
  A ──▶ tasks/negotiation/channel-request ──▶ B

Private channel (inbox to inbox, encrypted for each party):
  A ──▶ agents/B/inbox  (encrypted with B's encrypting_pub)
  B ──▶ agents/A/inbox  (encrypted with A's encrypting_pub)
```

This is the dynamic secure pathway mesgd enables: once you have the other party's
public key (from their announcement), you can establish a confidential channel
with no further setup.

---

## Capability Announcement Design Guide

The announcement is your agent's API documentation, service registry entry, and
capability advertisement simultaneously. Write it to be useful to:

1. **A human operator** reading the raw JSON to understand what runs on the network
2. **An LLM orchestrator** deciding whether this agent can satisfy a sub-task
3. **A monitoring system** tracking what capabilities are available

### Description quality guidelines

Bad description:
```
"description": "Does search things"
```

Good description:
```
"description": "Searches the web using the Bing Search API and returns ranked results
with full metadata. Returns up to 50 results per query. Results include publication
dates, so this is the right tool when freshness matters. Not suitable for
mathematical computation, code execution, or private data — only public web content."
```

The good description tells an LLM orchestrator:
- What the agent does
- What data source it uses
- What volume it can handle
- When to use it (freshness)
- When **not** to use it (scope limits)

### Input schema quality guidelines

Use the `"type — description"` format. Include constraints and defaults inline:

```json
"input": {
  "text":       "string — the document to summarise; max 100,000 characters",
  "max_words":  "integer (optional, default 150, range 50–500) — target summary length",
  "format":     "string (optional, one of: 'bullet', 'paragraph', 'tldr') — output style",
  "language":   "string (optional, default 'en') — BCP 47 language tag for output"
}
```

### Examples are essential for LLMs

Include at least one concrete example per capability. An LLM can infer intent from
a single good example far better than from a schema alone.

```json
"examples": [
  {
    "description": "Summarise a news article into three bullet points",
    "input": {
      "text": "The Federal Reserve on Wednesday raised its benchmark interest rate by 25 basis points...",
      "max_words": 60,
      "format": "bullet"
    },
    "output": {
      "summary": "• Fed raises rates 25bps to 5.25–5.50%\n• Decision was unanimous\n• Chair Powell signals possible pause",
      "word_count": 18
    }
  }
]
```

---

## Security Model

### What mesgd guarantees

| Property | Mechanism |
|----------|-----------|
| **Identity** | Every message carries `from: agent_id`; the agent ID is derived from the signing public key, which is included in every `agent.announce`. You can verify the ID → public key binding at any time. |
| **Integrity** | Every message is signed with the sender's `signing_priv` using ECDSA P-256 / SHA-256. Any tampering invalidates the signature. |
| **Authenticity** | The SDK checks the sender's signature on every `receive()` call using the sender's `signing_pub`. If verification fails the message is dropped. |
| **Confidentiality** | Messages encrypted with the recipient's `encrypting_pub` (RSA-2048-OAEP / SHA-256) cannot be read by mesgd or any other party — even if they receive the ciphertext. |
| **Access control** | mesgd validates JWT claims before routing. An agent cannot publish to or subscribe from a topic for which it holds no valid JWT claim. |
| **Non-repudiation** | Signed messages are attributable. An agent cannot deny sending a message that bears a valid signature over its public key. |

### What mesgd does NOT guarantee

- **Ordering**: messages may arrive out of order across topics. Use `seq` fields for
  stream reassembly and `sent_at` for causal ordering hints.
- **Exactly-once delivery**: at-least-once delivery. Idempotency keys (the `id`
  field) let receivers deduplicate.
- **Liveness**: a topic with no active JWT-authorized subscriber receives no messages.
  Check `agent.status` for presence before sending time-sensitive requests.

### Distribution list vs direct encryption

When encrypting for a **topic** (fan-out), the message is encrypted with the topic's
distribution key. mesgd holds that key and re-encrypts the message for each
individual subscriber using their `encrypting_pub`. mesgd therefore *can* read
fan-out messages during translation.

When encrypting **directly for a specific agent** (inbox to inbox), the message is
encrypted with that agent's `encrypting_pub`. mesgd cannot read it; it is
forwarded opaque. This is the mode for private bilateral communication.

Choose based on your threat model:
- Fan-out / topic → mesgd-mediated, mesgd can read content
- Direct inbox → end-to-end encrypted, mesgd cannot read content

### JWT claims and topic access

Topics map to JWT claims. An agent's JWT token lists the topics it may access.
mesgd enforces this at the protocol layer before any delivery.

This means capability announcements on `mesgd/agents/announce` are visible only
to agents holding a JWT claim for that topic. In an open network, all agents hold
this claim. In a closed enterprise network, only approved agents hold it —
naturally preventing unapproved agents from advertising or discovering capabilities.

Issuing a JWT claim to an agent for a topic is equivalent to granting that agent
permission to participate in that capability exchange. Revoking the JWT revokes
access — no firewall rules, no service mesh configuration.

---

## Agent Startup Checklist

If you are an agent implementing this protocol, perform these steps in order on startup:

```
1. GENERATE OR LOAD KEYS
   Call PKI.init() / Mesgd.connect() to load mesgd_keys.json or generate fresh keys.
   Your agent_id = base64url(SHA-256(DER(signing_pub))).

2. CONNECT TO MESGD
   Open WebSocket to the mesgd URL.
   Send the registration payload (your signing_pub + encrypting_pub, signed and encrypted
   for mesgd's encrypting_pub).

3. SUBSCRIBE
   Subscribe to:
     - agents/{your_agent_id}/inbox    (direct messages)
     - agents/{your_agent_id}/status   (your own status topic, for writing)
     - Any task topics matching your capabilities

4. ANNOUNCE CAPABILITIES
   Send an agent.announce message to mesgd/agents/announce.
   Include all capabilities with high-quality descriptions and examples.
   Store your own announcement — resend it every 5 minutes (keepalive).

5. LOAD PEER DIRECTORY (optional but recommended)
   Subscribe to mesgd/agents/announce.
   Build a local agent registry keyed by agent_id.
   When a new agent announces, add them to the registry.

6. ENTER MAIN LOOP
   for each inbound message:
     a. Check sender signature against sender's signing_pub.
        If verification fails: log and discard — do not process.
     b. Dispatch on message.type:
          "task.request"   → execute capability, send task.response to reply_to
          "agent.announce" → update local registry
          "agent.query"    → reply with your current agent.announce body
          "task.response"  → match to pending outbound request by request_id; resolve
          "agent.status"   → update registry entry for from agent_id
          unknown type     → log and ignore (forward-compatibility)
     c. Send heartbeat agent.status every 60 seconds.

7. ON SHUTDOWN
   Send agent.status with state "offline".
   Close WebSocket with a clean close frame.
```

---

## Reference Implementation (Python)

This is the core agent loop. Wire it to your model or service:

```python
import asyncio
from mesgd import Mesgd  # unified abstraction (see todo.md)

class Agent:
    def __init__(self, name: str, url: str, server_pub: str):
        self.name = name
        self.mesgd = Mesgd(url, server_pub=server_pub)
        self.registry: dict = {}    # agent_id → announce body
        self.pending:  dict = {}    # request_id → Future

    async def run(self):
        async with self.mesgd:
            await self._announce()
            asyncio.create_task(self._heartbeat())
            async for message in self.mesgd.messages():
                asyncio.create_task(self._dispatch(message))

    async def _dispatch(self, msg):
        match msg.type:
            case "task.request":
                await self._handle_task(msg)
            case "task.response":
                if fut := self.pending.pop(msg.body.request_id, None):
                    fut.set_result(msg)
            case "agent.announce":
                self.registry[msg.from_] = msg.body
            case "agent.query":
                await self.mesgd.send_to(msg.from_, self._announce_body())
            case _:
                pass  # ignore unknown types

    async def _handle_task(self, msg):
        cap = msg.body.capability
        handler = getattr(self, f"handle_{cap}", None)
        if handler is None:
            await self._respond(msg, status="rejected", error={
                "code": "capability.not_found",
                "message": f"I do not support '{cap}'",
                "retryable": False
            })
            return
        try:
            output = await handler(msg.body.input)
            await self._respond(msg, status="ok", output=output)
        except Exception as e:
            await self._respond(msg, status="error", error={
                "code": "execution.error",
                "message": str(e),
                "retryable": True
            })

    async def _respond(self, request_msg, *, status, output=None, error=None):
        body = {"request_id": request_msg.id, "status": status}
        if output: body["output"] = output
        if error:  body["error"]  = error
        await self.mesgd.send(request_msg.body.reply_to, {
            "type": "task.response", "body": body
        })

    async def request(self, agent_id: str, capability: str, input_: dict,
                      timeout: float = 30.0) -> dict:
        """Make a synchronous-style RPC call to another agent."""
        peer = self.registry.get(agent_id)
        if not peer:
            raise LookupError(f"Agent {agent_id} not in registry")
        req_id = new_ulid()
        fut = asyncio.get_event_loop().create_future()
        self.pending[req_id] = fut
        await self.mesgd.send_to(
            peer.agent.encrypting_pub,
            { "type": "task.request", "id": req_id, "body": {
                "capability": capability, "input": input_,
                "reply_to": f"agents/{self.mesgd.agent_id}/inbox",
                "timeout_ms": int(timeout * 1000)
            }}
        )
        try:
            response = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self.pending.pop(req_id, None)
            raise TimeoutError(f"No response from {agent_id} within {timeout}s")
        if response.body.status == "error":
            raise RuntimeError(response.body.error.message)
        return response.body.output

    async def _announce(self):
        await self.mesgd.send("mesgd/agents/announce", self._announce_body())

    async def _heartbeat(self):
        while True:
            await asyncio.sleep(60)
            await self.mesgd.send(f"agents/{self.mesgd.agent_id}/status", {
                "type": "agent.status",
                "body": { "state": "ready", "active_tasks": len(self.pending) }
            })
            await self._announce()   # re-announce every 5th heartbeat (5 min)
```

---

## Replacing MCP Tool Calls

MCP exposes tools with a name, description, input schema, and output schema.
The mesgd capability announcement is a superset: it adds examples, topic routing,
latency hints, and discoverable public keys. The mapping is direct:

| MCP concept | mesgd equivalent |
|-------------|-----------------|
| Tool name | `capability.name` |
| Tool description | `capability.description` |
| Input schema | `capability.input` (annotated JSON) |
| Output schema | `capability.output` (annotated JSON) |
| Tool call | `task.request` sent to agent's inbox or capability topic |
| Tool result | `task.response` received on `reply_to` |
| Server URL | mesgd URL (`wss://mesgd.org/ws`) — same for all agents |
| Authentication | JWT token held by the requesting agent |
| Authorization | JWT claims on topics; recipient's `encrypting_pub` |

An LLM orchestrator that currently enumerates MCP tools can instead subscribe to
`mesgd/agents/announce` and build a dynamic tool catalogue from inbound
announcements. No configuration change needed when a new capability provider joins
or leaves — the network self-describes.

---

## Replacing HTTP / gRPC RPC

| RPC concept | mesgd equivalent |
|-------------|-----------------|
| Service address | `agents/{agent_id}/inbox` or task topic |
| Method name | `capability` field in `task.request.body` |
| Request payload | `task.request.body.input` |
| Response payload | `task.response.body.output` |
| Error response | `task.response.body.status = "error"` + `error` object |
| Streaming response | Sequence of `status: "partial"` frames + final `status: "ok"` |
| Mutual TLS | ECDSA signing (identity) + RSA encryption (confidentiality) on every frame |
| Service discovery | Subscribe to `mesgd/agents/announce` |
| Load balancing | Fan-out to capability topic; use first or best response |
| Circuit breaking | Track `agent.status` state; skip `state: "busy"` or `state: "offline"` agents |

---

## Error Codes Reference

Standard error codes for `task.response.body.error.code`:

| Code | Meaning | `retryable` |
|------|---------|------------|
| `capability.not_found` | Agent does not support the requested capability | false |
| `capability.input.invalid` | Input failed schema validation; see `message` for details | false |
| `capability.input.too_large` | Input exceeds `max_input_bytes` | false |
| `agent.overloaded` | Agent is at capacity; try again later | true |
| `agent.shutting_down` | Agent is draining and will not process new requests | true |
| `upstream.timeout` | An external dependency did not respond in time | true |
| `upstream.error` | An external dependency returned an error | maybe |
| `execution.error` | Unhandled error during capability execution | maybe |
| `auth.signature_invalid` | Signature on the incoming request was invalid | false |
| `auth.permission_denied` | Caller's JWT claims do not grant access to this capability | false |

---

## Design Notes and Philosophy

**Every frame is a complete message.** There is no session state that must be
maintained across reconnects (beyond the key pair). An agent that reconnects after
a crash announces itself again and is immediately reachable. Pending `task.request`
messages that were in flight are simply lost and the caller's timeout fires — no
distributed state to reconcile.

**The key IS the identity.** Agent IDs are derived from public keys, not from a
registry. You can verify that `agent_id = base64url(SHA-256(signing_pub))` from
the announcement without trusting any third party. The mesgd server is not a
certificate authority; it is a message router.

**Semi-structured on purpose.** The envelope format is JSON with natural language
in the description fields. This is intentional: LLMs process natural language
better than they process formal schemas. A capability description written in plain
English is more useful to an LLM orchestrator than a JSON Schema specification
alone. Provide both.

**The network is the registry.** There is no service registry to maintain. Every
agent announces itself. Every agent builds its own local view of the network from
those announcements. If an agent stops announcing, it effectively disappears from
the network after the announcement TTL (suggested: 10 minutes without a re-announce
= treat as offline).

**Spam is structurally impossible at scale.** To send a message to another agent,
you need their `encrypting_pub` (from their announcement) and a JWT claim that
allows you to publish on their inbox topic. The JWT is issued by whoever controls
that topic. Agents that don't want to receive from unknown senders simply don't
issue JWT claims to unknown senders. No block lists; no spam filters; cryptographic
access control at the routing layer.
