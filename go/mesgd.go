package pki

// mesgd transport client. One Conn == one wss connection == one path == one
// JWT; open several for several topics or grants. On/Send are the headline
// surface. Security is opt-in: plain, signed (sig over body), or signed +
// sealed (body encrypted, routable fields left in cleartext).
//
// The WebSocket client is stdlib-only (no external dependency), implementing
// just the RFC 6455 client subset mesgd needs: a json subprotocol with the
// bearer token as its second value, masked text frames, and ping/pong.

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
)

type Conn struct {
	raw       net.Conn
	br        *bufio.Reader
	pki       *PKI
	serverPub map[string]interface{}
	handlers  map[string]func(map[string]interface{})
}

type Options struct {
	PKI       *PKI                   // identity for sign/seal/open
	Token     string                 // JWT; sent as the second subprotocol value
	ServerPub map[string]interface{} // recipient/server encrypting_pub for seal
	TLS       *tls.Config            // optional (e.g. a private CA for tests)
}

type SendOpts struct{ Sign, Seal bool }

// Connect dials wss://host/path (path = subscription) and completes the upgrade.
func Connect(wsURL string, opt Options) (*Conn, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if u.Port() == "" {
		host += map[string]string{"wss": ":443", "ws": ":80"}[u.Scheme]
	}
	raw, err := dial(u.Scheme, host, opt.TLS)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	proto := "json"
	if opt.Token != "" {
		proto = "json, " + opt.Token
	}
	io.WriteString(raw, "GET "+u.RequestURI()+" HTTP/1.1\r\n"+
		"Host: "+u.Host+"\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: "+base64.StdEncoding.EncodeToString(nonce)+"\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Protocol: "+proto+"\r\n\r\n")

	br := bufio.NewReader(raw)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(status, " 101 ") {
		return nil, fmt.Errorf("mesgd: upgrade failed: %s", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return &Conn{raw: raw, br: br, pki: opt.PKI, serverPub: opt.ServerPub,
		handlers: map[string]func(map[string]interface{}){}}, nil
}

func dial(scheme, host string, cfg *tls.Config) (net.Conn, error) {
	if scheme == "ws" {
		return net.Dial("tcp", host)
	}
	return tls.Dial("tcp", host, cfg)
}

// On registers a handler by message type; "*" is the catch-all.
func (c *Conn) On(typ string, h func(map[string]interface{})) { c.handlers[typ] = h }

// Send publishes message as one text frame. With Sign/Seal set, message must
// carry a "body"; Send attaches "sig" over it and swaps "body" for an encrypted
// "enc", leaving routable fields visible.
func (c *Conn) Send(message map[string]interface{}, o SendOpts) error {
	wire, err := c.frame(message, o)
	if err != nil {
		return err
	}
	return c.writeFrame(wire)
}

// Recv reads one text frame, opens "enc" back into "body", and dispatches it.
func (c *Conn) Recv() error {
	payload, err := c.readFrame()
	if err != nil {
		return err
	}
	return c.dispatch(payload)
}

func (c *Conn) Close() error { return c.raw.Close() }

func (c *Conn) frame(message map[string]interface{}, o SendOpts) ([]byte, error) {
	if !o.Sign && !o.Seal {
		return json.Marshal(message)
	}
	body, err := json.Marshal(message["body"])
	if err != nil {
		return nil, err
	}
	if o.Sign {
		sig, err := c.pki.Sign(string(body))
		if err != nil {
			return nil, err
		}
		message["sig"] = sig
	}
	if o.Seal {
		enc, err := c.pki.Seal(c.serverPub, string(body))
		if err != nil {
			return nil, err
		}
		delete(message, "body")
		message["enc"] = enc
	}
	return json.Marshal(message)
}

func (c *Conn) dispatch(raw []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if enc, ok := m["enc"].(string); ok {
		opened, err := c.pki.Open(enc)
		if err != nil {
			return err
		}
		var body interface{}
		if err := json.Unmarshal([]byte(opened), &body); err != nil {
			return err
		}
		delete(m, "enc")
		m["body"] = body
	}
	typ, _ := m["type"].(string)
	h := c.handlers[typ]
	if h == nil {
		h = c.handlers["*"]
	}
	if h != nil {
		h(m)
	}
	return nil
}

// ── RFC 6455 framing (client masks; server frames arrive unmasked) ──────────

func (c *Conn) writeFrame(payload []byte) error {
	return c.writeRaw(0x1, payload)
}

func (c *Conn) writeRaw(opcode byte, payload []byte) error {
	n := len(payload)
	header := []byte{0x80 | opcode}
	switch {
	case n < 126:
		header = append(header, byte(0x80|n))
	case n < 65536:
		header = append(header, 0xFE, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		header = append(append(header, 0xFF), ext[:]...)
	}
	mask := make([]byte, 4)
	rand.Read(mask)
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.raw.Write(append(header, mask...)); err != nil {
		return err
	}
	_, err := c.raw.Write(masked)
	return err
}

func (c *Conn) readFrame() ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return nil, err
	}
	opcode := h[0] & 0x0F
	n := int(h[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		io.ReadFull(c.br, ext[:])
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		io.ReadFull(c.br, ext[:])
		n = int(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if h[1]&0x80 != 0 {
		io.ReadFull(c.br, mask[:])
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, err
	}
	if h[1]&0x80 != 0 {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	switch opcode {
	case 0x8: // close
		return nil, io.EOF
	case 0x9: // ping -> pong, then read the next frame
		c.writeRaw(0xA, payload)
		return c.readFrame()
	case 0xA: // pong
		return c.readFrame()
	}
	return payload, nil
}
