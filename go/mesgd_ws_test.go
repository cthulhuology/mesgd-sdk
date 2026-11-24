package pki

// Transport framing tests (no server): plain / signed / sealed frame building
// and decode+dispatch, exercising the Seal/Open path. Internal package test so
// it can drive the unexported frame/dispatch directly.

import (
	"encoding/json"
	"os"
	"testing"
)

func loadFixturePKI(t *testing.T) *PKI {
	t.Helper()
	data, err := os.ReadFile("../fixtures/jwks.json")
	if err != nil {
		t.Fatalf("read jwks: %v", err)
	}
	var jwks []map[string]interface{}
	if err := json.Unmarshal(data, &jwks); err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	p, err := ImportJWKS(jwks)
	if err != nil {
		t.Fatalf("import jwks: %v", err)
	}
	return p
}

func TestFramePlain(t *testing.T) {
	c := &Conn{handlers: map[string]func(map[string]interface{}){}}
	wire, err := c.frame(map[string]interface{}{
		"to": "x/y", "type": "ping", "body": map[string]interface{}{"a": 1},
	}, SendOpts{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	json.Unmarshal(wire, &m)
	if m["body"] == nil || m["enc"] != nil || m["sig"] != nil {
		t.Fatalf("plain frame should keep body, no enc/sig: %s", wire)
	}
}

func TestFrameSignedSealedRoundTrip(t *testing.T) {
	p := loadFixturePKI(t)
	c := &Conn{pki: p, serverPub: p.PubJWK(), handlers: map[string]func(map[string]interface{}){}}

	wire, err := c.frame(map[string]interface{}{
		"to": "agents/alice/inbox", "type": "task.request",
		"body": map[string]interface{}{"cap": "summarize", "n": 3},
	}, SendOpts{Sign: true, Seal: true})
	if err != nil {
		t.Fatal(err)
	}

	var w map[string]interface{}
	json.Unmarshal(wire, &w)
	if w["enc"] == nil {
		t.Fatal("sealed frame missing enc")
	}
	if w["body"] != nil {
		t.Fatal("sealed frame must hide body")
	}
	if w["to"] != "agents/alice/inbox" {
		t.Fatal("routable field must stay cleartext")
	}
	if _, ok := w["sig"].(string); !ok {
		t.Fatal("signed frame missing sig")
	}

	var got map[string]interface{}
	c.On("task.request", func(m map[string]interface{}) { got = m })
	if err := c.dispatch(wire); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got == nil {
		t.Fatal("handler not called")
	}
	body := got["body"].(map[string]interface{})
	if body["cap"] != "summarize" {
		t.Fatalf("sealed body not recovered: %v", got["body"])
	}

	bodyJSON, _ := json.Marshal(got["body"])
	ok, err := CheckWithPub(p.PubJWK(), string(bodyJSON), got["sig"].(string))
	if err != nil || !ok {
		t.Fatalf("sig should verify over body: ok=%v err=%v", ok, err)
	}
}
