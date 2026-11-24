package main

import (
	"encoding/json"
	pki "mesgd-sdk"
	"os"
)

func main() {
	var r struct {
		Op   string
		Args []json.RawMessage
	}
	if json.NewDecoder(os.Stdin).Decode(&r) != nil {
		panic("invalid test input")
	}
	transport, err := pki.HTTPSAuthTransport(os.Getenv("MESGD_AUTH_URL"))
	if err != nil {
		panic("invalid test origin")
	}
	c := pki.AuthClient{Transport: transport}
	s := func(i int) string { var v string; json.Unmarshal(r.Args[i], &v); return v }
	k := func(i int) []map[string]interface{} {
		var v []map[string]interface{}
		json.Unmarshal(r.Args[i], &v)
		return v
	}
	var result map[string]interface{}
	switch r.Op {
	case "signup":
		result, err = c.Signup(s(0), s(1), s(2), k(3))
	case "confirm":
		result, err = c.Confirm(s(0), s(1), s(2))
	case "login":
		result, err = c.Login(s(0), s(1), s(2))
	case "reset_password":
		result, err = c.ResetPassword(s(0), s(1), s(2), s(3))
	case "keys":
		result, err = c.Keys(s(0))
	case "set_keys":
		result, err = c.SetKeys(s(0), s(1), s(2), k(3))
	case "logout":
		result, err = c.Logout(s(0))
	}
	if ae, ok := err.(*pki.AuthError); ok {
		json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"status": ae.Status})
		return
	}
	if err != nil {
		panic("authentication transport failed")
	}
	json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"result": result})
}
