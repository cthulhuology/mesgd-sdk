package pki

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAuthContract(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/auth_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Op           string
		Args         []json.RawMessage
		Method, Path string
		Body         map[string]interface{}
		Token        *string
		Result       map[string]interface{}
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		t.Run(r.Op, func(t *testing.T) {
			a := AuthClient{Transport: func(m, p string, b map[string]interface{}, tok string) (int, map[string]interface{}, error) {
				expectedToken := ""
				if r.Token != nil {
					expectedToken = *r.Token
				}
				wire, _ := json.Marshal(b)
				expected, _ := json.Marshal(r.Body)
				if m != r.Method || p != r.Path || string(wire) != string(expected) || tok != expectedToken {
					t.Fatal("incorrect auth request")
				}
				return 200, r.Result, nil
			}}
			str := func(i int) string { var s string; json.Unmarshal(r.Args[i], &s); return s }
			keys := func(i int) []map[string]interface{} {
				var k []map[string]interface{}
				json.Unmarshal(r.Args[i], &k)
				return k
			}
			var result map[string]interface{}
			switch r.Op {
			case "signup":
				result, err = a.Signup(str(0), str(1), str(2), keys(3))
			case "confirm":
				result, err = a.Confirm(str(0), str(1), str(2))
			case "login":
				result, err = a.Login(str(0), str(1), str(2))
			case "reset_password":
				result, err = a.ResetPassword(str(0), str(1), str(2), str(3))
			case "keys":
				result, err = a.Keys(str(0))
			case "set_keys":
				result, err = a.SetKeys(str(0), str(1), str(2), keys(3))
			case "logout":
				result, err = a.Logout(str(0))
			}
			if err != nil || !reflect.DeepEqual(result, r.Result) {
				t.Fatal("incorrect auth response", err)
			}
		})
	}
}
func TestAuthRejects(t *testing.T) {
	a := AuthClient{Transport: func(string, string, map[string]interface{}, string) (int, map[string]interface{}, error) {
		t.Fatal("invalid input reached transport")
		return 0, nil, nil
	}}
	for _, o := range []string{"12345", "01234x", "012345\n"} {
		if _, e := a.Login("u", "p", o); e == nil {
			t.Fatal("accepted invalid OTP")
		}
	}
	for _, f := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, e := a.Signup("u", "e", "p", []map[string]interface{}{{f: "PRIVATE"}}); e == nil {
			t.Fatal("accepted private key")
		}
	}
	if _, e := HTTPSAuthTransport("http://localhost"); e == nil {
		t.Fatal("accepted insecure origin")
	}
	a.Transport = func(string, string, map[string]interface{}, string) (int, map[string]interface{}, error) {
		return 401, map[string]interface{}{"secret": "DO_NOT_LOG"}, nil
	}
	_, e := a.Login("u", "p", "012345")
	ae, ok := e.(*AuthError)
	if !ok || ae.Status != 401 || strings.Contains(e.Error(), "DO_NOT_LOG") {
		t.Fatal("incorrect error")
	}
}
