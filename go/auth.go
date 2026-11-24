package pki

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type AuthTransport func(method, path string, body map[string]interface{}, token string) (int, map[string]interface{}, error)
type AuthClient struct{ Transport AuthTransport }
type AuthError struct{ Status int }

func (e *AuthError) Error() string { return fmt.Sprintf("mesgd authentication HTTP %d", e.Status) }

func HTTPSAuthTransport(origin string) (AuthTransport, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("expected an HTTPS server origin")
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(method, path string, body map[string]interface{}, token string) (int, map[string]interface{}, error) {
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				return 0, nil, errors.New("invalid authentication request")
			}
		}
		req, err := http.NewRequest(method, strings.TrimRight(origin, "/")+path, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, errors.New("invalid authentication request")
		}
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := client.Do(req)
		if err != nil {
			return 0, nil, errors.New("authentication transport failed")
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return res.StatusCode, nil, nil
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 1048577))
		if err != nil || len(raw) > 1048576 {
			return 0, nil, errors.New("invalid authentication response")
		}
		var result map[string]interface{}
		if json.Unmarshal(raw, &result) != nil || result == nil {
			return 0, nil, errors.New("invalid authentication response")
		}
		return res.StatusCode, result, nil
	}, nil
}

var otpPattern = regexp.MustCompile(`^[0-9]{6}$`)

func authOTP(code string) error {
	if !otpPattern.MatchString(code) {
		return errors.New("OTP must be a six-digit string")
	}
	return nil
}
func authPublicKeys(keys []map[string]interface{}) error {
	if len(keys) > 2 {
		return errors.New("expected at most two public JWKs")
	}
	for _, k := range keys {
		if k == nil {
			return errors.New("invalid public JWK")
		}
		for _, f := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, ok := k[f]; ok {
				return errors.New("private JWKs are not accepted")
			}
		}
	}
	return nil
}
func (a *AuthClient) request(method, path string, body map[string]interface{}, token string) (map[string]interface{}, error) {
	if a.Transport == nil {
		return nil, errors.New("missing authentication transport")
	}
	status, result, err := a.Transport(method, path, body, token)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, &AuthError{status}
	}
	return result, nil
}
func (a *AuthClient) Signup(user, email, password string, keys []map[string]interface{}) (map[string]interface{}, error) {
	if err := authPublicKeys(keys); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []map[string]interface{}{}
	}
	return a.request("POST", "/auth/signup", map[string]interface{}{"user": user, "email": email, "password": password, "public_keys": keys}, "")
}
func (a *AuthClient) Confirm(user, enrollment, code string) (map[string]interface{}, error) {
	if err := authOTP(code); err != nil {
		return nil, err
	}
	return a.request("POST", "/auth/signup/confirm", map[string]interface{}{"user": user, "enrollment_token": enrollment, "otp": code}, "")
}
func (a *AuthClient) Login(user, password, code string) (map[string]interface{}, error) {
	if err := authOTP(code); err != nil {
		return nil, err
	}
	return a.request("POST", "/auth/login", map[string]interface{}{"user": user, "password": password, "otp": code}, "")
}
func (a *AuthClient) ResetPassword(user, recovery, password, code string) (map[string]interface{}, error) {
	if err := authOTP(code); err != nil {
		return nil, err
	}
	return a.request("POST", "/auth/password/reset", map[string]interface{}{"user": user, "recovery_code": recovery, "new_password": password, "otp": code}, "")
}
func (a *AuthClient) Keys(token string) (map[string]interface{}, error) {
	return a.request("GET", "/auth/keys", nil, token)
}
func (a *AuthClient) SetKeys(token, password, code string, keys []map[string]interface{}) (map[string]interface{}, error) {
	if err := authOTP(code); err != nil {
		return nil, err
	}
	if err := authPublicKeys(keys); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []map[string]interface{}{}
	}
	return a.request("PUT", "/auth/keys", map[string]interface{}{"password": password, "otp": code, "public_keys": keys}, token)
}
func (a *AuthClient) Logout(token string) (map[string]interface{}, error) {
	return a.request("POST", "/auth/logout", nil, token)
}
