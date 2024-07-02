package google_auth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	defaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	defaultHeader    = &Header{Algorithm: "RS256", Typ: "JWT"}
)

func GetAuthToken(credentialsJsonPath string, scopes ...string) (*Token, error) {
	data, err := os.ReadFile(credentialsJsonPath)
	if err != nil {
		return nil, err
	}

	conf := &Config{}
	if err = json.Unmarshal(data, conf); err != nil {
		return nil, err
	}

	return doRequest(conf, scopes...)
}

func doRequest(conf *Config, scopes ...string) (*Token, error) {

	pk, err := ParseKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, err
	}
	hc := http.DefaultClient
	claimSet := &ClaimSet{
		Iss:   conf.ClientEmail,
		Scope: strings.Join(scopes, " "),
		Aud:   conf.TokenUri,
	}

	h := *defaultHeader
	h.KeyID = conf.PrivateKeyId
	payload, err := Encode(&h, claimSet, pk)
	if err != nil {
		return nil, err
	}
	reqVals := url.Values{}
	reqVals.Set("grant_type", defaultGrantType)
	reqVals.Set("assertion", payload)
	resp, err := hc.PostForm(conf.TokenUri, reqVals)
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return nil, &RetrieveError{
			Response: resp,
			Body:     body,
		}
	}
	// tokenRes is the JSON response body.
	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"` // relative seconds from now
	}
	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	token := &Token{
		AccessToken: tokenRes.AccessToken,
		TokenType:   tokenRes.TokenType,
	}
	raw := make(map[string]interface{})
	json.Unmarshal(body, &raw) // no error checks for optional fields
	token = token.WithExtra(raw)

	if secs := tokenRes.ExpiresIn; secs > 0 {
		token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	if v := tokenRes.IDToken; v != "" {
		// decode returned id token to get expiry
		claimSet, err := Decode(v)
		if err != nil {
			return nil, fmt.Errorf("oauth2: error decoding JWT token: %v", err)
		}
		token.Expiry = time.Unix(claimSet.Exp, 0)
	}

	return token, nil
}
