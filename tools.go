package google_auth2

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

func ParseKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("private key should be a PEM or plain PKCS1 or PKCS8; parse error: %v", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is invalid")
	}
	return parsed, nil
}

// Encode encodes a signed JWS with provided header and claim set.
// This invokes EncodeWithSigner using crypto/rsa.SignPKCS1v15 with the given RSA private key.
func Encode(header *Header, c *ClaimSet, key *rsa.PrivateKey) (string, error) {
	sg := func(data []byte) (sig []byte, err error) {
		h := sha256.New()
		h.Write(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	}
	return EncodeWithSigner(header, c, sg)
}

// Decode decodes a claim set from a JWS payload.
func Decode(payload string) (*ClaimSet, error) {
	// decode returned id token to get expiry
	s := strings.Split(payload, ".")
	if len(s) < 2 {
		// TODO(jbd): Provide more context about the error.
		return nil, errors.New("jws: invalid token received")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	c := &ClaimSet{}
	err = json.NewDecoder(bytes.NewBuffer(decoded)).Decode(c)
	return c, err
}

// Signer returns a signature for the given data.
type Signer func(data []byte) (sig []byte, err error)

// EncodeWithSigner encodes a header and claim set with the provided signer.
func EncodeWithSigner(header *Header, c *ClaimSet, sg Signer) (string, error) {
	head, err := header.encode()
	if err != nil {
		return "", err
	}
	cs, err := c.encode()
	if err != nil {
		return "", err
	}
	ss := fmt.Sprintf("%s.%s", head, cs)
	sig, err := sg([]byte(ss))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", ss, base64.RawURLEncoding.EncodeToString(sig)), nil
}
