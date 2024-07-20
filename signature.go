// Package signature signs and unsigns cookies. It can also unsign cookies
// created by node-cookie-signature if the same 'secret' is used,
// allowing interoperability with node.js sessions
package cookiesignature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var (
	errEmptySignedValue   = errors.New("signed value must be provided")
	errEmptyUnsignedValue = errors.New("unsigned value must be provided")
	errInvalidSignature   = errors.New("invalid signature")
)

// CookieSignature allows interoperability with [node-cookie-signature] to sign and unsign cookies.
// Cookies that have one or more secrets will be stored and verified in a way that ensures the cookie's integrity.
// Secrets may be rotated by adding new secrets to the front of the secrets array.
// Cookies that have been signed with old secrets will still be decoded successfully in Unsign,
// and the newest secret (the first one in the array) will always be used to sign outgoing cookies created in Sign.
//
// [node-cookie-signature]: https://github.com/tj/node-cookie-signature/blob/master/index.js
type CookieSignature struct {
	secrets [][]byte
}

// NewCookieSignature creates a new CookieSignature instance
func NewCookieSignature(secrets []string) (*CookieSignature, error) {
	if len(secrets) == 0 {
		return nil, errors.New("secret key must be provided")
	}

	result := CookieSignature{}
	for i, secret := range secrets {
		if secret == "" {
			return nil, fmt.Errorf("secret key at index %d must not be empty", i)
		}
		result.secrets = append(result.secrets, []byte(secret))
	}
	return &result, nil
}

// Sign computes a signature from the input string and returns a joined string of the input and the signed value
func (cs CookieSignature) Sign(input string) (string, error) {
	if input == "" {
		return "", errEmptyUnsignedValue
	}
	return Sign(input, cs.secrets[0])
}

// SignBase64 computes a signature from the input string with base64 encoding
func (cs CookieSignature) SignBase64(input string) (string, error) {
	if input == "" {
		return "", errEmptyUnsignedValue
	}
	return Sign(base64.StdEncoding.EncodeToString([]byte(input)), cs.secrets[0])
}

// Unsign compares and extracts the value (the part of the string before the '.') from the input value
func (cs CookieSignature) Unsign(input string) (string, error) {
	if input == "" {
		return "", errEmptySignedValue
	}
	var firstError error
	for _, secret := range cs.secrets {
		if result, err := Unsign(input, secret); err == nil {
			return result, nil
		} else if firstError == nil {
			firstError = err
		}
	}
	return "", firstError
}

// UnsignBase64 compares and extracts the base64 value (the part of the string before the '.') from the input value
func (cs CookieSignature) UnsignBase64(input string) ([]byte, error) {
	rawResult, err := cs.Unsign(input)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(strings.TrimRight(rawResult, "="))
}

// Sign computes a signature from the input string and returns a joined string of the input and the signed value
func Sign(input string, secret []byte) (string, error) {
	hashBytes, err := computeHMAC256(input, secret)
	if err != nil {
		return "", err
	}
	hash := hashBase64(hashBytes)

	return fmt.Sprintf("%s.%s", input, hash), nil
}

// Unsign compares and extracts the value (the part of the string before the '.') from the input value
func Unsign(input string, secret []byte) (string, error) {
	parts := strings.Split(input, ".")
	length := len(parts)
	if length < 2 {
		return "", errInvalidSignature
	}

	rawResult := strings.Join(parts[:length-1], ".")
	inputHash, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(parts[length-1])
	if err != nil {
		return "", err
	}

	expectedHash, err := computeHMAC256(rawResult, secret)
	if err != nil {
		return "", err
	}

	if len(inputHash) != len(expectedHash) || !hmac.Equal([]byte(inputHash), []byte(expectedHash)) {
		return "", errInvalidSignature
	}
	return rawResult, nil
}

// Create an HMAC signature that is identical to one produced by node-cookie-signature
func computeHMAC256(input string, secret []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, secret)
	_, err := mac.Write([]byte(input))
	if err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func hashBase64(hashBytes []byte) string {
	return strings.TrimRight(string(base64.StdEncoding.EncodeToString(hashBytes)), "=")
}
