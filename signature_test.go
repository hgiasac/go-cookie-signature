package cookiesignature

import (
	"testing"
)

func TestCookieSignature(t *testing.T) {
	_, err := NewCookieSignature([]string{})
	if err == nil || err.Error() != "secret key must be provided" {
		t.Fatalf("expected error: secret key must be provided, got: %s", err)
	}

	_, err = NewCookieSignature([]string{""})
	expectedErrorMessage := "secret key at index 0 must not be empty"
	if err == nil || err.Error() != expectedErrorMessage {
		t.Fatalf("expected error: %s, got: %s", expectedErrorMessage, err)
	}
}

func TestSign(t *testing.T) {
	cs, err := NewCookieSignature([]string{"tobiiscool"})
	if err != nil {
		t.Fatalf("expected no error, got: %s", err)
	}
	_, err = cs.Sign("")
	if err == nil || err != errEmptyUnsignedValue {
		t.Fatalf("expected error: %s, got: %s", errEmptyUnsignedValue, err)
	}

	_, err = cs.SignBase64("")
	if err == nil || err != errEmptyUnsignedValue {
		t.Fatalf("expected error: %s, got: %s", errEmptyUnsignedValue, err)
	}

	val, err := cs.Sign("hello")
	assertEqual(t, "hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI", val, err)

	val2, err := Sign("hello", []byte("wrongsecret"))
	assertNotEqual(t, "hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI", val2, err)
}

func TestUnsign(t *testing.T) {
	cs, err := NewCookieSignature([]string{"correctsecret"})
	if err != nil {
		t.Fatalf("expected no error, got: %s", err)
	}
	val, err := cs.SignBase64("hello")
	if err != nil {
		t.Fatalf("expected no error, got: %s", err)
	}

	bs, err := cs.UnsignBase64(val)
	assertEqual(t, "hello", string(bs), err)

	if _, err := Unsign(val, []byte("wrongsecret")); err == nil || err != errInvalidSignature {
		t.Fatalf("expected invalid signature error, got: %s", err)
	}
	val2, err := Sign("hello", []byte("wrongsecret"))
	if err != nil {
		t.Fatalf("expected no error, got: %s", err)
	}

	if _, err = cs.Unsign(""); err == nil || err != errEmptySignedValue {
		t.Fatalf("expected error: %s, got: %s", errEmptySignedValue, err)
	}

	if _, err = cs.Unsign("foo"); err == nil || err != errInvalidSignature {
		t.Fatalf("expected error: %s, got: %s", errInvalidSignature, err)
	}
	if _, err = cs.Unsign("foo.bar=="); err == nil || err.Error() != "illegal base64 data at input byte 3" {
		t.Fatalf("expected error: %s, got: %s", errInvalidSignature, err)
	}

	if _, err = cs.UnsignBase64(val2); err == nil || err != errInvalidSignature {
		t.Fatalf("expected error: %s, got: %s", errInvalidSignature, err)
	}
}

func assertEqual(t *testing.T, expected string, got string, err error) {
	if err != nil {
		t.Fatalf("expected no error, got: %s", err)
	}
	if expected != got {
		t.Fatalf("expected: %s, got: %s", expected, got)
	}
}

func assertNotEqual(t *testing.T, expected string, got string, err error) {
	if err != nil {
		t.Fatalf("expected no error, got: %s", err)
	}
	if expected == got {
		t.Fatalf("expected not equal, expected: %s, got: %s", expected, got)
	}
}
