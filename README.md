# Cookie Signature

A cookie signature library which is compatible with cookies signed by https://github.com/tj/node-cookie-signature is written in Go.

## Installation

```sh
go get github.com/hgiasac/go-cookie-signature
```

## Usage

### Functions

```go
secret := []byte("tobiiscool")
signed, err := cookiesignature.Sign("hello", secret)
if err != nil {
  panic(err)
}

log.Println(signed)
// hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI

result, err := cookiesignature.Unsign(signed, secret)
if err != nil {
  panic(err)
}
log.Println(result)
// hello
```

### CookieSignature

`CookieSignature` encapsules signature methods with reusable secrets. There can be one or more secrets will be stored and verified in a way that ensures the cookie's integrity. Secrets may be rotated by adding new secrets to the front of the secrets array. Cookies that have been signed with old secrets will still be decoded successfully in `Unsign`, and the newest secret (the first one in the array) will always be used to sign outgoing cookies created in `Sign`.

```go
cs := cookiesignature.NewCookieSignature([]string{"n3wsecr3t" "olds3cret"})

signed, err := cs.Sign("hello", secret)
if err != nil {
  panic(err)
}

log.Println(signed)
// hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI

result, err := cs.Unsign(signed, secret)
if err != nil {
  panic(err)
}
log.Println(result)
```
