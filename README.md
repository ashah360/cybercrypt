# cybercrypt

Cybercrypt provides simple abstracted functions for encrypting payment data with JWK for the CyberSource payment processor.

### Usage

```go
key, err := cybercrypt.ParseJWK([]byte(json))
if err != nil {
	log.Fatal(err)
}

card, err := cybercrypt.WithJWK(key, []byte("4716770433256661"))
if err != nil {
	log.Fatal(err)
}

fmt.Println(card)
```
