package cybercrypt

import "encoding/json"

// JWK describes the structure of a JWK payload
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ParseJWK parses a JWK from a buffer
func ParseJWK(data []byte) (*JWK, error) {
	var jwk JWK
	err := json.Unmarshal(data, &jwk)
	if err != nil {
		return nil, err
	}

	return &jwk, nil
}
