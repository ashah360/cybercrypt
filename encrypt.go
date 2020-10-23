package cybercrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// RSAExponent defines 'e' used for RSA encryption
const RSAExponent = 65537

// WithJWK encrypts the provided buffer (RSA-OEP-256) with a JWK
func WithJWK(jwk *JWK, payload []byte) (string, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return "", err
	}

	var e int
	if jwk.E == "AQAB" || jwk.E == "AAEAAQ" {
		e = RSAExponent
	} else {
		return "", errors.New("E not supported")
	}

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}

	buf := []byte(payload)

	// Provides a sufficient level of entropy
	r := rand.Reader

	encBuf, err := rsa.EncryptOAEP(sha256.New(), r, pk, buf, []byte{})
	if err != nil {
		return "", fmt.Errorf("Encryption Error: %s", err)
	}

	encoded := base64.StdEncoding.EncodeToString(encBuf)

	return encoded, nil
}
