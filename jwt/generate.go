package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strconv"
	"time"
)

type jwtHeader struct {
	AuthenticationType string `json:"typ"`
	Algorithm          string `json:"alg"`
}

type jwtPayload struct {
	ExpiredAt string      `json:"expiredAt"`
	Payload   interface{} `json:"payload"`
	IssuedAt  string      `json:"issuedAt"`
}

func hmacAlgorithm(src string, hashFunction func() hash.Hash, secret string) []byte {
	key := []byte(secret)
	hmacKey := hmac.New(hashFunction, key)
	hmacKey.Write([]byte(src))
	return hmacKey.Sum(nil)
}

func GenerateJWT(requestedTime time.Time, data interface{}, secret string) (string, error) {
	header := jwtHeader{
		AuthenticationType: "JWT",
		Algorithm:          "HS256",
	}
	JSONHeader, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.StdEncoding.EncodeToString(JSONHeader)

	payload := jwtPayload{
		ExpiredAt: strconv.FormatInt(requestedTime.Add(5*time.Minute).Unix(), 10),
		Payload:   data,
		IssuedAt:  strconv.FormatInt(requestedTime.Unix(), 10),
	}
	JSONPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.StdEncoding.EncodeToString(JSONPayload)

	signatureData := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	signature := hmacAlgorithm(signatureData, sha256.New, secret)
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	jwtMessage := fmt.Sprintf("%s.%s", signatureData, encodedSignature)
	return jwtMessage, nil
}
