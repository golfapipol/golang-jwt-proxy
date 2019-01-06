package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func Check(token, secret string) (jwtPayload, error) {
	var data jwtPayload
	tempSplitToken := strings.Split(token, ".")
	if len(tempSplitToken) != 3 {
		return data, errors.New("Invalid token format")
	}

	// check make new signature equal request signature
	// 0: header
	// 1: payload
	// 2: signature
	signatureData := fmt.Sprintf("%s.%s", tempSplitToken[0], tempSplitToken[1])
	newSignature := hmacAlgorithm(signatureData, sha256.New, secret)
	requestSignature, _ := base64.StdEncoding.DecodeString(tempSplitToken[2])
	if !hmac.Equal(requestSignature, newSignature) {
		return data, errors.New("Signature not match")
	}

	payload, _ := base64.StdEncoding.DecodeString(tempSplitToken[1])
	err := json.Unmarshal([]byte(payload), &data)
	return data, err
}
