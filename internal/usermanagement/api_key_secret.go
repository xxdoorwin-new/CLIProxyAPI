package usermanagement

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

const (
	userAPIKeyPrefix       = "cpak_"
	userAPIKeyRandomBytes  = 32
	userAPIKeyDisplayChars = 14
)

type GeneratedAPIKey struct {
	Plaintext string
	Prefix    string
	Hash      []byte
}

func GenerateUserAPIKey() (*GeneratedAPIKey, error) {
	raw := make([]byte, userAPIKeyRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	plaintext := userAPIKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return &GeneratedAPIKey{
		Plaintext: plaintext,
		Prefix:    DisplayPrefixForUserAPIKey(plaintext),
		Hash:      HashUserAPIKey(plaintext),
	}, nil
}

func DisplayPrefixForUserAPIKey(plaintext string) string {
	plaintext = strings.TrimSpace(plaintext)
	if len(plaintext) <= userAPIKeyDisplayChars {
		return plaintext
	}
	return plaintext[:userAPIKeyDisplayChars]
}

func HashUserAPIKey(plaintext string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(plaintext)))
	return sum[:]
}

func VerifyUserAPIKey(plaintext string, expectedHash []byte) bool {
	if strings.TrimSpace(plaintext) == "" || len(expectedHash) == 0 {
		return false
	}
	actual := HashUserAPIKey(plaintext)
	return subtle.ConstantTimeCompare(actual, expectedHash) == 1
}
