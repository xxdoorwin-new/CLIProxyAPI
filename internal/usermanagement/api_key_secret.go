package usermanagement

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const (
	userAPIKeyPrefix       = "cpak_"
	userAPIKeyRandomBytes  = 32
	userAPIKeyDisplayChars = 30
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

func ConfiguredAPIKeyFingerprint(apiKey string) []byte {
	return HashUserAPIKey(apiKey)
}

func ConfiguredAPIKeyFingerprintHex(apiKey string) string {
	return hex.EncodeToString(ConfiguredAPIKeyFingerprint(apiKey))
}

func EncodeAPIKeyFingerprint(fingerprint []byte) string {
	if len(fingerprint) == 0 {
		return ""
	}
	return hex.EncodeToString(fingerprint)
}

func DecodeAPIKeyFingerprint(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, invalid("configured api key fingerprint is required")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) == 0 {
		return nil, invalid("configured api key fingerprint is invalid")
	}
	return decoded, nil
}
