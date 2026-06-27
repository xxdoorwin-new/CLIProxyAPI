package usermanagement

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const defaultPasswordHashCost = bcrypt.DefaultCost

func HashPassword(password string) ([]byte, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return nil, invalid("password is required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), defaultPasswordHashCost)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func VerifyPassword(password string, hash []byte) bool {
	if strings.TrimSpace(password) == "" || len(hash) == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}
