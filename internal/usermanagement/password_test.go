package usermanagement

import (
	"errors"
	"testing"
)

func TestHashPasswordAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if string(hash) == "correct horse battery staple" {
		t.Fatal("HashPassword() returned plaintext password")
	}
	if !VerifyPassword("correct horse battery staple", hash) {
		t.Fatal("VerifyPassword() = false, want true")
	}
	if VerifyPassword("wrong password", hash) {
		t.Fatal("VerifyPassword() = true for wrong password")
	}
}

func TestHashPasswordRejectsEmptyPassword(t *testing.T) {
	_, err := HashPassword("  ")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("HashPassword() error = %v, want ErrInvalid", err)
	}
}
