package usermanagement

import "testing"

func TestGenerateUserAPIKeyReturnsOneTimeSecretMaterial(t *testing.T) {
	generated, err := GenerateUserAPIKey()
	if err != nil {
		t.Fatalf("GenerateUserAPIKey() error = %v", err)
	}
	if generated.Plaintext == "" || generated.Prefix == "" || len(generated.Hash) == 0 {
		t.Fatalf("generated key = %#v", generated)
	}
	if generated.Plaintext == generated.Prefix {
		t.Fatal("prefix should not contain the full plaintext key")
	}
	if string(generated.Hash) == generated.Plaintext {
		t.Fatal("hash contains plaintext key")
	}
	if !VerifyUserAPIKey(generated.Plaintext, generated.Hash) {
		t.Fatal("VerifyUserAPIKey() = false, want true")
	}
	if VerifyUserAPIKey(generated.Plaintext+"x", generated.Hash) {
		t.Fatal("VerifyUserAPIKey() = true for wrong key")
	}
}

func TestGeneratedUserAPIKeysAreUnique(t *testing.T) {
	first, err := GenerateUserAPIKey()
	if err != nil {
		t.Fatalf("GenerateUserAPIKey() first error = %v", err)
	}
	second, err := GenerateUserAPIKey()
	if err != nil {
		t.Fatalf("GenerateUserAPIKey() second error = %v", err)
	}
	if first.Plaintext == second.Plaintext {
		t.Fatal("GenerateUserAPIKey() returned duplicate plaintext keys")
	}
	if first.Prefix == second.Prefix {
		t.Fatal("GenerateUserAPIKey() returned duplicate display prefixes")
	}
}
