package encryption

import (
	"reflect"
	"testing"
)

func TestEncryptDecryptAES(t *testing.T) {
	key := []byte("thisisa16bytekey")
	plaintext := "hello world"

	encrypted, err := EncryptAES(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := DecryptAES(key, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decryption mismatch: got %q, want: %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptAES_EmptyString(t *testing.T) {
	key := []byte("thisisa16bytekey")
	plaintext := ""

	encrypted, err := EncryptAES(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := DecryptAES(key, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decryption mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptAES_DifferentKey(t *testing.T) {
	key1 := []byte("thisisa16bytekey")
	key2 := []byte("another16bytekey")
	plaintext := "test data"

	encrypted, err := EncryptAES(key1, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := DecryptAES(key2, encrypted)
	if err == nil {
		t.Errorf("Decryption with a diff key should have failed, but it didn't")
	}

	if decrypted == plaintext {
		t.Errorf("Decryption with a diff key, should not be equal to the plain text")
	}
}

func TestEncryptAES_MultipleEncryptions(t *testing.T) {
	key := []byte("thisisa16bytekey")
	plaintext := "same message"

	encrypted1, err := EncryptAES(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encrypted2, err := EncryptAES(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if reflect.DeepEqual(encrypted1, encrypted2) {
		t.Errorf("Multiple encryptions with the same key and plaintext should produce different ciphertexts")
	}
}
