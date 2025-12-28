package bigkey

import (
	"bytes"
	"testing"
)

func TestBasicEncryptDecrypt(t *testing.T) {
	// Setup with small number of identities for testing
	pubKey, privKey, err := Setup(100)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message := []byte("Hello, World!")

	// Encrypt
	ciphertext, err := Encrypt(pubKey, privKey.Identities, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	plaintext, err := Decrypt(privKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, message) {
		t.Errorf("Decrypted message doesn't match. Got %v, want %v", plaintext, message)
	}
}

func TestMultipleMessages(t *testing.T) {
	pubKey, privKey, err := Setup(1000)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	messages := [][]byte{
		[]byte("First message"),
		[]byte("Second message"),
		[]byte("Third message"),
		[]byte("Fourth message"),
		[]byte("Fifth message"),
	}

	// Encrypt all messages
	var ciphertexts []*Ciphertext
	for _, msg := range messages {
		c, err := Encrypt(pubKey, privKey.Identities, msg)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		ciphertexts = append(ciphertexts, c)
	}

	// Verify they used different identities (with high probability)
	usedIDs := make(map[string]bool)
	for _, c := range ciphertexts {
		if usedIDs[c.ID] {
			t.Logf("Warning: Identity %s was reused (expected with random selection)", c.ID)
		}
		usedIDs[c.ID] = true
	}

	// Decrypt all messages
	for i, c := range ciphertexts {
		plaintext, err := Decrypt(privKey, c)
		if err != nil {
			t.Fatalf("Decrypt failed for message %d: %v", i, err)
		}
		if !bytes.Equal(plaintext, messages[i]) {
			t.Errorf("Message %d mismatch. Got %v, want %v", i, plaintext, messages[i])
		}
	}
}

func TestForwardSecrecy(t *testing.T) {
	pubKey, privKey, err := Setup(100)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message := []byte("Secret message")

	// Encrypt
	ciphertext, err := Encrypt(pubKey, privKey.Identities, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt successfully
	plaintext, err := Decrypt(privKey, ciphertext)
	if err != nil {
		t.Fatalf("First decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, message) {
		t.Errorf("Decrypted message doesn't match")
	}

	// Delete the key
	usedID := ciphertext.ID
	privKey.DeleteKey(usedID)

	// Try to decrypt again - should fail
	_, err = Decrypt(privKey, ciphertext)
	if err == nil {
		t.Error("Expected decryption to fail after key deletion, but it succeeded")
	}
}

func TestRemainingKeys(t *testing.T) {
	numIdentities := 50
	pubKey, privKey, err := Setup(numIdentities)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if privKey.RemainingKeys() != numIdentities {
		t.Errorf("Expected %d remaining keys, got %d", numIdentities, privKey.RemainingKeys())
	}

	// Encrypt and delete some keys
	// Track unique identities used (accounting for possible collisions with random selection)
	numMessages := 10
	usedIDs := make(map[string]bool)
	for i := 0; i < numMessages; i++ {
		c, err := Encrypt(pubKey, privKey.Identities, []byte("test"))
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		usedIDs[c.ID] = true
		privKey.DeleteKey(c.ID)
	}

	remaining := privKey.RemainingKeys()
	uniqueUsed := len(usedIDs)
	expected := numIdentities - uniqueUsed
	if remaining != expected {
		t.Errorf("Expected %d remaining keys (used %d unique IDs), got %d", expected, uniqueUsed, remaining)
	}
}

func TestLargeMessage(t *testing.T) {
	pubKey, privKey, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Test with a larger message
	message := make([]byte, 1024)
	for i := range message {
		message[i] = byte(i % 256)
	}

	ciphertext, err := Encrypt(pubKey, privKey.Identities, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	plaintext, err := Decrypt(privKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Error("Large message decryption mismatch")
	}
}

func TestEmptyMessage(t *testing.T) {
	pubKey, privKey, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message := []byte("")

	ciphertext, err := Encrypt(pubKey, privKey.Identities, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	plaintext, err := Decrypt(privKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Error("Empty message decryption mismatch")
	}
}

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup(100)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	pubKey, privKey, _ := Setup(1000)
	message := []byte("Benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(pubKey, privKey.Identities, message)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	pubKey, privKey, _ := Setup(1000)
	message := []byte("Benchmark message")
	ciphertext, _ := Encrypt(pubKey, privKey.Identities, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(privKey, ciphertext)
	}
}
