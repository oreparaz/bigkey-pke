package bigkey

import (
	"bytes"
	"crypto/rand"
	"testing"

	"vuvuzela.io/crypto/ibe"
)

// Test that you cannot decrypt with the wrong identity key
func TestWrongIdentityKeyFails(t *testing.T) {
	pubKey, privKey, err := Setup(100)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message := []byte("Secret message")

	// Encrypt to a specific identity
	ciphertext, err := Encrypt(pubKey, privKey.Identities, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	originalID := ciphertext.ID

	// Try to decrypt with a different identity key
	for _, wrongID := range privKey.Identities {
		if wrongID != originalID {
			// Swap the identity in the ciphertext
			wrongCiphertext := &Ciphertext{
				C:  ciphertext.C,
				ID: wrongID,
			}

			plaintext, err := Decrypt(privKey, wrongCiphertext)
			if err == nil {
				// Decryption succeeded - check if plaintext is garbage or actually matches
				if bytes.Equal(plaintext, message) {
					t.Errorf("SECURITY FAILURE: Successfully decrypted with wrong identity %s (original: %s)", wrongID, originalID)
				}
				// If we get garbage, that's OK - the IBE scheme allowed decryption but produced wrong output
				t.Logf("Decryption with wrong identity produced %d bytes (likely garbage)", len(plaintext))
			}
			break // Only test one wrong identity
		}
	}
}

// Test that you cannot decrypt without any private key
func TestDecryptionWithoutPrivateKeyFails(t *testing.T) {
	pubKey1, privKey1, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Create a second key pair (different recipient)
	_, privKey2, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message := []byte("Secret message")

	// Encrypt to pubKey1
	ciphertext, err := Encrypt(pubKey1, privKey1.Identities, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with privKey2 (wrong recipient)
	_, err = Decrypt(privKey2, ciphertext)
	if err == nil {
		t.Error("SECURITY FAILURE: Decrypted with wrong recipient's private key")
	}
}

// Test that modifying the ciphertext causes decryption to fail
func TestCiphertextTampering(t *testing.T) {
	pubKey, privKey, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message := []byte("Secret message")

	ciphertext, err := Encrypt(pubKey, privKey.Identities, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with the ciphertext V field
	originalC := ciphertext.C
	tamperedC := ibe.Ciphertext{
		U: originalC.U,
		V: make([]byte, len(originalC.V)),
	}
	copy(tamperedC.V, originalC.V)

	// Flip a bit in V
	if len(tamperedC.V) > 0 {
		tamperedC.V[0] ^= 0x01
	}

	tamperedCiphertext := &Ciphertext{
		C:  tamperedC,
		ID: ciphertext.ID,
	}

	plaintext, err := Decrypt(privKey, tamperedCiphertext)
	if err == nil {
		if bytes.Equal(plaintext, message) {
			t.Error("SECURITY FAILURE: Tampered ciphertext decrypted to original message")
		}
		t.Logf("Tampered ciphertext decrypted to garbage (this is OK): %v", plaintext)
	}
}

// Test that the same plaintext encrypted twice produces different ciphertexts (IND-CPA)
func TestRandomizedEncryption(t *testing.T) {
	pubKey, privKey, err := Setup(100)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message := []byte("Same message")

	// Force encryption to same identity by creating a custom identity list
	singleID := []string{privKey.Identities[0]}

	// Encrypt the same message twice to the same identity
	c1, err := Encrypt(pubKey, singleID, message)
	if err != nil {
		t.Fatalf("First encrypt failed: %v", err)
	}

	c2, err := Encrypt(pubKey, singleID, message)
	if err != nil {
		t.Fatalf("Second encrypt failed: %v", err)
	}

	// Ciphertexts should be different (randomized encryption)
	if bytes.Equal(c1.C.V, c2.C.V) {
		t.Error("SECURITY WARNING: Same message encrypted twice produced identical ciphertexts (not randomized)")
	}

	// Both should decrypt to the same message
	p1, err := Decrypt(privKey, c1)
	if err != nil || !bytes.Equal(p1, message) {
		t.Error("First ciphertext didn't decrypt correctly")
	}

	p2, err := Decrypt(privKey, c2)
	if err != nil || !bytes.Equal(p2, message) {
		t.Error("Second ciphertext didn't decrypt correctly")
	}
}

// Test random identity selection is reasonably uniform
func TestRandomIdentityDistribution(t *testing.T) {
	numIdentities := 100
	pubKey, privKey, err := Setup(numIdentities)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	numSamples := 1000
	counts := make(map[string]int)

	// Encrypt many messages and track which identities are chosen
	for i := 0; i < numSamples; i++ {
		c, err := Encrypt(pubKey, privKey.Identities, []byte("test"))
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		counts[c.ID]++
	}

	// Check that we used a reasonable number of unique identities
	uniqueUsed := len(counts)
	expectedUnique := int(float64(numIdentities) * 0.6) // Expect at least 60% coverage

	if uniqueUsed < expectedUnique {
		t.Errorf("Poor distribution: only %d/%d identities used in %d samples", uniqueUsed, numIdentities, numSamples)
	}

	// Check for extreme outliers (one identity used way more than others)
	expectedAvg := float64(numSamples) / float64(numIdentities)
	for id, count := range counts {
		if float64(count) > expectedAvg*5 {
			t.Errorf("Identity %s used %d times (5x more than expected average %.1f)", id, count, expectedAvg)
		}
	}

	t.Logf("Distribution: %d unique identities used out of %d (%.1f%%)", uniqueUsed, numIdentities, float64(uniqueUsed)*100/float64(numIdentities))
}

// Test binary data (not just text)
func TestBinaryData(t *testing.T) {
	pubKey, privKey, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Create random binary data
	message := make([]byte, 256)
	_, err = rand.Read(message)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
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
		t.Error("Binary data not preserved through encryption/decryption")
	}
}

// Test that Setup actually generates different keys each time
func TestSetupRandomness(t *testing.T) {
	pubKey1, _, err := Setup(10)
	if err != nil {
		t.Fatalf("First setup failed: %v", err)
	}

	pubKey2, _, err := Setup(10)
	if err != nil {
		t.Fatalf("Second setup failed: %v", err)
	}

	// The MPKs should be different (they contain random elements)
	// We can't directly compare them, but we can test behavior
	message := []byte("test")

	// Encrypt with first public key
	identities := []string{"id-000000001"}
	c1, err := Encrypt(pubKey1, identities, message)
	if err != nil {
		t.Fatalf("Encrypt with pubKey1 failed: %v", err)
	}

	// Encrypt with second public key (same identity string)
	c2, err := Encrypt(pubKey2, identities, message)
	if err != nil {
		t.Fatalf("Encrypt with pubKey2 failed: %v", err)
	}

	// Ciphertexts should be different (different public keys)
	if bytes.Equal(c1.C.V, c2.C.V) && c1.C.U.String() == c2.C.U.String() {
		t.Error("SECURITY WARNING: Different setups produced same encryption behavior")
	}
}

// Test collision handling - what happens when we randomly select the same identity twice
func TestIdentityCollisionHandling(t *testing.T) {
	pubKey, privKey, err := Setup(10) // Small number increases collision probability
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	message1 := []byte("First message")

	// Encrypt many messages until we get a collision
	usedIDs := make(map[string]bool)
	foundCollision := false

	for i := 0; i < 100; i++ {
		c, err := Encrypt(pubKey, privKey.Identities, message1)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if usedIDs[c.ID] {
			foundCollision = true
			t.Logf("Found collision: identity %s used twice", c.ID)

			// Both messages should still decrypt correctly
			p, err := Decrypt(privKey, c)
			if err != nil {
				t.Fatalf("Decrypt after collision failed: %v", err)
			}
			if !bytes.Equal(p, message1) {
				t.Error("Message decrypted incorrectly after collision")
			}
			break
		}

		usedIDs[c.ID] = true
	}

	if foundCollision {
		t.Log("Collision handling works correctly")
	} else {
		t.Log("No collision found in 100 attempts (this is OK with small probability)")
	}
}

// Test that MSK is not accessible after Setup (best effort - Go doesn't guarantee memory clearing)
func TestMasterSecretKeyInaccessible(t *testing.T) {
	_, privKey, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// There's no direct way to check if MSK is truly wiped in Go
	// But we can verify that the PrivateKey structure doesn't contain MSK
	// This is more of a structure test than a security test

	// The PrivateKey should only contain identity keys, not MSK
	if privKey.Keys == nil {
		t.Error("Private key has no identity keys")
	}

	if len(privKey.Keys) == 0 {
		t.Error("Private key has zero identity keys")
	}

	// We can't extract new keys without MSK - this is tested implicitly
	// by the fact that privKey only contains pre-extracted keys
}

// Test very large message
func TestVeryLargeMessage(t *testing.T) {
	pubKey, privKey, err := Setup(5)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Test with 1MB message
	message := make([]byte, 1024*1024)
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
		t.Error("Large message not preserved")
	}
}

// Test setup with invalid parameters
func TestInvalidSetup(t *testing.T) {
	_, _, err := Setup(0)
	if err == nil {
		t.Error("Setup with 0 identities should fail")
	}

	_, _, err = Setup(-1)
	if err == nil {
		t.Error("Setup with negative identities should fail")
	}
}

// Test encryption with no identities
func TestEncryptNoIdentities(t *testing.T) {
	pubKey, _, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	_, err = Encrypt(pubKey, []string{}, []byte("test"))
	if err == nil {
		t.Error("Encrypt with no identities should fail")
	}
}

// Test decryption with nil ciphertext
func TestDecryptNilCiphertext(t *testing.T) {
	_, privKey, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// This will likely panic or error - we're testing robustness
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic (expected): %v", r)
		}
	}()

	_, err = Decrypt(privKey, nil)
	if err == nil {
		t.Error("Decrypt with nil ciphertext should fail")
	}
}

// Test that different messages to same identity work
func TestMultipleMessagesToSameIdentity(t *testing.T) {
	pubKey, privKey, err := Setup(100)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	singleID := []string{privKey.Identities[0]}

	messages := [][]byte{
		[]byte("Message one"),
		[]byte("Message two"),
		[]byte("Message three"),
	}

	var ciphertexts []*Ciphertext

	// Encrypt all to the same identity
	for _, msg := range messages {
		c, err := Encrypt(pubKey, singleID, msg)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		if c.ID != singleID[0] {
			t.Error("Wrong identity selected")
		}
		ciphertexts = append(ciphertexts, c)
	}

	// All should decrypt correctly
	for i, c := range ciphertexts {
		p, err := Decrypt(privKey, c)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if !bytes.Equal(p, messages[i]) {
			t.Errorf("Message %d decrypted incorrectly", i)
		}
	}
}
