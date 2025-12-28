package main

import (
	"fmt"
	"log"

	"github.com/oreparaz/bigkey-pke/pkg/bigkey"
)

func main() {
	fmt.Println("=== Big Key Public-Key Encryption Demo ===")
	fmt.Println()

	// Alice: Setup phase
	fmt.Println("SETUP PHASE")
	fmt.Println("-----------")

	numIdentities := 10000
	fmt.Printf("Alice: Generating big key pair with %d identities...\n", numIdentities)

	pubKey, privKey, err := bigkey.Setup(numIdentities)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	fmt.Printf("Alice: Public key generated (MPK): %d bytes\n", estimateMPKSize())
	fmt.Printf("Alice: Private key generated (BigSK): ~%d identity keys\n", privKey.RemainingKeys())
	fmt.Println("Alice: Master secret key (MSK) has been wiped")

	// Bob gets the public key and identity list
	// In practice, identities would be pre-agreed out of band
	identities := pubKey.GetIdentities(privKey)
	fmt.Printf("Bob: Received public key and %d identities\n", len(identities))

	fmt.Println("\nENCRYPTION & DECRYPTION")
	fmt.Println("-----------------------")

	// Bob sends several messages to Alice
	messages := []string{
		"Hello Alice, this is message 1",
		"Second message with random identity selection",
		"Third message - testing forward secrecy",
	}

	var ciphertexts []*bigkey.Ciphertext

	for i, msg := range messages {
		fmt.Printf("\nMessage %d: Bob → Alice\n", i+1)

		// Bob encrypts (randomly selects identity)
		c, err := bigkey.Encrypt(pubKey, identities, []byte(msg))
		if err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}

		fmt.Printf("  Bob: Encrypted to random identity: %s\n", c.ID)
		fmt.Printf("  Bob: Ciphertext size: %d bytes\n", estimateCiphertextSize(len(msg)))

		ciphertexts = append(ciphertexts, c)

		// Alice decrypts
		plaintext, err := bigkey.Decrypt(privKey, c)
		if err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}

		fmt.Printf("  Alice: Decrypted: \"%s\"\n", string(plaintext))

		// Alice deletes the used key for forward secrecy
		privKey.DeleteKey(c.ID)
		fmt.Printf("  Alice: Deleted identity key %s (forward secrecy)\n", c.ID)
		fmt.Printf("  Alice: Remaining keys: %d\n", privKey.RemainingKeys())
	}

	// Demonstrate that deleted keys can't be used again
	fmt.Println("\nFORWARD SECRECY DEMONSTRATION")
	fmt.Println("------------------------------")

	deletedCiphertext := ciphertexts[0]
	fmt.Printf("Attempting to decrypt first message again (identity %s)...\n", deletedCiphertext.ID)

	_, err = bigkey.Decrypt(privKey, deletedCiphertext)
	if err != nil {
		fmt.Printf("✓ Decryption failed as expected: %v\n", err)
		fmt.Println("  (This demonstrates forward secrecy - the key was deleted)")
	} else {
		fmt.Println("✗ Unexpected: Decryption should have failed!")
	}

	// Key statistics
	fmt.Println("\nKEY STATISTICS")
	fmt.Println("--------------")
	fmt.Printf("Public key size:  ~%d bytes\n", estimateMPKSize())
	fmt.Printf("Private key size: ~%d bytes (%d keys × ~%d bytes/key)\n",
		numIdentities*100, numIdentities, 100)
	fmt.Printf("Size ratio:       ~%d:1 (private:public)\n", numIdentities*100/estimateMPKSize())

	fmt.Println("\n=== Demo Complete ===")
}

// Rough size estimates based on BN256 curve parameters
func estimateMPKSize() int {
	// MasterPublicKey contains one G1 element (~64 bytes)
	return 64
}

func estimateCiphertextSize(msgLen int) int {
	// Ciphertext overhead is ~80 bytes + message length
	return 80 + msgLen
}
