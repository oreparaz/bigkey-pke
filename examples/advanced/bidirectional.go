package main

import (
	"fmt"
	"log"

	"github.com/oreparaz/bigkey-pke/pkg/bigkey"
)

func main() {
	fmt.Println("=== Bidirectional Communication Example ===")
	fmt.Println()

	// Alice and Bob both generate key pairs
	fmt.Println("Setting up key pairs...")
	alicePub, alicePriv, err := bigkey.Setup(100)
	if err != nil {
		log.Fatal(err)
	}

	bobPub, bobPriv, err := bigkey.Setup(100)
	if err != nil {
		log.Fatal(err)
	}

	// Alice sends to Bob
	fmt.Println("\nAlice → Bob:")
	aliceMsg := []byte("Hi Bob, this is Alice!")
	ct1, err := bigkey.Encrypt(bobPub, bobPriv.Identities, aliceMsg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Encrypted to: %s\n", ct1.ID)

	bobReceived, err := bigkey.Decrypt(bobPriv, ct1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Bob received: %s\n", string(bobReceived))
	bobPriv.DeleteKey(ct1.ID)

	// Bob sends to Alice
	fmt.Println("\nBob → Alice:")
	bobMsg := []byte("Hi Alice, got your message!")
	ct2, err := bigkey.Encrypt(alicePub, alicePriv.Identities, bobMsg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Encrypted to: %s\n", ct2.ID)

	aliceReceived, err := bigkey.Decrypt(alicePriv, ct2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Alice received: %s\n", string(aliceReceived))
	alicePriv.DeleteKey(ct2.ID)

	fmt.Printf("\n✓ Bidirectional communication successful!\n")
}
