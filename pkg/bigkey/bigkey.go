package bigkey

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"vuvuzela.io/crypto/ibe"
)

// PublicKey is the short public key (just the IBE master public key)
type PublicKey struct {
	MPK *ibe.MasterPublicKey
}

// PrivateKey is the large private key (collection of identity private keys)
type PrivateKey struct {
	// Map from identity string to IBE private key
	Keys map[string]*ibe.IdentityPrivateKey
	// List of identities for random selection
	Identities []string
}

// Ciphertext contains the IBE ciphertext and the identity used
type Ciphertext struct {
	C  ibe.Ciphertext
	ID string
}

// Setup generates a big key pair with the specified number of pre-agreed identities.
// The master secret key is used to extract all identity keys, then discarded.
func Setup(numIdentities int) (*PublicKey, *PrivateKey, error) {
	if numIdentities <= 0 {
		return nil, nil, fmt.Errorf("numIdentities must be positive")
	}

	// Step 1: Generate IBE master keys
	mpk, msk := ibe.Setup(rand.Reader)

	// Step 2: Pre-agree on identities (sequential format for simplicity)
	identities := make([]string, numIdentities)
	for i := 0; i < numIdentities; i++ {
		identities[i] = fmt.Sprintf("id-%09d", i+1)
	}

	// Step 3: Extract all identity private keys to create the "big private key"
	keys := make(map[string]*ibe.IdentityPrivateKey, numIdentities)
	for _, id := range identities {
		idBytes := []byte(id)
		identityKey := ibe.Extract(msk, idBytes)
		keys[id] = identityKey
	}

	// Step 4: Wipe the master secret key (critical security step!)
	// In Go, we can't force memory clearing, but we dereference and nil it
	msk = nil

	// Create the public and private keys
	pubKey := &PublicKey{
		MPK: mpk,
	}

	privKey := &PrivateKey{
		Keys:       keys,
		Identities: identities,
	}

	return pubKey, privKey, nil
}

// Encrypt encrypts a message to the public key by randomly selecting an identity
func Encrypt(pubKey *PublicKey, identities []string, message []byte) (*Ciphertext, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities available")
	}

	// Randomly select an identity from the list
	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(identities))))
	if err != nil {
		return nil, fmt.Errorf("failed to generate random index: %w", err)
	}
	idx := int(idxBig.Int64())
	selectedID := identities[idx]

	// Encrypt using IBE
	idBytes := []byte(selectedID)
	c := ibe.Encrypt(rand.Reader, pubKey.MPK, idBytes, message)

	return &Ciphertext{
		C:  c,
		ID: selectedID,
	}, nil
}

// Decrypt decrypts a ciphertext using the big private key
func Decrypt(privKey *PrivateKey, ciphertext *Ciphertext) ([]byte, error) {
	// Look up the identity private key
	identityKey, exists := privKey.Keys[ciphertext.ID]
	if !exists {
		return nil, fmt.Errorf("identity key not found (may have been deleted): %s", ciphertext.ID)
	}

	// Decrypt using the identity private key
	plaintext, ok := ibe.Decrypt(identityKey, ciphertext.C)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return plaintext, nil
}

// DeleteKey removes an identity key from the private key for forward secrecy
func (privKey *PrivateKey) DeleteKey(identity string) {
	delete(privKey.Keys, identity)
}

// RemainingKeys returns the number of unused identity keys
func (privKey *PrivateKey) RemainingKeys() int {
	return len(privKey.Keys)
}

// GetIdentities returns a copy of the identity list (for sender to use)
func (pubKey *PublicKey) GetIdentities(privKey *PrivateKey) []string {
	// In practice, identities would be pre-shared out of band
	// This is just a convenience for the prototype
	identities := make([]string, len(privKey.Identities))
	copy(identities, privKey.Identities)
	return identities
}
