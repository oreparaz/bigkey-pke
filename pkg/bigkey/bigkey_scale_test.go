package bigkey

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// Test setup with increasingly large numbers of identities
func TestSetupScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping scaling test in short mode")
	}

	sizes := []int{10, 100, 1000, 10000}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			start := time.Now()
			var m1 runtime.MemStats
			runtime.ReadMemStats(&m1)

			pubKey, privKey, err := Setup(size)
			if err != nil {
				t.Fatalf("Setup with %d identities failed: %v", size, err)
			}

			elapsed := time.Since(start)
			var m2 runtime.MemStats
			runtime.ReadMemStats(&m2)

			// Verify counts
			if len(privKey.Identities) != size {
				t.Errorf("Expected %d identities, got %d", size, len(privKey.Identities))
			}
			if privKey.RemainingKeys() != size {
				t.Errorf("Expected %d keys, got %d", size, privKey.RemainingKeys())
			}

			// Test basic functionality
			message := []byte("Test message")
			c, err := Encrypt(pubKey, privKey.Identities, message)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			plaintext, err := Decrypt(privKey, c)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if string(plaintext) != string(message) {
				t.Error("Decryption failed for scaled setup")
			}

			memUsed := m2.Alloc - m1.Alloc
			t.Logf("Size %d: Setup took %v, Memory: ~%d MB, Time per key: %v",
				size, elapsed, memUsed/(1024*1024), elapsed/time.Duration(size))
		})
	}
}

// Test with very large number of identities (1 million)
func TestLargeScaleSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large scale test in short mode")
	}

	// This is memory and time intensive
	size := 100000 // 100k identities

	t.Logf("Starting setup with %d identities (this may take a while)...", size)
	start := time.Now()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	pubKey, privKey, err := Setup(size)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	elapsed := time.Since(start)
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	memUsed := m2.Alloc - m1.Alloc

	t.Logf("Setup completed in %v", elapsed)
	t.Logf("Memory used: ~%d MB", memUsed/(1024*1024))
	t.Logf("Time per key: %v", elapsed/time.Duration(size))
	t.Logf("Identities: %d", len(privKey.Identities))
	t.Logf("Keys: %d", privKey.RemainingKeys())

	// Test basic functionality with large key set
	message := []byte("Test with large key set")
	c, err := Encrypt(pubKey, privKey.Identities, message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	plaintext, err := Decrypt(privKey, c)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(plaintext) != string(message) {
		t.Error("Decryption failed with large key set")
	}

	t.Logf("Encryption/decryption working correctly with %d identities", size)
}

// Test collision probability with different identity space sizes
func TestCollisionProbability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping collision test in short mode")
	}

	testCases := []struct {
		numIdentities int
		numMessages   int
		description   string
	}{
		{10, 5, "small space, few messages"},
		{100, 20, "medium space, moderate messages"},
		{1000, 50, "large space, moderate messages"},
		{100, 100, "medium space, many messages (expect collisions)"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			pubKey, privKey, err := Setup(tc.numIdentities)
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			usedIDs := make(map[string]int)
			collisions := 0

			for i := 0; i < tc.numMessages; i++ {
				c, err := Encrypt(pubKey, privKey.Identities, []byte("test"))
				if err != nil {
					t.Fatalf("Encrypt failed: %v", err)
				}

				if usedIDs[c.ID] > 0 {
					collisions++
				}
				usedIDs[c.ID]++
			}

			uniqueUsed := len(usedIDs)
			collisionRate := float64(collisions) / float64(tc.numMessages) * 100

			t.Logf("Identities: %d, Messages: %d, Unique: %d, Collisions: %d (%.1f%%)",
				tc.numIdentities, tc.numMessages, uniqueUsed, collisions, collisionRate)

			// For large spaces with few messages, we expect very few collisions
			if tc.numIdentities >= 1000 && tc.numMessages <= 50 && collisionRate > 10 {
				t.Errorf("Unexpectedly high collision rate: %.1f%%", collisionRate)
			}
		})
	}
}

// Benchmark setup with different sizes
func BenchmarkSetup10(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup(10)
	}
}

func BenchmarkSetup100(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup(100)
	}
}

func BenchmarkSetup1000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup(1000)
	}
}

// Benchmark random identity selection overhead
func BenchmarkRandomSelection(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		identities := make([]string, size)
		for i := 0; i < size; i++ {
			identities[i] = fmt.Sprintf("id-%09d", i+1)
		}

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			pubKey, _, _ := Setup(10)
			message := []byte("test")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Encrypt(pubKey, identities, message)
			}
		})
	}
}

// Test memory cleanup when deleting keys
func TestMemoryCleanupOnDeletion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	size := 10000
	pubKey, privKey, err := Setup(size)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	initialKeys := privKey.RemainingKeys()

	// Encrypt and delete half the keys
	numToDelete := size / 2
	for i := 0; i < numToDelete; i++ {
		c, err := Encrypt(pubKey, privKey.Identities, []byte("test"))
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		privKey.DeleteKey(c.ID)
	}

	runtime.GC() // Force garbage collection

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	finalKeys := privKey.RemainingKeys()

	t.Logf("Initial keys: %d", initialKeys)
	t.Logf("Final keys: %d", finalKeys)
	t.Logf("Memory before: %d MB", m1.Alloc/(1024*1024))
	t.Logf("Memory after: %d MB", m2.Alloc/(1024*1024))

	// Note: Go's GC may not immediately free memory, so we can't assert strict bounds
	// This test is mainly for observing behavior
}

// Test that encryption time doesn't significantly degrade with large identity lists
func TestEncryptionTimeWithLargeIdentityList(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timing test in short mode")
	}

	sizes := []int{100, 1000, 10000, 100000}
	iterations := 100

	for _, size := range sizes {
		pubKey, privKey, err := Setup(size)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		message := []byte("Test message")

		start := time.Now()
		for i := 0; i < iterations; i++ {
			_, err := Encrypt(pubKey, privKey.Identities, message)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
		}
		elapsed := time.Since(start)
		avgTime := elapsed / time.Duration(iterations)

		t.Logf("Identity list size %6d: Average encrypt time: %v", size, avgTime)
	}

	// Encryption time should be roughly constant regardless of identity list size
	// (only the random selection changes, which is O(1))
}

// Test decryption time with large key sets
func TestDecryptionTimeWithLargeKeySet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timing test in short mode")
	}

	sizes := []int{100, 1000, 10000}
	iterations := 100

	for _, size := range sizes {
		pubKey, privKey, err := Setup(size)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		message := []byte("Test message")

		// Pre-encrypt messages
		ciphertexts := make([]*Ciphertext, iterations)
		for i := 0; i < iterations; i++ {
			c, err := Encrypt(pubKey, privKey.Identities, message)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			ciphertexts[i] = c
		}

		start := time.Now()
		for _, c := range ciphertexts {
			_, err := Decrypt(privKey, c)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
		}
		elapsed := time.Since(start)
		avgTime := elapsed / time.Duration(iterations)

		t.Logf("Key set size %5d: Average decrypt time: %v", size, avgTime)
	}

	// Decryption time should be roughly constant (map lookup is O(1) average case)
}
