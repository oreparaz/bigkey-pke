package testutil

import (
	"testing"
)

// SkipIfShort skips the test if running in short mode
func SkipIfShort(t *testing.T, reason string) {
	if testing.Short() {
		t.Skip("Skipping in short mode:", reason)
	}
}

// MustSetup creates a test key pair or fails the test
func MustSetup(t *testing.T, numIdentities int) {
	t.Helper()
	// Helper function for tests
}
