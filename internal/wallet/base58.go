package wallet

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/mr-tron/base58"
)

// Define a version byte for addresses (e.g., 0x00 for mainnet)
const addressChecksumLen = 4
const version = byte(0x00)

// Base58Encode encodes a payload (e.g., public key hash) into Base58Check format.
func Base58Encode(payload []byte) string {
	// 1. Add version prefix
	versionedPayload := append([]byte{version}, payload...)

	// 2. Calculate checksum
	checksum := calculateChecksum(versionedPayload)

	// 3. Append checksum
	fullPayload := append(versionedPayload, checksum...)

	// 4. Encode to Base58
	encoded := base58.Encode(fullPayload)
	return encoded
}

// Base58Decode decodes a Base58Check encoded string back into its payload.
// It verifies the checksum and version.
func Base58Decode(encoded string) ([]byte, error) {
	// 1. Decode from Base58
	fullPayload, err := base58.Decode(encoded)
	if err != nil {
		log.Printf("Error decoding base58 string '%s': %v", encoded, err)
		return nil, fmt.Errorf("invalid base58 format: %w", err)
	}

	// 2. Check minimum length (version + checksum)
	if len(fullPayload) < addressChecksumLen+1 {
		return nil, fmt.Errorf("invalid base58check length: %d", len(fullPayload))
	}

	// 3. Split payload and checksum
	payloadAndVersion := fullPayload[:len(fullPayload)-addressChecksumLen]
	receivedChecksum := fullPayload[len(fullPayload)-addressChecksumLen:]

	// 4. Validate version
	receivedVersion := payloadAndVersion[0]
	if receivedVersion != version {
		return nil, fmt.Errorf("invalid address version: got %d, expected %d", receivedVersion, version)
	}

	// 5. Calculate expected checksum
	expectedChecksum := calculateChecksum(payloadAndVersion)

	// 6. Compare checksums
	if !bytes.Equal(receivedChecksum, expectedChecksum) {
		return nil, fmt.Errorf("invalid checksum: expected %x, got %x", expectedChecksum, receivedChecksum)
	}

	// 7. Return the actual payload (without version byte)
	payload := payloadAndVersion[1:]
	return payload, nil
}

// calculateChecksum performs a double SHA256 hash and returns the first 4 bytes.
func calculateChecksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:addressChecksumLen]
}
