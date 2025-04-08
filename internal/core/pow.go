package core

import (
	"fmt"
	"log"
	"math"
	"math/big"
	"time" // For logging time taken

	"golang.org/x/crypto/argon2"
)

// maxNonce is used to prevent infinite loops in Run()
const maxNonce = math.MaxInt64

// ProofOfWork represents a proof-of-work challenge
type ProofOfWork struct {
	block  *Block
	target *big.Int // Target threshold (hash must be less than this)
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	// Convert the target bytes from the block into a big.Int
	target := new(big.Int)
	target.SetBytes(b.Target)

	pow := &ProofOfWork{b, target}
	return pow
}

// Run performs the proof-of-work computation (mining).
// It tries nonces until an Argon2id hash of the block data is found that is below the target.
func (pow *ProofOfWork) Run() (int64, []byte, error) {
	var hash [32]byte // Argon2id default output size
	var intHash big.Int
	nonce := int64(0)

	startTime := time.Now() // Start timing
	log.Printf("Mining the block containing \"%s\" (Target: %x)\n", pow.block.HashTransactions(), pow.target.Bytes())

	// Prepare Argon2id parameters (adjust as needed for security/performance trade-off)
	// These are example parameters; tune them based on desired block time and security level.
	mem := uint32(64 * 1024)        // 64MB memory
	timeCost := uint32(1)           // 1 iteration (low for faster testing, increase for security)
	threads := uint8(4)             // Number of threads
	salt := pow.block.PrevBlockHash // Use previous block hash as salt for variation
	keyLen := uint32(32)            // Output hash length (bytes)

	for nonce < maxNonce {
		data := prepareDataForHashing(pow.block, nonce) // Use the helper from block.go

		// Calculate Argon2id hash
		hashBytes := argon2.IDKey(data, salt, timeCost, mem, threads, keyLen)
		copy(hash[:], hashBytes)

		intHash.SetBytes(hash[:])

		// Compare hash with target
		if intHash.Cmp(pow.target) == -1 {
			duration := time.Since(startTime)
			log.Printf("Found valid nonce %d. Hash: %x (Took %s)\n", nonce, hash, duration)
			return nonce, hash[:], nil // Found a valid nonce
		}
		nonce++
	}

	// If loop completes without finding a nonce (highly unlikely with reasonable difficulty)
	return 0, nil, fmt.Errorf("proof of work failed: exceeded maxNonce")
}

// Validate checks if the block's Argon2id hash is valid (meets the target difficulty)
func (pow *ProofOfWork) Validate() (bool, error) {
	var intHash big.Int

	// Prepare Argon2id parameters (must match those used in Run)
	mem := uint32(64 * 1024)
	timeCost := uint32(1)
	threads := uint8(4)
	salt := pow.block.PrevBlockHash
	keyLen := uint32(32)

	// log.Printf("[DEBUG] Validate: Validating block %d (Nonce: %d, Target: %x)", pow.block.Height, pow.block.Nonce, pow.block.Target)
	data := prepareDataForHashing(pow.block, pow.block.Nonce)
	// log.Printf("[DEBUG] Validate: Prepared data for hashing (len %d): %x", len(data), data)

	hashBytes := argon2.IDKey(data, salt, timeCost, mem, threads, keyLen)
	// log.Printf("[DEBUG] Validate: Calculated Argon2id hash: %x", hashBytes)

	// Check if calculated hash matches the stored block hash
	// Note: This assumes block.Hash was set correctly after mining.
	// if !bytes.Equal(hashBytes, pow.block.Hash) {
	// 	 log.Printf("Validation Error: Calculated hash %x does not match stored hash %x", hashBytes, pow.block.Hash)
	// 	 return false, nil
	// }

	// Check if the hash is below the target
	intHash.SetBytes(hashBytes)
	// log.Printf("[DEBUG] Validate: Comparing calculated hash Int (%s) with Target Int (%s)", intHash.String(), pow.target.String())
	if intHash.Cmp(pow.target) == -1 {
		// log.Println("[DEBUG] Validate: Hash is LESS than target. Validation SUCCESSFUL.")
		return true, nil
	}

	// log.Println("[DEBUG] Validate: Hash is NOT less than target. Validation FAILED.")
	return false, nil
}
