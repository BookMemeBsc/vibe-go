package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"math/big"
)

// TargetDifficulty represents the target threshold for a valid block hash.
// A lower target means higher difficulty.
// Start with a relatively easy target for testing.
// This should be represented as a big.Int for comparison.
// Example: A target requiring the hash to start with N zero bits.
var TargetDifficulty = big.NewInt(1) // Placeholder - will be set properly in pow.go
const TargetDifficultyBits = 10      // Target: Hash must have leading zeros (adjust for difficulty)

// Block represents a block in the VIBE blockchain.
type Block struct {
	Timestamp     int64          // Unix timestamp of when the block was created
	PrevBlockHash []byte         // Hash of the previous block in the chain
	Transactions  []*Transaction // List of transactions included in this block
	Hash          []byte         // Hash of the current block's contents (Timestamp, PrevBlockHash, HashTransactions, Nonce, Target)
	Height        int64          // Block number in the chain (genesis block is 0)
	Nonce         int64          // Nonce used to find a valid hash below the target difficulty
	Target        []byte         // Target threshold for this block (Proof-of-Work)
	// Validator     []byte         // Removed for PoW
	// Signature     []byte         // Removed for PoW
}

// HashTransactions creates a simple hash representation of all transactions in the block.
// NOTE: A proper Merkle Root implementation is recommended for production systems
//
//	to allow for efficient transaction verification (SPV proofs).
func (b *Block) HashTransactions() []byte {
	var txHashes [][]byte
	var txHash [32]byte

	for _, tx := range b.Transactions {
		txHashes = append(txHashes, tx.ID)
	}
	// Simple concatenation of transaction IDs; replace with Merkle tree later
	txHash = sha256.Sum256(bytes.Join(txHashes, []byte{}))

	return txHash[:]
}

// SetHash calculates and sets the hash of the block based on PoW relevant fields.
// Note: This is now primarily used by the PoW algorithm internally when checking nonces.
// The final block hash is determined *by* the PoW result.
func (b *Block) SetHash() {
	// This function might become less relevant, as the hash is found via PoW search.
	// The PoW preparation step will assemble the data to be hashed.
	log.Println("Warning: Direct SetHash call might be incorrect in PoW context. Hash is found via mining.")
	// For consistency, let's keep a way to calculate *a* hash, but it won't be the final one usually.
	headers := prepareDataForHashing(b, b.Nonce) // Use a helper
	hash := sha256.Sum256(headers)
	b.Hash = hash[:]
}

// prepareDataForHashing is a helper to assemble block data for hashing in PoW.
// It includes the nonce.
func prepareDataForHashing(b *Block, nonce int64) []byte {
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(b.Timestamp))

	heightBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBytes, uint64(b.Height))

	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, uint64(nonce))

	// difficultyBytes := make([]byte, 8) // Removed
	// binary.LittleEndian.PutUint64(difficultyBytes, uint64(b.DifficultyBits)) // Removed

	// --- DEBUG LOGGING ---
	// txHashBytes := b.HashTransactions()
	// log.Printf("[DEBUG] prepareDataForHashing (Nonce: %d):", nonce)
	// log.Printf("  Timestamp:      %x (from %d)", timestampBytes, b.Timestamp)
	// log.Printf("  PrevBlockHash:  %x", b.PrevBlockHash)
	// log.Printf("  TxHash:         %x", txHashBytes)
	// log.Printf("  Height:         %x (from %d)", heightBytes, b.Height)
	// log.Printf("  Target:         %x", b.Target)
	// log.Printf("  Nonce:          %x (from %d)", nonceBytes, nonce)
	// --- END DEBUG LOGGING ---

	data := bytes.Join(
		[][]byte{
			timestampBytes,
			b.PrevBlockHash,
			b.HashTransactions(), // Include Merkle root of transactions
			heightBytes,
			b.Target,   // Include Target bytes directly
			nonceBytes, // Nonce is crucial for PoW!
		},
		[]byte{}, // Separator
	)
	return data
}

// TODO:
// - Implement method to calculate the block's hash (Merkle root ...) // Partially done (simple hash)
// - Implement method for validator to sign the block // REMOVED (PoW)
// - Implement method to verify the block's signature and basic validity // REMOVED (PoW) -> Replaced by PoW validation
// - Consider adding Merkle Root field ...
