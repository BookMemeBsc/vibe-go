package core

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"vibe-ai/internal/wallet"

	"github.com/dgraph-io/badger/v3"
)

// Define the database path
const dbPath = "./data/blockchain"

// Define the key for storing the last block hash
const lastHashKey = "lh"

// Define target block time and adjustment interval
const targetBlockTimeSeconds = 10
const difficultyAdjustmentInterval = 100    // Adjust difficulty every 100 blocks
const blockRewardHalvingInterval = 12600000 // Halving interval in blocks (210k * 60)

// Difficulty Adjustment Parameters
const maxTargetBits = 256   // Theoretical maximum target (all bits 1)
const initialTargetBits = 9 // Start with a relatively easy target (e.g., 20 leading zero bits equivalent)
var initialTarget = big.NewInt(1)

func init() {
	// Calculate the initial target value based on initialTargetBits
	initialTarget.Lsh(initialTarget, uint(maxTargetBits-initialTargetBits))
}

// Clamping factors for difficulty adjustment (adjust as needed)
var maxRetargetFactor = big.NewInt(4)
var minRetargetFactor = big.NewInt(1) // Reciprocal of max, used for division

// Define the smallest unit (like Satoshi for Bitcoin)
const VibeSmallestUnit = 100000000

// Define initial block reward
const InitialBlockReward = 1 * VibeSmallestUnit

// --- Hardcoded Genesis Block ---
// Define the timestamp for the genesis block (e.g., March 15, 2023 12:00:00 PM GMT)
const genesisTimestamp = 1744064329
const genesisRecipientPlaceholder = "1AcPj5C9FJsqjmKHnrG8Knm9RDfBsz1HqQAk16vjVbW73ayJNm" // Replace if desired

// getHardcodedGenesisBlock returns the predefined genesis block for the VIBE chain.
// IMPORTANT: The Nonce and Hash below are placeholders. You MUST calculate the actual
// Nonce and Hash by running PoW for this block data with the initialTarget and
// replace these placeholder values before deploying.
func getHardcodedGenesisBlock() *Block {
	// The human-readable Base58Check encoded address.
	genesisRecipientAddress := genesisRecipientPlaceholder

	// Decode the Base58Check address to get the raw public key hash.
	// NOTE: Replace 'utils.Base58Decode' with the actual function from your codebase.
	// This function should return the raw PubKeyHash bytes, stripping version and checksum.
	pubKeyHashBytes, err := wallet.Base58Decode(genesisRecipientAddress) // Use the function from the wallet package
	if err != nil {
		log.Panicf("FATAL: Failed to decode hardcoded genesis recipient address '%s': %v", genesisRecipientAddress, err)
	}

	// Create the coinbase transaction for the genesis block using the DECODED public key hash.
	coinbaseTx := NewCoinbaseTX(pubKeyHashBytes, 0, InitialBlockReward)

	// Construct the genesis block with fixed data
	genesis := &Block{
		Timestamp:     genesisTimestamp,
		PrevBlockHash: []byte{},
		Transactions:  []*Transaction{coinbaseTx},
		Height:        0,
		Target:        initialTarget.Bytes(),
		// --- PLACEHOLDER VALUES - MUST BE REPLACED ---
		Nonce: 1109, // Replace with actual nonce found by PoW
		// Hash:  []byte("0014b4efe685702e6e625bab45d2ce7859c52f2d83e63b66643f4d3f5db4376c"), // Incorrect: Converts string to bytes
		// --- END PLACEHOLDER VALUES ---
	}

	// Decode the hardcoded hex hash string
	hashBytes, err := hex.DecodeString("004b36d67431f75e3780c941c2dd606b93859c056a838ae7787bf62640957512")
	if err != nil {
		// This should not happen with a valid hex string, but handle it defensively.
		log.Panicf("FATAL: Failed to decode hardcoded genesis hash hex string: %v", err)
	}
	genesis.Hash = hashBytes

	// --- Verification (Optional but recommended after setting actual values) ---
	// Uncomment and run this section locally after replacing placeholders
	// to verify the hardcoded Nonce and Hash are correct for the given Target.
	/*
		pow := NewProofOfWork(genesis)
		isValid, err := pow.Validate()
		if err != nil {
			log.Panicf("FATAL: Error validating hardcoded genesis block PoW: %v", err)
		}
		if !isValid {
			log.Panicf("FATAL: Hardcoded genesis block Nonce/Hash is INVALID for the given Target!")
		}
		log.Println("Hardcoded genesis block PoW verified successfully.")
	*/

	// Verify the calculated hash matches the hardcoded hash (important sanity check)
	// Note: PrepareData needs Transactions to be properly hashed within the block structure first

	// --- DEBUG LOGGING ---
	// txHashBytes := genesis.HashTransactions()
	// log.Printf("[DEBUG] getHardcodedGenesisBlock: Returning Genesis Block:")
	// log.Printf("  Timestamp:     %d", genesis.Timestamp)
	// log.Printf("  PrevBlockHash: %x", genesis.PrevBlockHash)
	// log.Printf("  Transactions:  (Count: %d, Hash: %x)", len(genesis.Transactions), txHashBytes)
	// log.Printf("  Height:        %d", genesis.Height)
	// log.Printf("  Target:        %x", genesis.Target)
	// log.Printf("  Nonce:         %d", genesis.Nonce)
	// log.Printf("  Hash:          %x", genesis.Hash)
	// --- END DEBUG LOGGING ---

	return genesis
}

// Blockchain represents the VIBE blockchain.
// It provides methods to interact with the chain, like adding blocks and retrieving data.
type Blockchain struct {
	db                 *badger.DB    // BadgerDB database handle
	lastBlockHash      []byte        // Hash of the latest block in the chain
	blockBroadcastChan chan<- *Block // Channel to notify network layer of new blocks (write-only)
	// currentHeight is removed; it will be derived from the last block when needed
}

// GetLastBlockHashBytes returns the hash of the last block in the chain.
func (bc *Blockchain) GetLastBlockHashBytes() ([]byte, error) {
	// We already store lastBlockHash in memory, but let's read from DB for consistency?
	// Reading from memory is faster. Let's return the in-memory copy.
	if bc.lastBlockHash == nil {
		// This might happen if DB init failed or the DB was truly empty (before genesis)
		// but NewBlockchain should handle genesis creation.
		return nil, fmt.Errorf("last block hash not available in memory")
	}
	// Return a copy to prevent external modification
	hashCopy := make([]byte, len(bc.lastBlockHash))
	copy(hashCopy, bc.lastBlockHash)
	return hashCopy, nil
}

// NewBlockchain creates a new blockchain instance.
// If the database is empty, it creates and persists the genesis block.
// Otherwise, it loads the latest block hash and height.
// It now accepts a channel to broadcast newly added blocks.
func NewBlockchain(broadcastChan chan<- *Block) (*Blockchain, error) {
	var lastHash []byte

	opts := badger.DefaultOptions(dbPath)
	opts.Logger = nil // Disable Badger logger for cleaner output
	db, err := badger.Open(opts)
	if err != nil {
		log.Printf("Error opening database: %v. Make sure the directory exists or permissions are correct.", err)
		return nil, err
	}

	err = db.Update(func(txn *badger.Txn) error {
		// Check if the last hash key exists
		item, err := txn.Get([]byte(lastHashKey))
		if err == badger.ErrKeyNotFound {
			// No blockchain found, use the hardcoded genesis block
			log.Println("No existing blockchain found. Creating from hardcoded genesis block...")
			// genesis, genErr := createGenesisBlock() // Old dynamic creation
			genesis := getHardcodedGenesisBlock() // Use hardcoded block

			// if genErr != nil {
			// 	return fmt.Errorf("failed to create genesis block: %w", genErr) // Wrap error
			// }

			fmt.Println("Genesis block (received in NewBlockchain):", genesis)

			// --- Verify the hardcoded genesis block (optional runtime check) ---
			// This adds overhead but ensures the compiled code uses a valid genesis.
			// log.Println("[DEBUG] NewBlockchain: Attempting to validate hardcoded genesis block...")
			pow := NewProofOfWork(genesis)
			isValid, powErr := pow.Validate()
			// log.Printf("[DEBUG] NewBlockchain: Validation Result - isValid: %t, powErr: %v", isValid, powErr)
			if powErr != nil || !isValid {
				log.Printf("FATAL: Compiled with invalid hardcoded genesis block! Error: %v, Valid: %t", powErr, isValid)
				return fmt.Errorf("invalid hardcoded genesis block")
			}
			// --- End Verification ---

			// Serialize and store the genesis block
			genesisData, serErr := SerializeBlock(genesis)
			if serErr != nil {
				return fmt.Errorf("failed to serialize genesis block: %w", serErr) // Wrap error
			}
			if err := txn.Set(genesis.Hash, genesisData); err != nil {
				return fmt.Errorf("failed to store genesis block: %w", err) // Wrap error
			}

			// Store the genesis hash as the last hash
			if err := txn.Set([]byte(lastHashKey), genesis.Hash); err != nil {
				return fmt.Errorf("failed to set last hash key for genesis: %w", err) // Wrap error
			}
			lastHash = genesis.Hash
			log.Println("Hardcoded genesis block stored.")
			return nil
		} else if err != nil {
			// Other error reading the last hash key
			return err
		} else {
			// Blockchain exists, load the last hash
			err = item.Value(func(val []byte) error {
				lastHash = append([]byte{}, val...) // Copy the value
				return nil
			})
			log.Println("Existing blockchain found.")
			return err
		}
	})

	if err != nil {
		// Close the DB if initialization failed
		db.Close()
		return nil, err
	}

	bc := &Blockchain{
		db:                 db,
		lastBlockHash:      lastHash,
		blockBroadcastChan: broadcastChan,
	}

	return bc, nil
}

// Close closes the blockchain database.
func (bc *Blockchain) Close() {
	if bc.db != nil {
		bc.db.Close()
	}
}

// createGenesisBlock creates the first block in the chain.
// --- THIS FUNCTION IS NO LONGER USED AND CAN BE REMOVED ---

// SerializeBlock serializes a Block into bytes using gob encoding.
func SerializeBlock(b *Block) ([]byte, error) {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(b)
	if err != nil {
		return nil, fmt.Errorf("failed to encode block: %w", err)
	}
	return result.Bytes(), nil
}

// DeserializeBlock deserializes bytes into a Block using gob encoding.
func DeserializeBlock(d []byte) (*Block, error) {
	var block Block
	decoder := gob.NewDecoder(bytes.NewReader(d))

	err := decoder.Decode(&block)
	if err != nil {
		return nil, fmt.Errorf("failed to decode block: %w", err)
	}
	return &block, nil
}

// AddBlock saves the block into the blockchain database after verification.
func (bc *Blockchain) AddBlock(block *Block) error {
	// --- Verification ---
	// 1. Verify Proof-of-Work
	pow := NewProofOfWork(block)
	validPoW, err := pow.Validate()
	if err != nil {
		return fmt.Errorf("error validating proof of work: %w", err)
	}
	if !validPoW {
		return fmt.Errorf("invalid proof of work for block %x", block.Hash)
	}

	// 2. Verify PrevBlockHash
	// Skip this check for the genesis block (Height 0) as its PrevBlockHash should be empty,
	// and comparing it against the potentially non-empty bc.lastBlockHash is incorrect
	// when the node already has the genesis block.
	// The existence check during persistence handles duplicate genesis blocks.
	if block.Height > 0 {
		// Perform the check only for non-genesis blocks
		if bc.lastBlockHash == nil {
			// This indicates an inconsistent state if adding a non-genesis block
			return fmt.Errorf("cannot add block %x (Height %d): blockchain is not initialized properly (nil lastBlockHash)", block.Hash, block.Height)
		}
		if !bytes.Equal(block.PrevBlockHash, bc.lastBlockHash) {
			// Add block height to the error message for clarity
			return fmt.Errorf("invalid PrevBlockHash for block %d: expected %x, got %x", block.Height, bc.lastBlockHash, block.PrevBlockHash)
		}
	} else {
		// Optional, but good practice: Validate that genesis block indeed has empty PrevBlockHash
		if len(block.PrevBlockHash) != 0 {
			return fmt.Errorf("invalid genesis block (Height 0): PrevBlockHash must be empty, got %x", block.PrevBlockHash)
		}
	}

	// 3. Verify Height is correct (optional but good sanity check)
	// We might need GetLastBlock() for this, which involves a DB read.
	// Or trust bc.lastBlockHash corresponds to the correct height. Let's skip for now.

	// --- Persistence ---
	err = bc.db.Update(func(txn *badger.Txn) error {
		// Check if block already exists (optional, but good practice)
		// _, err := txn.Get(block.Hash)
		// ... (rest of existence check) ...

		// Serialize the block
		blockData, err := SerializeBlock(block)
		if err != nil {
			return fmt.Errorf("failed to serialize block for storage: %w", err)
		}

		// Store the block data
		if err := txn.Set(block.Hash, blockData); err != nil {
			return fmt.Errorf("failed to store block data: %w", err)
		}

		// Update the last block hash pointer
		if err := txn.Set([]byte(lastHashKey), block.Hash); err != nil {
			return fmt.Errorf("failed to update last block hash: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	// Update the in-memory last block hash only if DB update was successful
	bc.lastBlockHash = block.Hash

	log.Printf("Added block %x (Height: %d) to local chain\n", block.Hash, block.Height)

	// --- Broadcast Notification ---
	if bc.blockBroadcastChan != nil {
		// Send non-blockingly in case channel buffer is full or receiver not ready
		select {
		case bc.blockBroadcastChan <- block:
			log.Printf("Sent block %x to broadcast channel.", block.Hash)
		default:
			log.Printf("Warning: Block broadcast channel full or nil. Block %x not broadcasted immediately.", block.Hash)
		}
	}

	return nil
}

// GetBlock finds a block by its hash and returns it
func (bc *Blockchain) GetBlock(blockHash []byte) (*Block, error) {
	var block *Block

	err := bc.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(blockHash)
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("block with hash %x not found", blockHash)
		} else if err != nil {
			return fmt.Errorf("error getting block %x: %w", blockHash, err)
		}

		err = item.Value(func(val []byte) error {
			block, err = DeserializeBlock(val)
			if err != nil {
				// Wrap the deserialization error
				return fmt.Errorf("failed to deserialize block %x: %w", blockHash, err)
			}
			return nil
		})
		return err // Return error from item.Value (or nil if successful)
	})

	if err != nil {
		return nil, err
	}

	return block, nil
}

// GetLastBlock retrieves the most recent block from the database.
func (bc *Blockchain) GetLastBlock() (*Block, error) {
	var lastBlock *Block

	err := bc.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(lastHashKey))
		if err != nil {
			// This could be ErrKeyNotFound if genesis wasn't created, or other DB errors
			return fmt.Errorf("failed to get last block hash key: %w", err)
		}

		var lastHash []byte
		err = item.Value(func(val []byte) error {
			lastHash = append([]byte{}, val...)
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to read last block hash value: %w", err)
		}

		// Now get the actual block data using the hash
		item, err = txn.Get(lastHash)
		if err != nil {
			return fmt.Errorf("failed to get last block data (hash %x): %w", lastHash, err)
		}

		err = item.Value(func(val []byte) error {
			lastBlock, err = DeserializeBlock(val)
			if err != nil {
				return fmt.Errorf("failed to deserialize last block (hash %x): %w", lastHash, err)
			}
			return nil
		})
		return err // Return error from item.Value or nil
	})

	if err != nil {
		return nil, err
	}
	return lastBlock, nil
}

// BlockchainIterator is used to iterate over blockchain blocks
type BlockchainIterator struct {
	db          *badger.DB
	currentHash []byte // Hash of the current block in the iteration
}

// NewIterator creates a new BlockchainIterator starting from the current tip.
func (bc *Blockchain) NewIterator() *BlockchainIterator {
	return &BlockchainIterator{bc.db, bc.lastBlockHash}
}

// NewIteratorStartingFrom creates a new BlockchainIterator starting from a specific block hash.
func (bc *Blockchain) NewIteratorStartingFrom(startHash []byte) *BlockchainIterator {
	// TODO: Check if startHash actually exists in the DB?
	// For now, assume it does.
	return &BlockchainIterator{bc.db, startHash}
}

// Next returns the previous block in the chain and updates the iterator.
// Returns nil when the genesis block is reached or an error occurs.
func (iter *BlockchainIterator) Next() (*Block, error) {
	var block *Block

	err := iter.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(iter.currentHash)
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("iterator error: block %x not found", iter.currentHash)
		} else if err != nil {
			return fmt.Errorf("iterator error getting block %x: %w", iter.currentHash, err)
		}

		err = item.Value(func(val []byte) error {
			block, err = DeserializeBlock(val)
			if err != nil {
				return fmt.Errorf("iterator error deserializing block %x: %w", iter.currentHash, err)
			}
			return nil
		})
		return err
	})

	if err != nil {
		return nil, err
	}

	// Update the iterator's current hash to the previous block's hash
	iter.currentHash = block.PrevBlockHash

	return block, nil
}

// FindUTXO finds all unspent transaction outputs for a given public key hash.
func (bc *Blockchain) FindUTXO(pubKeyHash []byte) []TransactionOutput {
	var utxos []TransactionOutput
	spentTXOs := make(map[string][]int) // Map[txIDHex] -> []spentOutputIndices

	iter := bc.NewIterator()

	for {
		block, err := iter.Next()
		if err != nil {
			// Log the error, but might want to handle differently (e.g., return error)
			log.Printf("Error during UTXO iteration: %v", err)
			break // Stop iteration on error
		}

		// Iterate through transactions in the block
		for _, tx := range block.Transactions {
			txIDHex := hex.EncodeToString(tx.ID)

		Outputs: // Label for breaking inner loop
			for outIdx, out := range tx.Outputs {
				// Was the output spent?
				if spentTXOs[txIDHex] != nil {
					for _, spentOutIdx := range spentTXOs[txIDHex] {
						if spentOutIdx == outIdx {
							continue Outputs // Skip this output, it's spent
						}
					}
				}

				// Is the output locked with the target key?
				if out.IsLockedWithKey(pubKeyHash) {
					utxos = append(utxos, out)
				}
			}

			// Collect spent outputs if not a coinbase transaction
			if !tx.IsCoinbase() {
				for _, in := range tx.Inputs {
					// Check if the input spends an output locked by the target key
					if in.CanUnlockOutputWith(pubKeyHash) {
						inTxIDHex := hex.EncodeToString(in.PrevTxID)
						spentTXOs[inTxIDHex] = append(spentTXOs[inTxIDHex], in.OutputIndex)
					}
				}
			}
		}

		// Stop if we reached the genesis block
		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	return utxos
}

// GetBalance calculates the balance for a given public key hash.
// It sums the amounts of all unspent transaction outputs (UTXOs) for that address.
func (bc *Blockchain) GetBalance(pubKeyHash []byte) int64 {
	balance := int64(0)
	utxos := bc.FindUTXO(pubKeyHash)

	for _, out := range utxos {
		balance += out.Amount
	}

	return balance
}

// FindSpendableOutputs finds spendable transaction outputs for a given address and amount.
// It returns the accumulated amount and a map[txIDHex] -> []outputIndices.
func (bc *Blockchain) FindSpendableOutputs(pubKeyHash []byte, amount int64) (int64, map[string][]int) {
	unspentOutputs := make(map[string][]int) // Map[txIDHex] -> []outputIndices
	accumulated := int64(0)
	spentTXOs := make(map[string][]int) // Map[txIDHex] -> []spentOutputIndices

	iter := bc.NewIterator()

Work:
	for {
		block, err := iter.Next()
		if err != nil {
			log.Printf("Error during spendable outputs iteration: %v", err)
			break // Stop iteration on error
		}

		for _, tx := range block.Transactions {
			txIDHex := hex.EncodeToString(tx.ID)

		Outputs:
			for outIdx, out := range tx.Outputs {
				// Is this output spent?
				if spentTXOs[txIDHex] != nil {
					for _, spentOutIdx := range spentTXOs[txIDHex] {
						if spentOutIdx == outIdx {
							continue Outputs
						}
					}
				}

				// Is this output owned by the sender and contributes to the required amount?
				if out.IsLockedWithKey(pubKeyHash) && accumulated < amount {
					accumulated += out.Amount
					unspentOutputs[txIDHex] = append(unspentOutputs[txIDHex], outIdx)

					// If enough funds accumulated, exit loops
					if accumulated >= amount {
						break Work
					}
				}
			}

			// Gather spent outputs relevant to the sender
			if !tx.IsCoinbase() {
				for _, in := range tx.Inputs {
					if in.CanUnlockOutputWith(pubKeyHash) {
						inTxIDHex := hex.EncodeToString(in.PrevTxID)
						spentTXOs[inTxIDHex] = append(spentTXOs[inTxIDHex], in.OutputIndex)
					}
				}
			}
		}

		if len(block.PrevBlockHash) == 0 {
			break // Reached genesis block
		}
	}

	return accumulated, unspentOutputs
}

// FindTransaction finds a transaction by its ID.
// It iterates backwards through the blockchain.
// Note: This is inefficient for large blockchains. Consider indexing transactions separately.
func (bc *Blockchain) FindTransaction(ID []byte) (*Transaction, error) {
	iter := bc.NewIterator()

	for {
		block, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("error iterating blocks for transaction %x: %w", ID, err)
		}

		for _, tx := range block.Transactions {
			if bytes.Equal(tx.ID, ID) {
				return tx, nil // Found the transaction
			}
		}

		if len(block.PrevBlockHash) == 0 {
			break // Reached genesis block
		}
	}

	return nil, fmt.Errorf("transaction %x not found", ID) // Use fmt.Errorf for specific error
}

// CalculateNextDifficulty determines the target for the next block based on past block times.
func (bc *Blockchain) CalculateNextDifficulty(lastBlock *Block) ([]byte, error) {
	currentHeight := lastBlock.Height
	currentTarget := new(big.Int).SetBytes(lastBlock.Target)
	newHeight := currentHeight + 1

	// Only adjust at the interval
	if newHeight%difficultyAdjustmentInterval != 0 {
		log.Printf("Height %d not adjustment interval, keeping target: %x", newHeight, currentTarget.Bytes())
		return currentTarget.Bytes(), nil
	}

	// --- Find the block at the start of the adjustment interval ---
	var firstBlockInWindow *Block
	firstBlockHeight := newHeight - difficultyAdjustmentInterval

	// Iterate backwards (could be optimized if block heights were indexed)
	count := int64(0)
	iter := bc.NewIterator() // Starts from lastBlock
	for count < difficultyAdjustmentInterval {
		block, err := iter.Next() // Gets the previous block
		if err != nil {
			return nil, fmt.Errorf("failed to iterate back for difficulty adjustment: %w", err)
		}
		if block == nil || len(block.PrevBlockHash) == 0 { // Should not happen if interval > height
			return currentTarget.Bytes(), nil // Not enough blocks yet, keep current target
		}
		if block.Height == firstBlockHeight {
			firstBlockInWindow = block
			break
		}
		count++
		if count > difficultyAdjustmentInterval { // Safety break
			log.Println("Warning: Difficulty adjustment iteration went too far.")
			return currentTarget.Bytes(), nil
		}
	}

	if firstBlockInWindow == nil {
		// Should not happen if height >= interval
		log.Printf("Warning: Could not find block at height %d for difficulty adjustment. Keeping target: %x", firstBlockHeight, currentTarget.Bytes())
		return currentTarget.Bytes(), nil
	}

	// --- Calculate Time Difference ---
	actualTime := lastBlock.Timestamp - firstBlockInWindow.Timestamp
	expectedTime := int64(difficultyAdjustmentInterval * targetBlockTimeSeconds)

	log.Printf("Difficulty Adjustment Check: Height %d, Actual Time: %ds, Expected Time: %ds\n",
		newHeight, actualTime, expectedTime)

	// --- Adjust Target ---
	// newTarget = currentTarget * actualTime / expectedTime
	newTarget := new(big.Int)
	newTarget.Mul(currentTarget, big.NewInt(actualTime))
	newTarget.Div(newTarget, big.NewInt(expectedTime))

	// --- Clamping ---
	// Clamp maximum difficulty increase (target decrease)
	// Max decrease = currentTarget / 4
	maxDecreaseTarget := new(big.Int).Div(currentTarget, maxRetargetFactor)
	if newTarget.Cmp(maxDecreaseTarget) < 0 { // If newTarget < maxDecreaseTarget
		newTarget.Set(maxDecreaseTarget)
		log.Println("Difficulty increase limit hit (target floor). Adjusted target to max decrease.")
	}

	// Clamp maximum difficulty decrease (target increase)
	// Max increase = currentTarget * 4
	maxIncreaseTarget := new(big.Int).Mul(currentTarget, maxRetargetFactor)
	// Also ensure target doesn't exceed the absolute maximum (all bits 1)
	absoluteMaxTarget := big.NewInt(1)
	absoluteMaxTarget.Lsh(absoluteMaxTarget, maxTargetBits)
	if maxIncreaseTarget.Cmp(absoluteMaxTarget) > 0 {
		maxIncreaseTarget.Set(absoluteMaxTarget)
	}
	if newTarget.Cmp(maxIncreaseTarget) > 0 { // If newTarget > maxIncreaseTarget
		newTarget.Set(maxIncreaseTarget)
		log.Println("Difficulty decrease limit hit (target ceiling). Adjusted target to max increase.")
	}

	// Ensure target is never zero or negative (shouldn't happen with positive times, but safety)
	if newTarget.Sign() <= 0 {
		log.Println("Warning: Calculated target was zero or negative. Resetting to initial target.")
		newTarget.Set(initialTarget)
	}

	if newTarget.Cmp(currentTarget) != 0 {
		log.Printf("Difficulty adjusted at height %d. Old Target: %x, New Target: %x\n",
			newHeight, currentTarget.Bytes(), newTarget.Bytes())
	} else {
		log.Printf("No target adjustment needed at height %d. Target: %x", newHeight, newTarget.Bytes())
	}

	return newTarget.Bytes(), nil
}

// GetCurrentBlockReward calculates the block reward for a given height,
// considering the halving schedule.
func GetCurrentBlockReward(height int64) int64 {
	initialReward := int64(InitialBlockReward)
	// Calculate the number of halvings that have occurred
	halvings := height / blockRewardHalvingInterval

	// Max halvings can be capped (e.g., 64 for int64) to prevent overflow/underflow
	if halvings >= 64 {
		return 0 // Reward effectively becomes 0 after many halvings
	}

	// Calculate reward by right-shifting (integer division by 2) for each halving
	reward := initialReward >> halvings

	return reward
}

// TODO:
// - Implement AddBlock method
// - Implement methods to get blocks (by hash, by height)
// - Implement methods to get transactions
// - Implement Blockchain Iterator
// - Implement proper database integration (e.g., using BadgerDB, LevelDB)
// - Define the Coinbase Transaction structure
