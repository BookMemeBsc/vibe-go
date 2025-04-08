package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"vibe-ai/internal/wallet"

	"golang.org/x/crypto/ripemd160"
)

// TransactionInput represents an input reference in a transaction.
// It points to a previous transaction output.
type TransactionInput struct {
	PrevTxID    []byte // The ID of the transaction containing the output to spend
	OutputIndex int    // The index of the output in the previous transaction
	Signature   []byte // Signature proving ownership of the output being spent
	PubKey      []byte // Public key corresponding to the signature
}

// TransactionOutput represents an output in a transaction.
// It specifies the amount and the conditions required to spend it (typically a public key hash).
type TransactionOutput struct {
	Amount     int64  // Value in the smallest denomination of VIBE
	PubKeyHash []byte // Hash of the public key required to spend this output
}

// Transaction represents a transfer of value on the VIBE network.
type Transaction struct {
	ID        []byte              // Unique identifier for the transaction (hash of its contents)
	Timestamp time.Time           // Time the transaction was created
	Inputs    []TransactionInput  // List of inputs spending previous outputs
	Outputs   []TransactionOutput // List of new outputs created
}

// Serialize returns a serialized representation of the transaction (excluding ID).
// Used for hashing.
func (tx *Transaction) Serialize() []byte {
	var encoded bytes.Buffer

	// Create a copy of the transaction but without the ID for serialization
	txCopy := *tx
	txCopy.ID = nil

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(txCopy)
	if err != nil {
		// In a real application, proper error handling is crucial.
		// For simplicity here, we'll log a fatal error.
		log.Panicf("Failed to encode transaction: %v", err)
	}

	return encoded.Bytes()
}

// SetID calculates and sets the transaction ID (hash).
func (tx *Transaction) SetID() {
	hash := sha256.Sum256(tx.Serialize())
	tx.ID = hash[:]
}

// SerializeForSubmission returns a serialized representation of the full transaction (including ID).
func (tx *Transaction) SerializeForSubmission() ([]byte, error) {
	var encoded bytes.Buffer
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx) // Encode the whole struct
	if err != nil {
		return nil, fmt.Errorf("failed to encode full transaction: %w", err)
	}
	return encoded.Bytes(), nil
}

// IsCoinbase checks whether the transaction is a coinbase transaction.
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Inputs) == 1 && len(tx.Inputs[0].PrevTxID) == 0 && tx.Inputs[0].OutputIndex == -1
}

// Sign signs each input of a Transaction.
// Requires the private key of the sender and a map of previous transactions referenced by the inputs.
func (tx *Transaction) Sign(privKey ecdsa.PrivateKey, prevTXs map[string]Transaction) error {
	if tx.IsCoinbase() {
		return nil // Coinbase transactions are not signed
	}

	// Check if all previous transactions are provided
	for _, vin := range tx.Inputs {
		if _, ok := prevTXs[hex.EncodeToString(vin.PrevTxID)]; !ok {
			return errors.New("Previous transaction is not found for signing")
		}
	}

	// Create a trimmed copy for signing
	txCopy := tx.TrimmedCopy()

	// Sign each input
	for inID, vin := range txCopy.Inputs {
		prevTx := prevTXs[hex.EncodeToString(vin.PrevTxID)]
		// The PubKey in the input being signed is set to the PubKeyHash of the *output* it references.
		txCopy.Inputs[inID].Signature = nil
		txCopy.Inputs[inID].PubKey = prevTx.Outputs[vin.OutputIndex].PubKeyHash

		// Hash the serialized trimmed copy
		dataToSign := txCopy.Serialize()
		hashToSign := sha256.Sum256(dataToSign)

		// Sign the hash
		r, s, err := ecdsa.Sign(rand.Reader, &privKey, hashToSign[:])
		if err != nil {
			return fmt.Errorf("failed to sign input %d: %w", inID, err)
		}
		signature := append(r.Bytes(), s.Bytes()...)

		// Store the signature in the original transaction's input
		tx.Inputs[inID].Signature = signature

		// Reset PubKey in the copy for the next iteration (important!)
		txCopy.Inputs[inID].PubKey = nil
	}

	return nil
}

// Verify verifies the signatures of Transaction inputs.
// Requires a map of previous transactions referenced by the inputs.
func (tx *Transaction) Verify(prevTXs map[string]Transaction) (bool, error) {
	if tx.IsCoinbase() {
		return true, nil // Coinbase transactions are considered valid by definition here
	}

	// Check if all previous transactions are provided and valid
	for _, vin := range tx.Inputs {
		if _, ok := prevTXs[hex.EncodeToString(vin.PrevTxID)]; !ok {
			return false, errors.New("Previous transaction is not found for verification")
		}
	}

	// Create a trimmed copy for verification
	txCopy := tx.TrimmedCopy()
	curve := elliptic.P256() // Assuming P256 curve, consistent with wallet generation

	// Verify each input signature
	for inID, vin := range tx.Inputs { // Iterate over original inputs to get Sig and PubKey
		prevTx := prevTXs[hex.EncodeToString(vin.PrevTxID)]

		// Prepare data for verification (similar to signing)
		txCopy.Inputs[inID].Signature = nil
		txCopy.Inputs[inID].PubKey = prevTx.Outputs[vin.OutputIndex].PubKeyHash // Use PubKeyHash from the spent output

		dataToVerify := txCopy.Serialize()
		hashToVerify := sha256.Sum256(dataToVerify)

		// Reset PubKey in the copy for the next iteration
		txCopy.Inputs[inID].PubKey = nil

		// Parse the signature (r, s)
		if len(vin.Signature) == 0 {
			return false, fmt.Errorf("input %d has no signature", inID)
		}
		r := big.Int{}
		s := big.Int{}
		sigLen := len(vin.Signature)
		r.SetBytes(vin.Signature[:(sigLen / 2)])
		s.SetBytes(vin.Signature[(sigLen / 2):])

		// Parse the public key (x, y)
		if len(vin.PubKey) == 0 {
			return false, fmt.Errorf("input %d has no public key", inID)
		}
		x := big.Int{}
		y := big.Int{}
		keyLen := len(vin.PubKey)
		x.SetBytes(vin.PubKey[:(keyLen / 2)])
		y.SetBytes(vin.PubKey[(keyLen / 2):])

		rawPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}

		// Verify the signature against the hash and the public key
		if !ecdsa.Verify(&rawPubKey, hashToVerify[:], &r, &s) {
			// Signature is invalid
			return false, nil
		}
	}

	// All input signatures are valid
	return true, nil
}

// TrimmedCopy creates a deep copy of the Transaction suitable for signing/verification.
// It sets Signature to nil and PubKey to nil for all inputs.
func (tx *Transaction) TrimmedCopy() Transaction {
	var inputs []TransactionInput
	var outputs []TransactionOutput

	for _, vin := range tx.Inputs {
		inputs = append(inputs, TransactionInput{vin.PrevTxID, vin.OutputIndex, nil, nil})
	}

	for _, vout := range tx.Outputs {
		outputs = append(outputs, TransactionOutput{vout.Amount, vout.PubKeyHash})
	}

	txCopy := Transaction{
		ID:        tx.ID, // Keep original ID for context if needed, though it's recalculated in Verify
		Timestamp: tx.Timestamp,
		Inputs:    inputs,
		Outputs:   outputs,
	}

	return txCopy
}

// NewCoinbaseTX creates a new coinbase transaction.
// Coinbase transactions have no inputs and create new coins as a reward.
func NewCoinbaseTX(toPubKeyHash []byte, blockHeight int64, reward int64) *Transaction {
	// Coinbase input can contain arbitrary data, often the block height for uniqueness.
	inputData := fmt.Sprintf("Block %d reward", blockHeight)

	txInput := TransactionInput{
		PrevTxID:    []byte{},
		OutputIndex: -1, // Coinbase inputs don't refer to previous outputs
		Signature:   nil,
		PubKey:      []byte(inputData),
	}

	txOutput := TransactionOutput{
		Amount:     reward,
		PubKeyHash: toPubKeyHash,
	}

	// Determine the timestamp: Use 0 for genesis (height 0), time.Now() otherwise
	var txTimestamp time.Time
	if blockHeight == 0 {
		txTimestamp = time.Unix(0, 0) // Use Unix epoch (0) for genesis coinbase
	} else {
		txTimestamp = time.Now()
	}

	tx := Transaction{
		Timestamp: txTimestamp, // Use the determined timestamp
		Inputs:    []TransactionInput{txInput},
		Outputs:   []TransactionOutput{txOutput},
	}

	tx.SetID() // Calculate the hash (ID) for the coinbase transaction
	return &tx
}

// CanUnlockOutputWith checks if the input uses the provided public key hash.
// Note: This compares the provided pubKeyHash against the hash of the PubKey stored in the input.
func (in *TransactionInput) CanUnlockOutputWith(pubKeyHash []byte) bool {
	// Avoid hashing if PubKey is nil (e.g., in coinbase input or trimmed copy)
	if in.PubKey == nil {
		return false
	}
	hashing := sha256.Sum256(in.PubKey)
	hasher := ripemd160.New()
	_, err := hasher.Write(hashing[:])
	if err != nil {
		log.Panic(err) // Or return false with error
	}
	actualPubKeyHash := hasher.Sum(nil)
	return bytes.Equal(actualPubKeyHash, pubKeyHash)
}

// IsLockedWithKey checks if the output can be unlocked with the provided public key hash
func (out *TransactionOutput) IsLockedWithKey(pubKeyHash []byte) bool {
	return bytes.Equal(out.PubKeyHash, pubKeyHash)
}

// NewTransaction creates a new transaction
func NewTransaction(fromWallet *wallet.Wallet, toPubKeyHash []byte, amount int64, bc *Blockchain) (*Transaction, error) {
	var inputs []TransactionInput
	var outputs []TransactionOutput

	pubKeyHash := wallet.HashPubKey(fromWallet.PublicKey)
	acc, validOutputs := bc.FindSpendableOutputs(pubKeyHash, amount)

	if acc < amount {
		return nil, fmt.Errorf("insufficient funds: requested %d, available %d", amount, acc)
	}

	// Build list of inputs
	prevTXs := make(map[string]Transaction)
	for txidHex, outIndices := range validOutputs {
		txID, err := hex.DecodeString(txidHex)
		if err != nil {
			// This should realistically not happen if FindSpendableOutputs is correct
			log.Panicf("Error decoding txID hex %s: %v", txidHex, err)
			return nil, err
		}

		// Fetch the previous transaction needed for signing
		prevTx, err := bc.FindTransaction(txID)
		if err != nil {
			log.Printf("Could not find previous transaction %s for signing: %v", txidHex, err)
			return nil, err
		}
		prevTXs[txidHex] = *prevTx // Store the actual transaction, not pointer

		for _, outIdx := range outIndices {
			input := TransactionInput{
				PrevTxID:    txID,
				OutputIndex: outIdx,
				Signature:   nil, // Signature will be added by Sign method
				PubKey:      fromWallet.PublicKey,
			}
			inputs = append(inputs, input)
		}
	}

	// Build list of outputs
	// Output to recipient
	outputs = append(outputs, TransactionOutput{amount, toPubKeyHash})
	// Output for change (if any)
	if acc > amount {
		outputs = append(outputs, TransactionOutput{acc - amount, pubKeyHash})
	}

	tx := Transaction{
		Timestamp: time.Now(),
		Inputs:    inputs,
		Outputs:   outputs,
	}
	tx.SetID() // Calculate the transaction ID

	// Sign the inputs
	// Reconstruct the private key object before signing
	privKey := fromWallet.GetPrivateKey()
	err := tx.Sign(*privKey, prevTXs)
	if err != nil {
		log.Printf("Failed to sign transaction: %v", err)
		return nil, err
	}

	return &tx, nil
}

// DeserializeTransaction deserializes bytes into a Transaction using gob encoding.
func DeserializeTransaction(data []byte) (*Transaction, error) {
	var tx Transaction
	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&tx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}
	return &tx, nil
}

// TODO:
// - Implement methods for hashing transactions (SetID)
// - Implement methods for signing inputs
// - Implement methods for verifying signatures
// - Implement methods for locking/unlocking outputs (using PubKeyHash)
// - Define coinbase transaction structure (for validator rewards)
// - Implement NewTransaction function
