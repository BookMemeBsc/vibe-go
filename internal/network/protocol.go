package network

import (
	"vibe-ai/internal/core"
)

// Protocol IDs
const (
	BlockSyncProtocolID    = "/vibe/blocks/1.0.0"
	InventoryProtocolID    = "/vibe/inventory/1.0.0"
	TxSyncProtocolID       = "/vibe/tx/1.0.0"
	SubmitTxProtocolID     = "/vibe/submit_tx/1.0.0"
	PeerExchangeProtocolID = "/vibe/peers/1.0.0" // Protocol for exchanging peer lists
	// TODO: Add protocol for transactions, etc.
)

// Message Types (using constants for clarity)
const (
	// Block Sync related
	MsgTypeGetBlocksRequest = 1
	MsgTypeBlocksResponse   = 2

	// Inventory related
	MsgTypeInvBlock = 10 // Announce a new block hash
	MsgTypeInvTx    = 11 // Announce a new transaction hash

	// Transaction Sync related
	MsgTypeGetTx = 20 // Request a specific transaction
	MsgTypeTx    = 21 // Send a specific transaction
	// TODO: Add MsgTypeInvTx for transactions

	// Peer Exchange related
	MsgTypePeerList = 30 // Send a list of peer addresses
)

// BaseMessage helps determine the actual message type
type BaseMessage struct {
	Type int
}

// GetBlocksRequest asks a peer for blocks starting after a specific hash.
// If FromHash is empty, it requests blocks from genesis.
type GetBlocksRequest struct {
	FromHash []byte // Hash of the last block the requester has
}

// BlocksResponse sends blocks to a requesting peer.
type BlocksResponse struct {
	Blocks []*core.Block
}

// InvBlock announces the inventory (hash) of a new block.
type InvBlock struct {
	Hash   []byte
	Height int64
}

// InvTx announces the inventory (hash) of a new transaction.
type InvTx struct {
	TxID []byte
}

// GetTx requests a transaction by its ID.
type GetTx struct {
	TxID []byte
}

// Tx sends a transaction.
type Tx struct {
	Transaction *core.Transaction
}

// SubmitTx is used by clients to submit a new transaction to a node.
type SubmitTx struct {
	SerializedTx []byte
}

// PeerListMessage contains a list of peer multiaddresses for PEX.
type PeerListMessage struct {
	PeerAddrs [][]byte // List of multiaddresses (encoded as bytes)
}

// TODO:
// - Add message types for announcing new blocks/transactions.
// - Consider using Protobuf instead of gob for better cross-language compatibility and efficiency.
