package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
	"vibe-ai/internal/core"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	routing "github.com/libp2p/go-libp2p/core/routing"
	discovery_routing "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	discovery_util "github.com/libp2p/go-libp2p/p2p/discovery/util"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/multiformats/go-multiaddr"
	// Renamed alias
)

// SeedNodes defines the initial peers to connect to for bootstrapping the network.
// TODO: Replace these with actual seed node multiaddresses.
const (
	SeedNode1 = "/ip4/149.56.169.165/tcp/9001/p2p/12D3KooWETQAujZCiik1Hc3y3i64fZg1VEkGSEEb7cdQyEshaie2" // Example libp2p bootstrap node
	SeedNode2 = "/ip4/198.50.215.62/tcp/9002/p2p/12D3KooWJ2fyPfa1sRwmrMtvDNLSmM752emvauzFkGnPZM1mBLGA"  // Example libp2p bootstrap node

	// VibeNetworkRendezvousString is a unique string used for peer discovery within the DHT.
	VibeNetworkRendezvousString = "vibe-network-rendezvous-v1"

	// MaxBlocksPerSyncResponse defines the maximum number of blocks a node will
	// send in a single BlocksResponse message during synchronization.
	MaxBlocksPerSyncResponse = 500

	// Connection Manager Settings
	ConnManagerLowWater    = 20  // Minimum number of connections to maintain
	ConnManagerHighWater   = 100 // Maximum number of connections before pruning
	ConnManagerGracePeriod = time.Minute
)

var BootstrapPeers []multiaddr.Multiaddr

func init() {
	// Parse the multiaddresses for the bootstrap peers.
	// It's better to do this once at startup.
	for _, addrStr := range []string{SeedNode1, SeedNode2} {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			// Use log.Fatalf because if we can't parse bootstrap nodes, we can't proceed.
			log.Fatalf("Error parsing bootstrap node multiaddr '%s': %v", addrStr, err)
		}
		BootstrapPeers = append(BootstrapPeers, addr)
	}
}

// Node represents the running VIBE P2P node.
type Node struct {
	ctx                context.Context
	Host               host.Host
	Blockchain         *core.Blockchain
	blockBroadcastChan chan *core.Block             // Channel for broadcasting new blocks
	Mempool            map[string]*core.Transaction // Transaction mempool [txIDHex -> Transaction]
	MempoolMutex       sync.RWMutex                 // Mutex for protecting mempool access
	dht                *dht.IpfsDHT                 // Kademlia DHT for discovery
	// TODO: Add Mempool map[string]*core.Transaction
}

// NewNode creates and initializes a new VIBE node.
func NewNode(ctx context.Context, listenPort int, privKey crypto.PrivKey) (*Node, error) {
	// --- Create Broadcast Channel ---
	// Use a buffered channel to avoid blocking AddBlock if broadcast is slow
	blockChan := make(chan *core.Block, 10)

	// --- Blockchain Initialization ---
	// Ensure the data directory exists
	if _, err := os.Stat("./data"); os.IsNotExist(err) {
		log.Println("Data directory not found, creating './data'")
		err = os.Mkdir("./data", 0755) // Create data directory if it doesn't exist
		if err != nil {
			return nil, fmt.Errorf("failed to create data directory: %w", err)
		}
	}
	bc, err := core.NewBlockchain(blockChan) // Pass channel to blockchain
	if err != nil {
		// Cannot proceed without blockchain
		return nil, fmt.Errorf("failed to initialize blockchain: %w", err)
	}
	// Note: Need to defer bc.Close() somewhere, maybe in main after node creation?

	// --- Connection Manager Initialization ---
	cm, err := connmgr.NewConnManager(
		ConnManagerLowWater,
		ConnManagerHighWater,
		connmgr.WithGracePeriod(ConnManagerGracePeriod),
	)
	if err != nil {
		bc.Close()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// --- Host Initialization ---
	var kadDHT *dht.IpfsDHT // Declare kadDHT variable
	listenAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort))
	if err != nil {
		bc.Close() // Clean up blockchain if host fails
		return nil, fmt.Errorf("failed to create listen multiaddr: %w", err)
	}
	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(listenAddr),
		libp2p.Security(noise.ID, noise.New),
		// Enable the DHT
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			var err error
			// TODO: Configure DHT options (e.g., server mode, bootstrap peers)
			kadDHT, err = dht.New(ctx, h)
			return kadDHT, err
		}),
		// Attempt to open ports using uPNP for better connectivity.
		libp2p.EnableNATService(),
		// Configure the connection manager.
		libp2p.ConnectionManager(cm),
	)
	if err != nil {
		bc.Close() // Clean up blockchain if host fails
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	n := &Node{
		ctx:                ctx,
		Host:               h,
		Blockchain:         bc,
		blockBroadcastChan: blockChan,
		Mempool:            make(map[string]*core.Transaction),
		dht:                kadDHT, // Store the DHT instance
	}

	log.Printf("Node created. ID: %s", h.ID().String())
	log.Println("Listening on addresses:")
	for _, addr := range h.Addrs() {
		log.Printf("  %s/p2p/%s", addr, h.ID().String())
	}

	return n, nil
}

// Start sets up stream handlers and starts background processes like broadcasting.
func (n *Node) Start() {
	// Block Sync Handler
	blockSyncHandler := func(stream network.Stream) {
		n.HandleBlockSyncStream(stream)
	}
	n.Host.SetStreamHandler(BlockSyncProtocolID, blockSyncHandler)

	// Inventory Handler
	inventoryHandler := func(stream network.Stream) {
		n.HandleInventoryStream(stream)
	}
	n.Host.SetStreamHandler(InventoryProtocolID, inventoryHandler)

	// Transaction Sync Handler
	txSyncHandler := func(stream network.Stream) {
		n.HandleTxSyncStream(stream)
	}
	n.Host.SetStreamHandler(TxSyncProtocolID, txSyncHandler)

	// Transaction Submission Handler
	submitTxHandler := func(stream network.Stream) {
		n.HandleSubmitTxStream(stream)
	}
	n.Host.SetStreamHandler(SubmitTxProtocolID, submitTxHandler)

	// Peer Exchange Handler
	pexHandler := func(stream network.Stream) {
		n.HandlePeerExchangeStream(stream)
	}
	n.Host.SetStreamHandler(PeerExchangeProtocolID, pexHandler)

	log.Println("Node started successfully and handlers set.")

	// Start Broadcast Listener Goroutine
	go n.listenForBroadcasts()

	// Start Bootstrap Connection Process
	go n.BootstrapConnect()

	// Start Peer Discovery Process
	go n.DiscoverPeers()

	// Start Periodic Peer Exchange
	go n.ExchangePeersPeriodically()
}

// listenForBroadcasts listens on the blockBroadcastChan and broadcasts inventory.
func (n *Node) listenForBroadcasts() {
	log.Println("Broadcast listener started.")
	for {
		select {
		case block := <-n.blockBroadcastChan:
			log.Printf("Broadcasting new block: Hash=%x Height=%d", block.Hash, block.Height)
			inv := InvBlock{Hash: block.Hash, Height: block.Height}
			// Use node's context for broadcast, respects shutdown signal
			n.BroadcastMessage(InventoryProtocolID, inv)
		case <-n.ctx.Done(): // Listen for context cancellation (shutdown)
			log.Println("Broadcast listener shutting down.")
			return
		}
	}
}

// TriggerInitialSync requests blocks from a connected peer to start synchronization.
// It tries to find a connected bootstrap peer first.
func (n *Node) TriggerInitialSync() {
	log.Println("Attempting to trigger initial block sync...")
	connectedPeers := n.Host.Network().Peers()
	if len(connectedPeers) == 0 {
		log.Println("No connected peers to sync with yet.")
		// Consider retrying later or relying on discovery finding peers.
		return
	}

	// Prefer syncing from a bootstrap peer if connected
	var syncPeer peer.ID
	bootstrapPeerMap := make(map[peer.ID]struct{})
	for _, addr := range BootstrapPeers {
		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err == nil {
			bootstrapPeerMap[info.ID] = struct{}{}
		}
	}

	for _, p := range connectedPeers {
		if _, isBootstrap := bootstrapPeerMap[p]; isBootstrap {
			syncPeer = p
			log.Printf("Found connected bootstrap peer %s for initial sync.", syncPeer)
			break
		}
	}

	// If no bootstrap peer connected, pick the first connected peer
	if syncPeer == "" && len(connectedPeers) > 0 {
		syncPeer = connectedPeers[0]
		log.Printf("No bootstrap peer connected, using %s for initial sync.", syncPeer)
	}

	if syncPeer != "" {
		// Request blocks starting from our last known hash (or genesis if empty)
		lastHash, err := n.Blockchain.GetLastBlockHashBytes()
		if err != nil {
			// If we can't get the last hash (e.g., empty DB), use an empty slice,
			// which implies requesting from the genesis block.
			log.Println("Local blockchain seems empty or failed to get last hash. Requesting blocks from genesis.")
			lastHash = []byte{}
		}

		go func() {
			// Run sync in a goroutine to avoid blocking BootstrapConnect
			currentLastHash := lastHash
			totalBlocksAdded := 0

			for {
				log.Printf("Initial sync: Requesting blocks after %x from %s", currentLastHash, syncPeer)
				receivedBlocks, moreAvailable, err := n.RequestBlocks(syncPeer, currentLastHash)
				if err != nil {
					log.Printf("Initial sync request to %s failed: %v", syncPeer, err)
					break // Stop sync loop on error
				}

				if len(receivedBlocks) == 0 {
					if !moreAvailable {
						log.Printf("Initial sync: Received 0 blocks from %s and no more available. Sync complete or peer has no new blocks.", syncPeer)
					} else {
						log.Printf("Initial sync: Received 0 blocks from %s but more are available? Potentially lagging peer. Will retry later.", syncPeer)
					}
					break // Stop sync loop
				}

				log.Printf("Initial sync: Received %d blocks from %s (MoreAvailable: %v). Adding to chain...", len(receivedBlocks), syncPeer, moreAvailable)
				addedInBatch := 0
				lastBlockInBatch := receivedBlocks[len(receivedBlocks)-1]
				for _, block := range receivedBlocks {
					err := n.Blockchain.AddBlock(block)
					if err != nil {
						log.Printf("Initial sync: Failed to add block %x (Height: %d): %v", block.Hash, block.Height, err)
						// Stop processing this batch and the entire sync on error
						moreAvailable = false // Ensure we stop the outer loop
						break
					} else {
						addedInBatch++
					}
				}
				totalBlocksAdded += addedInBatch
				log.Printf("Initial sync: Processed batch, added %d blocks.", addedInBatch)

				if !moreAvailable {
					log.Printf("Initial sync: No more blocks available from %s.", syncPeer)
					break // Exit sync loop
				}

				// If more are available, update the hash for the next request
				currentLastHash = lastBlockInBatch.Hash

				// Add a small delay or check context cancellation?
				select {
				case <-n.ctx.Done():
					log.Println("Initial sync cancelled.")
					return
				case <-time.After(100 * time.Millisecond): // Brief pause before next request
				}
			}
			log.Printf("Initial sync process finished. Total blocks added: %d", totalBlocksAdded)
		}()
	} else {
		log.Println("Initial sync: Could not find a suitable peer to sync with.")
	}
}

// BootstrapConnect attempts to connect to the hardcoded bootstrap peers.
func (n *Node) BootstrapConnect() {
	log.Println("Starting bootstrap connection process...")
	var wg sync.WaitGroup
	connectionTimeout := 10 * time.Second // Timeout for each connection attempt

	for _, peerAddr := range BootstrapPeers {
		peerinfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
		if err != nil {
			log.Printf("Error parsing bootstrap peer address %s: %v", peerAddr, err)
			continue // Skip this peer if address is invalid
		}

		wg.Add(1)
		go func(pi peer.AddrInfo) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(n.ctx, connectionTimeout)
			defer cancel()

			err := n.Host.Connect(ctx, pi)
			if err != nil {
				log.Printf("Bootstrap connection to %s failed: %v", pi.ID, err)
			} else {
				log.Printf("Successfully connected to bootstrap peer: %s", pi.ID)
			}
		}(*peerinfo) // Pass a copy of peerinfo to the goroutine
	}

	wg.Wait() // Wait for all connection attempts to complete

	// Bootstrap the DHT. In the default configuration, this spawns background
	// processes that will refresh the peer table every hour.
	log.Println("Bootstrapping the DHT...")
	if err := n.dht.Bootstrap(n.ctx); err != nil {
		log.Printf("Error bootstrapping DHT: %v", err)
	} else {
		log.Println("DHT bootstrap process initiated.")
	}

	// Attempt initial sync after bootstrapping
	n.TriggerInitialSync()
}

// DiscoverPeers continuously searches for new peers using the DHT and connects to them.
func (n *Node) DiscoverPeers() {
	log.Println("Starting peer discovery process...")
	routingDiscovery := discovery_routing.NewRoutingDiscovery(n.dht)

	// Advertise our presence
	log.Printf("Announcing ourselves on rendezvous point: %s", VibeNetworkRendezvousString)
	discovery_util.Advertise(n.ctx, routingDiscovery, VibeNetworkRendezvousString)

	discoveryTicker := time.NewTicker(15 * time.Second) // Search for peers every 15 seconds
	defer discoveryTicker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			log.Println("Peer discovery process shutting down.")
			return
		case <-discoveryTicker.C:
			log.Println("Searching for new peers...")
			peerChan, err := routingDiscovery.FindPeers(n.ctx, VibeNetworkRendezvousString)
			if err != nil {
				log.Printf("Error finding peers: %v", err)
				continue
			}

			for peerInfo := range peerChan {
				if peerInfo.ID == n.Host.ID() {
					continue // Skip self
				}

				// Check if we are already connected or connecting
				if n.Host.Network().Connectedness(peerInfo.ID) != network.NotConnected {
					// log.Printf("Already connected/connecting to peer: %s", peerInfo.ID)
					continue
				}

				// Don't attempt too many connections concurrently if FindPeers returns many
				// The connection manager will handle pruning if we exceed HighWater.
				go func(pi peer.AddrInfo) {
					ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
					defer cancel()
					err := n.Host.Connect(ctx, pi)
					if err != nil {
						log.Printf("Discovery: connection to %s failed: %v", pi.ID, err)
					} else {
						log.Printf("Discovery: successfully connected to peer: %s", pi.ID)
					}
				}(peerInfo)
			}
		}
	}
}

// HandleBlockSyncStream handles incoming block sync requests.
func (n *Node) HandleBlockSyncStream(stream network.Stream) {
	bc := n.Blockchain
	remotePeer := stream.Conn().RemotePeer() // Get remote peer ID early
	log.Printf("Got a new block sync stream from %s", remotePeer)
	defer stream.Close()

	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	decoder := gob.NewDecoder(rw)
	encoder := gob.NewEncoder(rw)

	var req GetBlocksRequest
	err := decoder.Decode(&req)
	if err != nil {
		if err == io.EOF {
			log.Printf("Block sync stream from %s closed before request received.", remotePeer)
		} else {
			log.Printf("Error decoding GetBlocksRequest from %s: %v", remotePeer, err)
		}
		return
	}

	maxBlocksToSend := req.MaxBlocks
	if maxBlocksToSend <= 0 || maxBlocksToSend > MaxBlocksPerSyncResponse { // Use a defined constant or reasonable default
		maxBlocksToSend = MaxBlocksPerSyncResponse // e.g., 500
	}
	log.Printf("Received GetBlocksRequest from %s, requesting blocks after hash: %x (max: %d)", remotePeer, req.FromHash, maxBlocksToSend)

	blocksToSend := make([]*core.Block, 0, maxBlocksToSend) // Pre-allocate slice
	moreAvailable := false
	lastKnownHash := req.FromHash

	currentTipHash, err := bc.GetLastBlockHashBytes()
	if err != nil {
		log.Printf("Error getting last block hash for %s: %v", remotePeer, err)
		// Consider sending an error response or just closing
		return
	}

	// If the peer's last known hash is our current tip, they are up-to-date
	if bytes.Equal(lastKnownHash, currentTipHash) {
		log.Printf("Peer %s is already up-to-date (tip: %x). Sending empty response.", remotePeer, currentTipHash)
		resp := BlocksResponse{Blocks: []*core.Block{}, MoreBlocksAvailable: false}
		err = encoder.Encode(resp)
		if err != nil {
			log.Printf("Error encoding empty BlocksResponse to %s: %v", remotePeer, err)
		} else {
			err = rw.Flush()
			if err != nil {
				log.Printf("Error flushing empty BlocksResponse to %s: %v", remotePeer, err)
			}
		}
		return
	}

	iter := bc.NewIteratorStartingFrom(currentTipHash) // Start from our tip

	foundAncestor := false
	for len(blocksToSend) < maxBlocksToSend {
		block, err := iter.Next() // Iterates backwards
		if err != nil {
			log.Printf("Error iterating blockchain for %s: %v", remotePeer, err)
			break // Stop processing on iterator error
		}
		if block == nil {
			// Reached the end of iteration (should theoretically hit genesis)
			log.Printf("Iterator reached end unexpectedly for %s request.", remotePeer)
			break
		}

		// Stop if we reach the block the peer already has
		if bytes.Equal(block.Hash, lastKnownHash) {
			foundAncestor = true
			break
		}

		// Add block to the list (prepended to maintain order)
		blocksToSend = append([]*core.Block{block}, blocksToSend...)

		// Stop if we reach the genesis block (unless it's the requested ancestor)
		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	// Check if there are more blocks *after* the ones we collected but *before* the ancestor
	if !foundAncestor && len(blocksToSend) == maxBlocksToSend {
		// If we hit the limit and haven't found the ancestor/genesis, there must be more blocks
		// We need to check if the *next* block in the iteration exists and isn't the ancestor
		peekBlock, peekErr := iter.Next()
		if peekErr == nil && peekBlock != nil && !bytes.Equal(peekBlock.Hash, lastKnownHash) {
			moreAvailable = true
		} else if peekErr != nil {
			log.Printf("Error peeking next block for %s: %v", remotePeer, peekErr)
		}
	}

	resp := BlocksResponse{Blocks: blocksToSend, MoreBlocksAvailable: moreAvailable}
	err = encoder.Encode(resp)
	if err != nil {
		log.Printf("Error encoding BlocksResponse to %s: %v", remotePeer, err)
		return // Don't try to flush if encode failed
	}
	err = rw.Flush()
	if err != nil {
		log.Printf("Error flushing BlocksResponse to %s: %v", remotePeer, err)
		return
	}
	log.Printf("Sent %d blocks to %s (MoreAvailable: %v)", len(blocksToSend), remotePeer, moreAvailable)
}

// HandleInventoryStream handles incoming inventory announcements.
// This is now a method on *Node to access node state like Blockchain and RequestBlocks.
func (n *Node) HandleInventoryStream(stream network.Stream) {
	remotePeer := stream.Conn().RemotePeer()
	log.Printf("Got a new inventory stream from %s", remotePeer)
	defer stream.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	decoder := gob.NewDecoder(rw)

	// Read the inventory message (handle different types)
	var baseMsg BaseMessage
	err := decoder.Decode(&baseMsg)
	if err != nil {
		if err != io.EOF {
			log.Printf("Error decoding BaseMsg on inventory stream from %s: %v", remotePeer, err)
		}
		return
	}

	switch baseMsg.Type {
	case MsgTypeInvBlock:
		var inv InvBlock
		err = decoder.Decode(&inv) // Assuming gob decodes remaining fields
		if err != nil {
			log.Printf("Error decoding InvBlock details from %s: %v", remotePeer, err)
			return
		}
		log.Printf("Received InvBlock from %s: Hash=%x Height=%d", remotePeer, inv.Hash, inv.Height)
		n.handleInvBlock(inv, remotePeer)

	case MsgTypeInvTx:
		var inv InvTx
		err = decoder.Decode(&inv)
		if err != nil {
			log.Printf("Error decoding InvTx details from %s: %v", remotePeer, err)
			return
		}
		log.Printf("Received InvTx from %s: TxID=%x", remotePeer, inv.TxID)
		n.handleInvTx(inv, remotePeer)

	default:
		log.Printf("Received unknown inventory type %d from %s", baseMsg.Type, remotePeer)
	}
}

// handleInvBlock processes a received InvBlock message.
// It's called by HandleInventoryStream.
func (n *Node) handleInvBlock(inv InvBlock, remotePeer peer.ID) {
	bc := n.Blockchain
	// --- Check if we need this block ---
	_, err := bc.GetBlock(inv.Hash)
	if err == nil {
		// log.Printf("Already have block %x announced by %s. Ignoring.", inv.Hash, remotePeer)
		return
	} else {
		log.Printf("Don't have block %x announced by %s. Requesting blocks after our tip...", inv.Hash, remotePeer)
	}

	// --- Request the missing block(s) ---
	// This now happens in a loop until caught up or error
	go func() { // Run in goroutine to avoid blocking HandleInventoryStream
		totalBlocksAdded := 0
		for {
			myLastHash, err := bc.GetLastBlockHashBytes()
			if err != nil {
				log.Printf("handleInvBlock: Error getting own last block hash to request block %x: %v", inv.Hash, err)
				return // Stop sync on error
			}

			log.Printf("handleInvBlock: Requesting blocks after %x from %s (triggered by inv %x)", myLastHash, remotePeer, inv.Hash)
			receivedBlocks, moreAvailable, err := n.RequestBlocks(remotePeer, myLastHash)
			if err != nil {
				log.Printf("handleInvBlock: Error requesting blocks (after %x) from peer %s (triggered by inv %x): %v",
					myLastHash, remotePeer, inv.Hash, err)
				return // Stop sync on error
			}

			if len(receivedBlocks) == 0 {
				if !moreAvailable {
					log.Printf("handleInvBlock: Received 0 blocks from %s and no more available.", remotePeer)
				} else {
					log.Printf("handleInvBlock: Received 0 blocks from %s but more are available? Retrying later might be needed.", remotePeer)
				}
				break // Stop sync loop
			}

			log.Printf("handleInvBlock: Processing %d received blocks triggered by inventory announcement...", len(receivedBlocks))
			addedInBatch := 0
			for _, block := range receivedBlocks {
				err := bc.AddBlock(block) // Rely on AddBlock for all logic
				if err != nil {
					log.Printf("handleInvBlock: Failed to add received block %x (Height: %d): %v", block.Hash, block.Height, err)
					moreAvailable = false // Stop sync loop on error adding block
					break
				} else {
					addedInBatch++
				}
			}
			totalBlocksAdded += addedInBatch
			log.Printf("handleInvBlock: Finished processing batch. Added: %d", addedInBatch)

			if !moreAvailable {
				log.Printf("handleInvBlock: No more blocks available from %s.", remotePeer)
				break // Exit sync loop
			}
			// Small delay before next request in loop
			select {
			case <-n.ctx.Done():
				log.Println("handleInvBlock sync cancelled.")
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
		log.Printf("handleInvBlock: Finished sync process triggered by inv %x. Total blocks added: %d", inv.Hash, totalBlocksAdded)
	}()
}

// handleInvTx processes a received InvTx message.
// It's called by HandleInventoryStream.
func (n *Node) handleInvTx(inv InvTx, remotePeer peer.ID) {
	txIDHex := hex.EncodeToString(inv.TxID)
	log.Printf("Received inventory for transaction %s from %s", txIDHex, remotePeer)

	n.MempoolMutex.RLock()
	_, alreadyHave := n.Mempool[txIDHex]
	n.MempoolMutex.RUnlock()

	if !alreadyHave {
		// Check if already in blockchain as well (maybe it was mined recently)
		_, err := n.Blockchain.FindTransaction(inv.TxID)
		if err == nil {
			log.Printf("Tx %s from inventory already found in blockchain. Ignoring.", txIDHex)
			return
		}

		// Request the full transaction by opening a TxSync stream
		log.Printf("Tx %s not found locally. Requesting from peer %s.", txIDHex, remotePeer)
		req := GetTx{TxID: inv.TxID} // Original struct literal, as suggested conversion might not apply

		stream, err := n.Host.NewStream(n.ctx, remotePeer, TxSyncProtocolID)
		if err != nil {
			log.Printf("Failed to open TxSync stream to %s for tx %s: %v", remotePeer, txIDHex, err)
			return
		}
		defer stream.Close() // Ensure stream is closed after request/response or error

		rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
		encoder := gob.NewEncoder(rw)
		// decoder := gob.NewDecoder(rw) // Decoder not needed here, only sending request

		// Send GetTx request
		err = encoder.Encode(req)
		if err != nil {
			log.Printf("Failed to encode GetTx request to %s for tx %s: %v", remotePeer, txIDHex, err)
			return
		}
		err = rw.Flush()
		if err != nil {
			log.Printf("Failed to flush GetTx request to %s for tx %s: %v", remotePeer, txIDHex, err)
			return
		}
		// Response handling happens in HandleTxSyncStream, triggered by the peer
		log.Printf("Sent GetTx request for %s to %s", txIDHex, remotePeer)

	} else {
		log.Printf("Tx %s from inventory already in mempool. Ignoring.", txIDHex)
	}
}

// HandleTxSyncStream handles requests for specific transactions (GetTx).
func (n *Node) HandleTxSyncStream(stream network.Stream) {
	remotePeer := stream.Conn().RemotePeer()
	log.Printf("Got a new transaction sync stream from %s", remotePeer)
	defer stream.Close()

	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	decoder := gob.NewDecoder(rw)
	encoder := gob.NewEncoder(rw) // Need encoder to send response

	var req GetTx
	err := decoder.Decode(&req)
	if err != nil {
		if err != io.EOF {
			log.Printf("Error decoding GetTx request from %s: %v", remotePeer, err)
		}
		return
	}
	txIDHex := hex.EncodeToString(req.TxID)
	log.Printf("Received GetTx request from %s for tx %s", remotePeer, txIDHex)

	var txToSend *core.Transaction

	// Check mempool first
	n.MempoolMutex.RLock()
	txToSend = n.Mempool[txIDHex] // Simplified assignment
	n.MempoolMutex.RUnlock()

	// If not in mempool, check blockchain
	if txToSend == nil {
		txToSend, err = n.Blockchain.FindTransaction(req.TxID)
		if err != nil {
			// Couldn't find it anywhere
			log.Printf("Could not find requested tx %s for peer %s: %v", txIDHex, remotePeer, err)
			// Send empty/nil response? Gob might error on nil pointer.
			// Send empty Tx struct instead.
			txMsg := Tx{Transaction: nil}
			err = encoder.Encode(txMsg)
			if err != nil {
				log.Printf("Error encoding empty Tx response to %s: %v", remotePeer, err) // Added logging
			}
			err = rw.Flush()
			if err != nil {
				log.Printf("Error flushing empty Tx response to %s: %v", remotePeer, err) // Added logging
			}
			return
		}
	}

	// Found the transaction, send it back
	txMsg := Tx{Transaction: txToSend}
	err = encoder.Encode(txMsg)
	if err != nil {
		log.Printf("Failed to encode Tx message to %s for tx %s: %v", remotePeer, txIDHex, err)
		return
	}
	err = rw.Flush()
	if err != nil {
		log.Printf("Failed to flush Tx message to %s for tx %s: %v", remotePeer, txIDHex, err)
		return
	}
	log.Printf("Sent transaction %s to %s", txIDHex, remotePeer)
}

// HandleSubmitTxStream handles new transaction submissions from clients or peers.
func (n *Node) HandleSubmitTxStream(stream network.Stream) {
	remotePeer := stream.Conn().RemotePeer()
	log.Printf("Got a new transaction submission stream from %s", remotePeer)
	defer stream.Close()

	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	decoder := gob.NewDecoder(rw)

	var msg SubmitTx
	err := decoder.Decode(&msg)
	if err != nil {
		if err != io.EOF {
			log.Printf("Error decoding SubmitTx from %s: %v", remotePeer, err)
		}
		return
	}

	// Deserialize the transaction
	tx, err := core.DeserializeTransaction(msg.SerializedTx)
	if err != nil {
		log.Printf("Error deserializing submitted tx from %s: %v", remotePeer, err)
		return
	}
	txIDHex := hex.EncodeToString(tx.ID)
	log.Printf("Received potential new transaction %s from %s", txIDHex, remotePeer)

	// --- Basic Validation ---
	// 1. Check if already in mempool or blockchain
	n.MempoolMutex.RLock()
	_, inMempool := n.Mempool[txIDHex]
	n.MempoolMutex.RUnlock()
	if inMempool {
		log.Printf("Transaction %s already in mempool. Ignoring.", txIDHex)
		return
	}
	_, err = n.Blockchain.FindTransaction(tx.ID)
	if err == nil {
		log.Printf("Transaction %s already in blockchain. Ignoring.", txIDHex)
		return
	}

	// 2. Verify Signature
	if !tx.IsCoinbase() { // Skip coinbase (shouldn't be submitted anyway)
		prevTXs := make(map[string]core.Transaction)
		for _, vin := range tx.Inputs {
			prevTx, findErr := n.Blockchain.FindTransaction(vin.PrevTxID)
			if findErr != nil {
				log.Printf("Validation failed for tx %s: Cannot find previous tx %x", txIDHex, vin.PrevTxID)
				return // Reject transaction
			}
			prevTXs[hex.EncodeToString(vin.PrevTxID)] = *prevTx
		}

		verified, verifyErr := tx.Verify(prevTXs)
		if verifyErr != nil {
			log.Printf("Validation error for tx %s: %v", txIDHex, verifyErr)
			return // Reject transaction
		}
		if !verified {
			log.Printf("Validation failed for tx %s: Invalid signature", txIDHex)
			return // Reject transaction
		}
	}

	// TODO: Add more validation (e.g., double spending checks against blockchain + mempool)

	// --- Add to Mempool ---
	n.MempoolMutex.Lock()
	n.Mempool[txIDHex] = tx
	n.MempoolMutex.Unlock()
	log.Printf("Validated and added transaction %s to mempool.", txIDHex)

	// --- Broadcast Inventory ---
	inv := InvTx{TxID: tx.ID}
	n.BroadcastMessage(InventoryProtocolID, inv)
	log.Printf("Broadcasted inventory for new transaction %s", txIDHex)
}

// ConnectToPeer connects the host to a given peer multiaddress.
// Changed receiver to *Node
func (n *Node) ConnectToPeer(peerAddr string) error {
	log.Printf("Attempting to connect to peer: %s", peerAddr)
	peerMA, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		return fmt.Errorf("failed to parse peer multiaddr '%s': %w", peerAddr, err)
	}
	peerInfo, err := peer.AddrInfoFromP2pAddr(peerMA)
	if err != nil {
		return fmt.Errorf("failed to extract peer info from multiaddr '%s': %w", peerAddr, err)
	}
	connectCtx := n.ctx
	err = n.Host.Connect(connectCtx, *peerInfo)
	if err != nil {
		return fmt.Errorf("failed to connect to peer %s (%s): %w", peerInfo.ID, peerAddr, err)
	}
	log.Printf("Successfully connected to peer: %s", peerInfo.ID)
	return nil
}

// RequestBlocks opens a stream to a peer, sends a GetBlocksRequest, and handles the response.
// It now returns the received blocks and a flag indicating if more blocks are available.
func (n *Node) RequestBlocks(peerID peer.ID, fromHash []byte) ([]*core.Block, bool, error) {
	log.Printf("Opening stream to peer %s for protocol %s", peerID, BlockSyncProtocolID)
	stream, err := n.Host.NewStream(n.ctx, peerID, BlockSyncProtocolID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open new stream to peer %s: %w", peerID, err)
	}
	defer stream.Close()

	// Send the request
	req := GetBlocksRequest{
		FromHash:  fromHash,
		MaxBlocks: MaxBlocksPerSyncResponse, // Use the constant defined earlier
	}
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	encoder := gob.NewEncoder(rw)

	log.Printf("Sending GetBlocksRequest (FromHash: %x, Max: %d) to %s", fromHash, req.MaxBlocks, peerID)
	err = encoder.Encode(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode GetBlocksRequest to peer %s: %w", peerID, err)
	}
	err = rw.Flush()
	if err != nil {
		return nil, false, fmt.Errorf("failed to flush request buffer to peer %s: %w", peerID, err)
	}

	// Read the response
	decoder := gob.NewDecoder(rw)
	var resp BlocksResponse
	err = decoder.Decode(&resp)
	if err != nil {
		if err == io.EOF {
			log.Printf("Peer %s closed stream after request, potentially no blocks to send.", peerID)
			// Return empty list, not an error, and assume no more blocks
			return []*core.Block{}, false, nil
		} else {
			return nil, false, fmt.Errorf("failed to decode BlocksResponse from peer %s: %w", peerID, err)
		}
	}

	log.Printf("Received %d blocks from peer %s (MoreAvailable: %v)", len(resp.Blocks), peerID, resp.MoreBlocksAvailable)
	return resp.Blocks, resp.MoreBlocksAvailable, nil
}

// BroadcastMessage sends a message to all connected peers using the specified protocol ID.
// Changed receiver to *Node
func (n *Node) BroadcastMessage(protocolID protocol.ID, msg interface{}) {
	peers := n.Host.Network().Peers()
	if len(peers) == 0 {
		log.Println("No connected peers to broadcast to.")
		return
	}

	log.Printf("Broadcasting message (type %T) to %d peers using protocol %s...", msg, len(peers), protocolID)

	// Determine message type and prepare BaseMessage
	var baseMsg BaseMessage
	switch msg.(type) {
	case InvBlock:
		baseMsg.Type = MsgTypeInvBlock
	case *InvBlock: // Handle pointer case if necessary
		baseMsg.Type = MsgTypeInvBlock
	case InvTx:
		baseMsg.Type = MsgTypeInvTx
	case *InvTx: // Handle pointer case if necessary
		baseMsg.Type = MsgTypeInvTx
	// TODO: Add cases for other broadcastable message types if any
	default:
		log.Printf("Error: Unknown message type %T for broadcast. Aborting.", msg)
		return
	}

	// Serialize BaseMessage and the actual message
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)

	// Encode BaseMessage first
	err := encoder.Encode(baseMsg)
	if err != nil {
		log.Printf("Error encoding BaseMessage for broadcast: %v. Aborting.", err)
		return
	}

	// Encode the actual message second
	err = encoder.Encode(msg)
	if err != nil {
		log.Printf("Error encoding actual message (%T) for broadcast: %v. Aborting.", msg, err)
		return
	}
	msgBytes := buffer.Bytes()

	// Send to each peer concurrently (optional, but good for many peers)
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()
			stream, err := n.Host.NewStream(n.ctx, peerID, protocolID)
			if err != nil {
				log.Printf("Failed to open stream to peer %s for broadcast: %v", peerID, err)
				return
			}
			defer stream.Close()

			_, err = stream.Write(msgBytes)
			if err != nil {
				log.Printf("Failed to write broadcast message to peer %s: %v", peerID, err)
				return
			}
			// log.Printf("Broadcast message sent to peer %s", peerID)
		}(p)
	}
	wg.Wait()
	log.Printf("Broadcast finished.")
}

// StartMining starts a continuous mining loop in a goroutine.
func (n *Node) StartMining(minerPubKeyHash []byte) {
	log.Println("Starting mining process...")

	go func() {
		for {
			select {
			case <-n.ctx.Done(): // Stop mining on node shutdown
				log.Println("Stopping mining loop due to context cancellation.")
				return
			default:
				// --- Prepare Block ---
				lastBlock, err := n.Blockchain.GetLastBlock()
				if err != nil {
					log.Printf("Miner: Error getting last block: %v. Retrying shortly...", err)
					time.Sleep(5 * time.Second)
					continue
				}

				// Calculate the target for the new block
				nextTargetBytes, err := n.Blockchain.CalculateNextDifficulty(lastBlock)
				if err != nil {
					log.Printf("Miner: Error calculating next target: %v. Using previous block's target.", err)
					nextTargetBytes = lastBlock.Target // Fallback to previous target
				}

				newHeight := lastBlock.Height + 1
				reward := core.GetCurrentBlockReward(newHeight)
				coinbaseTx := core.NewCoinbaseTX(minerPubKeyHash, newHeight, reward)

				// Collect transactions from mempool
				n.MempoolMutex.RLock()
				mempoolTxs := make([]*core.Transaction, 0, len(n.Mempool))
				for _, tx := range n.Mempool {
					// TODO: Add more validation here (e.g., double spend check against current chain state + other mempool txs)
					mempoolTxs = append(mempoolTxs, tx)
				}
				n.MempoolMutex.RUnlock()
				// TODO: Sort transactions? Limit block size?

				blockTxs := []*core.Transaction{coinbaseTx}
				blockTxs = append(blockTxs, mempoolTxs...)

				// Construct block candidate
				blockCandidate := &core.Block{
					Timestamp:     time.Now().Unix(),
					PrevBlockHash: lastBlock.Hash,
					Transactions:  blockTxs,
					Height:        newHeight,
					Target:        nextTargetBytes, // Set the calculated target
					// Nonce and Hash will be found by PoW
				}

				// --- Run Proof of Work ---
				pow := core.NewProofOfWork(blockCandidate)
				nonce, hash, err := pow.Run() // This is blocking
				if err != nil {
					log.Printf("Miner: PoW run failed: %v. Restarting mining cycle.", err)
					continue // Try again
				}

				// --- Found Block ---
				blockCandidate.Nonce = nonce
				blockCandidate.Hash = hash
				log.Printf("Miner: Successfully mined block %d! Hash: %x", newHeight, hash)

				// --- Add Block to Local Chain (will trigger broadcast) ---
				err = n.Blockchain.AddBlock(blockCandidate)
				if err != nil {
					// This might happen if another node mined a block slightly faster (race condition)
					log.Printf("Miner: Failed to add mined block %x to chain: %v. Restarting mining cycle.", hash, err)
					// No need to clear mempool txs if block wasn't added
				} else {
					// --- Clear Mempool of Mined Transactions ---
					n.MempoolMutex.Lock()
					for _, tx := range mempoolTxs { // Only remove txs included in *this* block
						delete(n.Mempool, hex.EncodeToString(tx.ID))
					}
					n.MempoolMutex.Unlock()
					log.Printf("Miner: Cleared %d transactions from mempool.", len(mempoolTxs))
				}
				// Small pause or check for new work immediately?
				// time.Sleep(1 * time.Second) // Optional brief pause
			}
		}
	}()
}

// HandlePeerExchangeStream handles incoming peer lists.
func (n *Node) HandlePeerExchangeStream(stream network.Stream) {
	remotePeer := stream.Conn().RemotePeer()
	log.Printf("Got a new peer exchange stream from %s", remotePeer)
	defer stream.Close()

	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	decoder := gob.NewDecoder(rw)

	var msg PeerListMessage
	err := decoder.Decode(&msg)
	if err != nil {
		if err != io.EOF {
			log.Printf("Error decoding PeerListMessage from %s: %v", remotePeer, err)
		}
		return
	}

	log.Printf("Received peer list from %s containing %d addresses.", remotePeer, len(msg.PeerAddrs))

	for _, addrBytes := range msg.PeerAddrs {
		addr, err := multiaddr.NewMultiaddrBytes(addrBytes)
		if err != nil {
			log.Printf("PEX: Error parsing multiaddr from %s: %v", remotePeer, err)
			continue
		}

		peerinfo, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			log.Printf("PEX: Error getting AddrInfo from multiaddr %s (from %s): %v", addr, remotePeer, err)
			continue
		}

		// Don't connect to self
		if peerinfo.ID == n.Host.ID() {
			continue
		}

		// Check if already connected or connecting
		if n.Host.Network().Connectedness(peerinfo.ID) != network.NotConnected {
			// log.Printf("PEX: Already connected/connecting to peer %s (from %s)", peerinfo.ID, remotePeer)
			continue
		}

		// Attempt to connect to the new peer (in background)
		go func(pi peer.AddrInfo) {
			log.Printf("PEX: Attempting connection to new peer %s discovered via %s", pi.ID, remotePeer)
			ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
			defer cancel()
			err := n.Host.Connect(ctx, pi)
			if err != nil {
				// Don't log excessively if connection fails, might be unreachable
				// log.Printf("PEX: Connection to %s failed: %v", pi.ID, err)
			} else {
				log.Printf("PEX: Successfully connected to peer %s discovered via %s", pi.ID, remotePeer)
			}
		}(*peerinfo) // Pass a copy
	}
}

// ExchangePeersPeriodically periodically sends the current list of connected peers to all peers.
func (n *Node) ExchangePeersPeriodically() {
	pexTicker := time.NewTicker(30 * time.Second) // Exchange peers every 30 seconds
	defer pexTicker.Stop()

	log.Println("Starting periodic peer exchange process...")

	for {
		select {
		case <-n.ctx.Done():
			log.Println("Peer exchange process shutting down.")
			return
		case <-pexTicker.C:
			connectedPeers := n.Host.Network().Peers()
			if len(connectedPeers) == 0 {
				continue // No peers to exchange with
			}

			var peerAddrBytes [][]byte
			for _, p := range connectedPeers {
				// Get the addresses associated with the peer
				// Note: This includes addresses the host *thinks* the peer has.
				// It's better than sending our own listen addresses.
				addrs := n.Host.Peerstore().Addrs(p)
				if len(addrs) == 0 {
					continue
				}
				// Create the full /p2p/<peerID> address
				p2pAddr, err := multiaddr.NewMultiaddr("/p2p/" + p.String())
				if err != nil {
					log.Printf("PEX: Error creating p2p component for peer %s: %v", p, err)
					continue
				}
				fullAddr := addrs[0].Encapsulate(p2pAddr)
				addrBytes := fullAddr.Bytes() // Get the raw bytes of the *full* p2p multiaddress
				peerAddrBytes = append(peerAddrBytes, addrBytes)
			}

			if len(peerAddrBytes) == 0 {
				continue // No valid addresses found
			}

			msg := PeerListMessage{PeerAddrs: peerAddrBytes}

			// Serialize the message once
			var buffer bytes.Buffer
			encoder := gob.NewEncoder(&buffer)
			err := encoder.Encode(msg)
			if err != nil {
				log.Printf("PEX: Error encoding PeerListMessage: %v", err)
				continue
			}
			msgBytes := buffer.Bytes()

			log.Printf("PEX: Sending peer list (%d addresses) to %d peers...", len(peerAddrBytes), len(connectedPeers))
			// Send to each peer concurrently
			var wg sync.WaitGroup
			for _, p := range connectedPeers {
				wg.Add(1)
				go func(peerID peer.ID) {
					defer wg.Done()
					stream, err := n.Host.NewStream(n.ctx, peerID, PeerExchangeProtocolID)
					if err != nil {
						// log.Printf("PEX: Failed to open stream to peer %s: %v", peerID, err)
						return
					}
					defer stream.Close()

					_, err = stream.Write(msgBytes)
					if err != nil {
						// log.Printf("PEX: Failed to write peer list to peer %s: %v", peerID, err)
						return
					}
				}(p)
			}
			wg.Wait()
		}
	}
}

// TODO:
// - Add Start() method to Node struct
// - Add Mempool to Node struct
// - Add mining logic to Node struct
// - Refactor broadcast to originate from Node
