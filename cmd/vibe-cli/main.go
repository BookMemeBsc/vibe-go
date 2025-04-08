package main

import (
	"bufio"
	"context"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"vibe-ai/internal/core"
	"vibe-ai/internal/network"
	"vibe-ai/internal/wallet"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	// --- Command Line Flags ---
	createWalletCmd := flag.NewFlagSet("createwallet", flag.ExitOnError)
	getBalanceCmd := flag.NewFlagSet("getbalance", flag.ExitOnError)
	sendCmd := flag.NewFlagSet("send", flag.ExitOnError)
	printChainCmd := flag.NewFlagSet("printchain", flag.ExitOnError)

	getBalanceAddress := getBalanceCmd.String("address", "", "Address to get balance for")
	sendFrom := sendCmd.String("from", "", "Source wallet address (Base58Check)")
	sendTo := sendCmd.String("to", "", "Destination wallet address (Base58Check)")
	sendAmount := sendCmd.Int64("amount", 0, "Amount to send (in smallest VIBE unit)")
	sendNodeAddr := sendCmd.String("node", "", "Multiaddress of a VIBE node to submit the transaction to")

	// --- Basic Validation ---
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// --- Command Parsing & Execution ---
	// Declare variables here, initialize only when needed
	var bc *core.Blockchain
	var wallets *wallet.Wallets
	var err error

	switch os.Args[1] {
	case "createwallet":
		err = createWalletCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
		if createWalletCmd.Parsed() {
			// Load/Create wallets just for this command
			wallets, err = wallet.NewWallets()
			if err != nil {
				log.Fatalf("Failed to load wallets: %v", err)
			}
			address := wallets.CreateWallet()
			err = wallets.SaveToFile()
			if err != nil {
				log.Fatalf("Failed to save wallets after creation: %v", err)
			}
			fmt.Printf("Created new wallet. Address: %s\n", address)
		}
	case "getbalance":
		err = getBalanceCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
		if getBalanceCmd.Parsed() {
			if *getBalanceAddress == "" {
				getBalanceCmd.Usage()
				os.Exit(1)
			}
			// Initialize blockchain for this command
			if err := ensureDataDir(); err != nil {
				log.Fatalf("Failed to ensure data directory: %v", err)
			}
			bc, err = core.NewBlockchain(nil)
			if err != nil {
				log.Fatalf("Failed to initialize blockchain: %v", err)
			}
			defer bc.Close()

			// Decode the Base58Check address to get the public key hash
			pubKeyHash, err := wallet.Base58Decode(*getBalanceAddress)
			if err != nil {
				log.Fatalf("Invalid address format: %v", err)
			}

			balance := bc.GetBalance(pubKeyHash)
			fmt.Printf("Balance for '%s': %d (smallest unit)\n", *getBalanceAddress, balance)
			// Optional: Convert balance to VIBE units
			// fmt.Printf("Balance for '%s': %.8f VIBE\n", *getBalanceAddress, float64(balance)/float64(core.VibeSmallestUnit))
		}
	case "send":
		err := sendCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
		if sendCmd.Parsed() {
			if *sendFrom == "" || *sendTo == "" || *sendAmount <= 0 || *sendNodeAddr == "" {
				sendCmd.Usage()
				os.Exit(1)
			}
			// Initialize blockchain and wallets for this command
			if err := ensureDataDir(); err != nil {
				log.Fatalf("Failed to ensure data directory: %v", err)
			}
			bc, err = core.NewBlockchain(nil)
			if err != nil {
				log.Fatalf("Failed to initialize blockchain: %v", err)
			}
			defer bc.Close()
			wallets, err = wallet.NewWallets()
			if err != nil {
				log.Fatalf("Failed to load wallets: %v", err)
			}

			fromAddr := *sendFrom
			toAddr := *sendTo
			amount := *sendAmount
			nodeAddr := *sendNodeAddr

			// Decode recipient address (Base58Check)
			toPubKeyHash, err := wallet.Base58Decode(toAddr)
			if err != nil {
				log.Fatalf("Invalid recipient address format: %v", err)
			}

			// Find sender wallet using Base58Check address
			senderWallet := wallets.GetWallet(fromAddr)
			if senderWallet == nil {
				log.Fatalf("Sender wallet %s not found.", fromAddr)
			}

			// Create the transaction (uses local blockchain state for UTXOs)
			tx, err := core.NewTransaction(senderWallet, toPubKeyHash, amount, bc)
			if err != nil {
				log.Fatalf("Failed to create transaction: %v", err)
			}

			// Serialize the transaction for submission
			serializedTx, err := tx.SerializeForSubmission()
			if err != nil {
				log.Fatalf("Failed to serialize transaction: %v", err)
			}

			// --- Connect to Node and Submit ---
			// Create a temporary libp2p host for the CLI to send the message
			// This is inefficient but avoids needing the CLI to be a full long-running node.
			ctx := context.Background()
			cliHost, err := libp2p.New(libp2p.NoListenAddrs) // No need to listen
			if err != nil {
				log.Fatalf("Failed to create temp host: %v", err)
			}
			defer cliHost.Close()

			log.Printf("Connecting to node %s to submit transaction...", nodeAddr)
			nodeMA, err := multiaddr.NewMultiaddr(nodeAddr)
			if err != nil {
				log.Fatalf("Invalid node multiaddress %s: %v", nodeAddr, err)
			}
			nodeInfo, err := peer.AddrInfoFromP2pAddr(nodeMA)
			if err != nil {
				log.Fatalf("Invalid node peer info %s: %v", nodeAddr, err)
			}

			err = cliHost.Connect(ctx, *nodeInfo)
			if err != nil {
				log.Fatalf("Failed to connect to node %s: %v", nodeAddr, err)
			}

			log.Printf("Opening stream to node %s for protocol %s", nodeInfo.ID, network.SubmitTxProtocolID)
			stream, err := cliHost.NewStream(ctx, nodeInfo.ID, network.SubmitTxProtocolID)
			if err != nil {
				log.Fatalf("Failed to open stream to node: %v", err)
			}
			defer stream.Close()

			rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
			encoder := gob.NewEncoder(rw)

			msg := network.SubmitTx{SerializedTx: serializedTx}
			err = encoder.Encode(msg)
			if err != nil {
				log.Fatalf("Failed to encode SubmitTx message: %v", err)
			}
			err = rw.Flush()
			if err != nil {
				log.Fatalf("Failed to flush SubmitTx message: %v", err)
			}

			log.Printf("Transaction %x submitted successfully to node %s.", tx.ID, nodeAddr)
			fmt.Printf("Transaction %x submitted to node %s.\nIt should appear in the mempool and be broadcast soon.\n", tx.ID, nodeAddr)

			/* --- Removed Mempool File Logic ---
			mempoolFile := "./data/mempool.dat"
			// ... read ...
			transactions = append(transactions, tx)
			// ... write ...
			fmt.Printf("Transaction created successfully (ID: %x) and added to mempool.\n", tx.ID)
			fmt.Println("Run 'vibe-cli mine -address YOUR_MINER_ADDRESS' to include it in a block.")
			*/
		}
	case "printchain":
		err := printChainCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
		if printChainCmd.Parsed() {
			// Initialize blockchain for this command
			if err := ensureDataDir(); err != nil {
				log.Fatalf("Failed to ensure data directory: %v", err)
			}
			bc, err = core.NewBlockchain(nil)
			if err != nil {
				log.Fatalf("Failed to initialize blockchain: %v", err)
			}
			defer bc.Close()

			iter := bc.NewIterator()
			fmt.Println("--- Blockchain Blocks (Newest First) ---")
			for {
				block, err := iter.Next()
				if err != nil {
					log.Printf("Error iterating blockchain: %v", err)
					break
				}

				fmt.Printf("-------------------- Block %d --------------------\n", block.Height)
				fmt.Printf("  Hash:          %x\n", block.Hash)
				fmt.Printf("  Prev. Hash:    %x\n", block.PrevBlockHash)
				fmt.Printf("  Timestamp:     %s\n", time.Unix(block.Timestamp, 0).Format(time.RFC1123))
				fmt.Printf("  Transactions:  %d\n", len(block.Transactions))
				// Optional: Print transaction details
				// for _, tx := range block.Transactions {
				// 	 fmt.Printf("    - Tx %x\n", tx.ID)
				// }
				fmt.Println("--------------------------------------------------")

				// Break after printing genesis block
				if len(block.PrevBlockHash) == 0 {
					break
				}
			}
			fmt.Println("--- End of Blockchain --- ")
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

// ensureDataDir checks if the ./data directory exists and creates it if not.
func ensureDataDir() error {
	if _, err := os.Stat("./data"); os.IsNotExist(err) {
		log.Println("Data directory not found, creating './data'")
		return os.Mkdir("./data", 0755)
	}
	return nil // Return nil if directory already exists or Stat was successful
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  vibe-cli createwallet - Create a new wallet")
	fmt.Println("  vibe-cli getbalance -address ADDRESS - Get balance for ADDRESS (Base58Check)")
	fmt.Println("  vibe-cli send -from FROM -to TO -amount AMOUNT -node NODE_ADDR - Submit transaction to a node (Addresses are Base58Check)")
	fmt.Println("  vibe-cli printchain - Print all the blocks of the blockchain")
}
