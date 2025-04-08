package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"log"
	"math/big"
	"os"
	// "golang.org/x/crypto/ripemd160" // Removed deprecated import
)

const walletFile = "./data/wallets.dat"

// Wallet stores private key bytes and public key bytes
type Wallet struct {
	PrivateKeyBytes []byte // Store private key as bytes
	PublicKey       []byte
}

// NewWallet creates and returns a new Wallet
func NewWallet() *Wallet {
	privateBytes, public := newKeyPair()
	wallet := Wallet{privateBytes, public}

	return &wallet
}

// GetAddress returns wallet address as a Base58Check encoded string.
func (w Wallet) GetAddress() string {
	pubKeyHash := HashPubKey(w.PublicKey)
	// Encode the hash using Base58Check
	address := Base58Encode(pubKeyHash)
	return address
}

// HashPubKey hashes public key using SHA256.
// Previously used SHA256 followed by RIPEMD160, now uses only SHA256.
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	// // Removed RIPEMD160 hashing step
	// RIPEMD160Hasher := ripemd160.New()
	// _, err := RIPEMD160Hasher.Write(publicSHA256[:])
	// if err != nil {
	// 	log.Panic(err)
	// }
	// publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	// return publicRIPEMD160

	return publicSHA256[:] // Return the SHA256 hash directly
}

// GetPrivateKey reconstructs the ecdsa.PrivateKey from the stored bytes.
func (w Wallet) GetPrivateKey() *ecdsa.PrivateKey {
	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int).SetBytes(w.PrivateKeyBytes)
	privKey.PublicKey.Curve = elliptic.P256() // Assuming P256 was used for generation
	// Calculate X, Y from D (private scalar)
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())
	return privKey
}

// newKeyPair generates a new ECDSA private/public key pair
// Returns the private key as bytes and the public key as bytes
func newKeyPair() ([]byte, []byte) {
	curve := elliptic.P256() // Use P-256 curve, common choice
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}

	// Concatenate X and Y coordinates for the public key
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	// Return private key bytes (D scalar) and public key bytes
	return private.D.Bytes(), pubKey
}

// Wallets stores a collection of wallets
type Wallets struct {
	Wallets map[string]*Wallet // Map of address -> Wallet
}

// NewWallets creates Wallets and fills it from a file if it exists
func NewWallets() (*Wallets, error) {
	wallets := Wallets{}
	wallets.Wallets = make(map[string]*Wallet)

	err := wallets.LoadFromFile()
	// Ignore file not found error, as it means we just create a new wallets file
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return &wallets, nil
}

// CreateWallet adds a Wallet to Wallets
func (ws *Wallets) CreateWallet() string {
	wallet := NewWallet()
	address := wallet.GetAddress()
	ws.Wallets[address] = wallet

	log.Printf("Created new wallet with address: %s\n", address)
	return address
}

// GetWallet returns a Wallet by its address (Base58Check encoded string)
func (ws Wallets) GetWallet(address string) *Wallet {
	return ws.Wallets[address] // Returns nil if not found
}

// GetAddresses returns an array of addresses (Base58Check encoded strings) stored in the wallet file
func (ws *Wallets) GetAddresses() []string {
	var addresses []string
	for address := range ws.Wallets {
		addresses = append(addresses, address)
	}
	return addresses
}

// LoadFromFile loads wallets from the walletFile
func (ws *Wallets) LoadFromFile() error {
	if _, err := os.Stat(walletFile); os.IsNotExist(err) {
		return err // Return not exist error specifically
	}

	fileContent, err := os.ReadFile(walletFile)
	if err != nil {
		log.Printf("Error reading wallet file %s: %v", walletFile, err)
		return err
	}

	var wallets Wallets
	// gob.Register(elliptic.P256()) // No longer needed
	decoder := gob.NewDecoder(bytes.NewReader(fileContent))
	err = decoder.Decode(&wallets)
	if err != nil {
		log.Printf("Error decoding wallet file content: %v", err)
		return err
	}

	ws.Wallets = wallets.Wallets
	return nil
}

// SaveToFile saves wallets to a file
func (ws Wallets) SaveToFile() error {
	var content bytes.Buffer

	// gob.Register(elliptic.P256()) // No longer needed

	encoder := gob.NewEncoder(&content)
	err := encoder.Encode(ws)
	if err != nil {
		log.Printf("Error encoding wallets: %v", err)
		return err
	}

	err = os.WriteFile(walletFile, content.Bytes(), 0644)
	if err != nil {
		log.Printf("Error writing wallet file %s: %v", walletFile, err)
		return err
	}

	return nil
}

// TODO:
// - Implement saving/loading wallets from file
// - Implement Base58Check encoding/decoding for addresses
