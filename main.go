package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"multiNetworkWalletGenerator/utils"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	// Command-line arguments
	mnemonic := flag.String("mnemonic", "", "Mnemonic to be passed as --mnemonic=''")
	network := flag.String("network", "", "Network to be passed as --network=''")
	walletCount := flag.Int("count", 1, "Number of wallets to generate")
	outputFile := flag.String("output", "wallets.json", "Output file to save the wallets data")
	flag.Parse()

	// Generate the seed from the mnemonic
	seed, err := generateSeed(*mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	// Generate the master key from the seed
	masterKey, err := generateMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	// Generate the extended key for the specified network
	coinType := utils.GetCoinType(*network)
	extendedKey, err := deriveExtendedKey(masterKey, 44, coinType, 0, 0)
	if err != nil {
		log.Fatal(err)
	}

	// Generate wallets
	wallets, err := generateWallets(extendedKey, *walletCount, *network)
	if err != nil {
		log.Fatal(err)
	}

	// Save wallets to a file
	err = saveWalletsToFile(wallets, *outputFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Wallets saved to %s\n", *outputFile)
}

// generateSeed creates a seed from the mnemonic with error checking.
func generateSeed(mnemonic string) ([]byte, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return nil, fmt.Errorf("error generating seed: %v", err)
	}
	return seed, nil
}

// generateMasterKey creates a BIP32 master key from the seed.
func generateMasterKey(seed []byte) (*bip32.Key, error) {
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("error deriving master key: %v", err)
	}
	return masterKey, nil
}

// deriveExtendedKey derives an extended key from the master key based on the BIP44 path.
func deriveExtendedKey(masterKey *bip32.Key, purpose, coinType, account, change uint32) (*bip32.Key, error) {
	path := []uint32{
		bip32.FirstHardenedChild + purpose,  // Purpose: BIP-44
		bip32.FirstHardenedChild + coinType, // Coin type: Bitcoin/Ethereum/Tron, etc.
		bip32.FirstHardenedChild + account,  // Account: 0
		change,                              // Change: 0 (external addresses)
	}
	extendedKey := masterKey
	for _, index := range path {
		extendedKey = deriveChildKey(extendedKey, index)
	}
	return extendedKey, nil
}

// generateWallets generates a list of wallets based on the extended key.
func generateWallets(extendedKey *bip32.Key, walletCount int, network string) ([]utils.Wallet, error) {
	var wallets []utils.Wallet

	for i := 0; i < walletCount; i++ {
		childKey := deriveChildKey(extendedKey, uint32(i))

		// Convert to address
		address := utils.AddressConversion(childKey, network)

		wallets = append(wallets, utils.Wallet{
			PrivateKey: fmt.Sprintf("%x", childKey.Key),
			PublicKey:  fmt.Sprintf("%x", childKey.PublicKey().Key),
			Address:    address,
		})
	}

	return wallets, nil
}

// deriveChildKey derives a child key for a given index.
func deriveChildKey(extendedKey *bip32.Key, index uint32) *bip32.Key {
	childKey, err := extendedKey.NewChildKey(index)
	if err != nil {
		log.Fatalf("error deriving child key: %v", err)
	}
	return childKey
}

// saveWalletsToFile saves the wallet data to the specified output file.
func saveWalletsToFile(wallets []utils.Wallet, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	// Marshal the wallet data to JSON
	jsonData, err := json.MarshalIndent(wallets, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling data to JSON: %v", err)
	}

	// Write the JSON data to the file
	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	return nil
}
