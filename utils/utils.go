package utils

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"log"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	mrtronBase58 "github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip32"
	"golang.org/x/crypto/ripemd160"
)

// AddressConversion converts the child key to an address for different networks.
func AddressConversion(childKey *bip32.Key, network string) string {
	switch network {
	case "EVM":
		return generateEVMAddress(childKey)
	case "BTC":
		return generateBTCAddress(childKey)
	case "TRX":
		return generateTRXAddress(childKey)
	case "ERC":
		return generateERCAddress(childKey)
	default:
		log.Printf("Unsupported network: %s", network)
		return ""
	}
}

// generateEVMAddress generates an Ethereum address from the child key.
func generateEVMAddress(childKey *bip32.Key) string {
	ecdaPrivateKey := crypto.ToECDSAUnsafe(childKey.Key)
	ecdaPublicKey := ecdaPrivateKey.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*ecdaPublicKey)
	return address.Hex()
}

// generateBTCAddress generates a Bitcoin address from the child key.
func generateBTCAddress(childKey *bip32.Key) string {
	pubKeyBytes := childKey.PublicKey().Key
	pubKeyHash := hash160(pubKeyBytes)

	// Prepend the network prefix (0x00 for mainnet)
	versionedPayload := append([]byte{0x00}, pubKeyHash...)

	// Compute the checksum and Base58 encode
	fullPayload := append(versionedPayload, computeChecksum(versionedPayload)...)
	return base58.Encode(fullPayload)
}

// generateERCAddress generates a Europecoin address from the child key.
func generateERCAddress(childKey *bip32.Key) string {
	pubKeyHash := hash160(childKey.PublicKey().Key)

	// Add Europecoin version byte (0x21 for mainnet)
	versionedPayload := append([]byte{0x21}, pubKeyHash...)

	// Compute checksum and Base58 encode
	fullPayload := append(versionedPayload, computeChecksum(versionedPayload)...)
	return base58.Encode(fullPayload)
}

// generateTRXAddress generates a Tron address from the child key.
func generateTRXAddress(childKey *bip32.Key) string {
	pubKeyBytes := childKey.PublicKey().Key

	// Step 1: SHA256 hash of the public key
	sha256Hash := sha256.Sum256(pubKeyBytes)

	// Step 2: RIPEMD160 hash of the SHA256 result
	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash[:])
	pubKeyHash := ripemd160Hasher.Sum(nil)

	// Step 3: Prepend the Tron network prefix (0x41)
	trxPayload := append([]byte{0x41}, pubKeyHash...)

	// Step 4: Compute the checksum and append it
	fullPayload := append(trxPayload, computeChecksum(trxPayload)...)

	// Step 5: Base58 encode the payload
	return mrtronBase58.Encode(fullPayload)
}

// computeChecksum computes a double SHA-256 checksum for the provided data.
func computeChecksum(data []byte) []byte {
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:4]
}

// hash160 computes the RIPEMD-160 hash of the SHA-256 hash of the input.
func hash160(data []byte) []byte {
	sha256Hasher := sha256.New()
	sha256Hasher.Write(data)
	sha256Hash := sha256Hasher.Sum(nil)

	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash)
	return ripemd160Hasher.Sum(nil)
}

// GetCoinType returns the coin type according to BIP44 for various networks.
func GetCoinType(network string) uint32 {
	switch network {
	case "EVM":
		return 60
	case "BTC":
		return 0
	case "ERC":
		return 151
	case "TRX":
		return 195
	default:
		return 60
	}
}
