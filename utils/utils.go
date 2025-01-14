package utils

import (
	"crypto/ecdsa"
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"golang.org/x/crypto/ripemd160"
)

// AddressConversion converts the child key to an address for different networks.
func AddressConversion(childKey *bip32.Key, network string) string {
	var address string

	switch network {
	case "EVM":
		address = generateEVMAddress(childKey)
	case "BTC":
		address = generateBTCAddress(childKey)
	case "TRX":
		// TODO
		address = generateTRXAddress(childKey)
	case "ERC":
		// TODO
		address = ""
	default:
		address = ""
	}

	return address
}

// generateEVMAddress generates an Ethereum address from the child key.
func generateEVMAddress(childKey *bip32.Key) string {
	ecdaPrivateKey := crypto.ToECDSAUnsafe(childKey.Key)
	ecdaPublicKey := ecdaPrivateKey.Public().(*ecdsa.PublicKey)
	newAddress := crypto.PubkeyToAddress(*ecdaPublicKey)
	return "0x" + newAddress.Hex()
}

// generateBTCAddress generates a Bitcoin address from the child key.
func generateBTCAddress(childKey *bip32.Key) string {
	pubKeyBytes := childKey.PublicKey().Key
	pubKeyHash := Hash160(pubKeyBytes)

	// Prepend the network prefix (0x00 for mainnet)
	versionedPayload := append([]byte{0x00}, pubKeyHash...)
	// Compute the checksum (double SHA-256)
	checksum := computeChecksum(versionedPayload)

	// Base58 encode the result
	fullPayload := append(versionedPayload, checksum...)
	return base58.Encode(fullPayload)
}

// generateTRXAddress generates a Tron address from the child key.
func generateTRXAddress(childKey *bip32.Key) string {
	privateKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), childKey.Key)

	// Use the uncompressed public key for Tron
	publicKey := privateKey.PubKey().SerializeUncompressed()
	pubKeyHash := Hash160(publicKey)

	// Prepend Tron mainnet prefix (0x41)
	tronNetworkByte := byte(0x41)
	addressBytes := append([]byte{tronNetworkByte}, pubKeyHash...)
	// Compute checksum (double SHA-256)
	checksum := computeChecksum(addressBytes)

	// Base58 encode the result
	fullPayload := append(addressBytes, checksum...)
	return base58.Encode(fullPayload)
}

// computeChecksum computes a double SHA-256 checksum for the provided data.
func computeChecksum(data []byte) []byte {
	sha256Hasher := sha256.New()
	sha256Hasher.Write(data)
	checksum1 := sha256Hasher.Sum(nil)

	sha256Hasher.Reset()
	sha256Hasher.Write(checksum1)
	return sha256Hasher.Sum(nil)[:4]
}

// Hash160 computes the RIPEMD-160 hash of the SHA-256 hash of the input.
func Hash160(data []byte) []byte {
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
