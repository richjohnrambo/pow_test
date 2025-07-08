package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

/*
*
实践非对称加密 RSA（编程语言不限）：
先生成一个公私钥对
用私钥对符合 POW 4 个 0 开头的哈希值的 “昵称 + nonce” 进行私钥签名
用公钥验证
*/
func main() {

	originalData := "rambo6540713639054262903"
	// 1. Generate RSA Key Pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048 bits is a common secure size
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	fmt.Println("RSA Key Pair Generated.")

	// Convert keys to PEM format for storage/transmission (optional, but good practice)
	privateKeyPEM := exportPrivateKeyAsPEM(privateKey)
	publicKeyPEM := exportPublicKeyAsPEM(publicKey)

	fmt.Printf("\nPrivate Key (PEM):\n%s", string(privateKeyPEM))
	fmt.Printf("\nPublic Key (PEM):\n%s", string(publicKeyPEM))

	fmt.Printf("privateKey: %s\n", privateKey)
	fmt.Printf("publicKey: %s\n", publicKey)

	hashed := sha256.Sum256([]byte(originalData)) // Sum256 returns a [32]byte, convert to slice if needed
	messageHash := hashed[:]

	// 4. Sign with Private Key
	// We'll use PSS (Probabilistic Signature Scheme) for better security than PKCS1v15
	// PSS is recommended for new applications.
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, messageHash, nil)
	if err != nil {
		log.Fatalf("Error signing message: %v", err)
	}
	// 5. Verify with Public Key
	// The verifier would have the original message, the signature, and the public key.
	// They would re-hash the message to get 'rehashedMessageHash'.
	rehashed := sha256.Sum256([]byte(originalData))
	rehashedMessageHash := rehashed[:]

	// VerifyPSS requires the public key, the hashing algorithm used, the message hash,
	// and the signature.
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, rehashedMessageHash, signature, nil)
	if err != nil {
		fmt.Printf("Signature verification failed: %v\n", err)
	} else {
		fmt.Println("Signature successfully verified!")
	}
}

// exportPrivateKeyAsPEM converts an RSA private key to PEM format.
func exportPrivateKeyAsPEM(privateKey *rsa.PrivateKey) []byte {
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		},
	)
	return privPEM
}

// exportPublicKeyAsPEM converts an RSA public key to PEM format.
func exportPublicKeyAsPEM(publicKey *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Error marshalling public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubASN1,
		},
	)
	return pubPEM
}

// You would typically have functions to load keys from PEM files as well.
// For example:
/*
func loadPrivateKeyFromPEM(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPublicKeyFromPEM(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA type")
	}
	return rsaPub, nil
}
*/
