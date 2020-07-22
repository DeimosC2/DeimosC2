package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"

	"github.com/DeimosC2/DeimosC2/lib/logging"
)

//GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return privkey, &privkey.PublicKey
}

//PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(p *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(p),
		},
	)
	return privBytes
}

//PublicKeyToBytes public key to bytes
func PublicKeyToBytes(p *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubBytes
}

//BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return key
}

//BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			logging.ErrorLogger.Println(err.Error())
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		logging.ErrorLogger.Println(err.Error())
	}
	return key
}

//EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return ciphertext
}

//DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		logging.ErrorLogger.Println(err.Error())
	}
	return plaintext
}
