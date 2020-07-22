// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

//overall need to clean this up and keep only the necessary code as most of it was taken.

package certs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/AdvancedThreatAnalytics/DeimosC2/lib/logging"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case rsa.PrivateKey:
		return &k.PublicKey
	case ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		logging.Logger.Println("default returning nil")
		return nil
	}
}

//GenerateLocalCert is used to generate a local cert for HTTPS
func GenerateLocalCert(host string, validFrom string, validFor time.Duration, isCA bool, rsaBits int, ecdsaCurve string, ed25519Key bool, certPath string, keyPath string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey

	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			logging.ErrorLogger.Println("Failed to parse creation date: ", err.Error())
		}
	}

	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logging.ErrorLogger.Println("Failed to generate serial number: ", err.Error())
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		logging.ErrorLogger.Println("Failed to create certificate: ", err.Error())
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		logging.ErrorLogger.Println("Failed to open cert.pem for writing: ", err.Error())
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		logging.ErrorLogger.Println("Failed to write data to cert.pem: ", err.Error())
	}
	if err := certOut.Close(); err != nil {
		logging.ErrorLogger.Println("Error closing cert.pem: ", err.Error())
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logging.ErrorLogger.Println("Failed to open key.pem for writing: ", err.Error())
		return
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logging.ErrorLogger.Println("Unable to marshal private key: ", err.Error())
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		logging.ErrorLogger.Println("Failed to write data to key.pem: ", err.Error())
	}
	if err := keyOut.Close(); err != nil {
		logging.ErrorLogger.Println("Error closing key.pem: ", err.Error())
	}
}
