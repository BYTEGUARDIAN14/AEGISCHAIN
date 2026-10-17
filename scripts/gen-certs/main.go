package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	certFile := "deploy/certs/tls.crt"
	keyFile := "deploy/certs/tls.key"

	_ = os.MkdirAll(filepath.Dir(certFile), 0755)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"AegisChain Security"},
			CommonName:   "aegischain-admission-webhook.aegischain-system.svc",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames: []string{
			"aegischain-admission-webhook",
			"aegischain-admission-webhook.aegischain-system",
			"aegischain-admission-webhook.aegischain-system.svc",
			"aegischain-admission-webhook.aegischain-system.svc.cluster.local",
			"localhost",
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		panic(err)
	}

	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		panic(err)
	}

	fmt.Println("Successfully generated webhook TLS certificates in deploy/certs/")
}
