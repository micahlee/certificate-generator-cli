package lib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"
)

func GenerateCertificates(config Configuration) error {

	for _, certConfig := range config.Certificates {
		if err := issueCertificate(certConfig, nil, nil); err != nil {
			return nil
		}
	}

	return nil
}

func issueCertificate(config Certificate, caCert *x509.Certificate, caKey interface{}) error {
	fmt.Printf("Generating certificate for: %v\n", config.CommonName)

	// Create private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil
	}

	keyFilename := path.Join(config.InstallTo, fmt.Sprintf("%s.key", config.FilenamePrefix))
	if err := savePrivateKey(privateKey, keyFilename); err != nil {
		return err
	}

	expires, err := time.ParseDuration(config.Expires)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(expires)

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Country:            []string{config.Country},
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationUnit},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range config.SubjectAltNames {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// if *isCA {
	// 	template.IsCA = true
	// 	template.KeyUsage |= x509.KeyUsageCertSign
	// }

	// If no CA is provided, then self sign
	if caCert == nil {
		caCert = &template
	}
	if caKey == nil {
		caKey = privateKey
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, caCert, publicKey(privateKey), caKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certFilename := path.Join(config.InstallTo, fmt.Sprintf("%s.crt", config.FilenamePrefix))
	if err := saveCertificate(cert, certFilename); err != nil {
		return err
	}

	for _, certConfig := range config.Issue {
		if err := issueCertificate(certConfig, &template, privateKey); err != nil {
			return nil
		}
	}

	return nil
}

func savePrivateKey(key interface{}, filename string) error {

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filename), os.ModePerm); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	if err := pem.Encode(keyOut, pemBlockForKey(key)); err != nil {
		return err
	}

	return keyOut.Close()
}

func saveCertificate(derBytes []byte, filename string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filename), os.ModePerm); err != nil {
		return err
	}

	certOut, err := os.Create(filename)
	if err != nil {
		return err
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	return certOut.Close()
}

func randomSerial() (*big.Int, error) {
	//Max random value, a 130-bits integer, i.e 2^130 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

	//Generate cryptographically strong pseudo-random between 0 - max
	return rand.Int(rand.Reader, max)
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}
