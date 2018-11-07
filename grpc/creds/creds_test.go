package creds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"os"
	"time"
)

func ClientTransportCredentials(host string, cert *x509.Certificate, caPriv *rsa.PrivateKey) ([]byte, *rsa.PrivateKye, *tls.Config) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)

	temp := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{host},
		},
		NotBefore:             time.Unix(1000, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	derA, err := x509.CreateCertificate(rand.Reader, temp, temp, priv.Public(), priv)
	conf := &tls.Config{
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{derA}, PrivateKey: priv},
			{Certificate: [][]byte{cert.Raw}},
		}
	}
	
	return derA, priv, tlsConf
}
