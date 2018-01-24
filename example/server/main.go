package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/coreos/rkt/pkg/lock"
)

const certFile = "/var/run/secrets/vaultproject.io/cert.pem"
const caCertFile = "/var/run/secrets/vaultproject.io/ca-cert.pem"
const privKeyFile = "/var/run/secrets/vaultproject.io/private.pem"

type CertificateStore struct {
	CACertificate []byte
	Certificate   *tls.Certificate
}

var (
	cm    *CertificateStore
	flock *lock.FileLock
	err   error
)

func main() {
	flock, err = lock.NewLock(certFile, 1)
	if err != nil {
		log.Fatalf("could not set lock: %v", err)
	}
	startServer()
}

func NewCertificateStore() (*CertificateStore, error) {
	flock.ExclusiveLock()
	cm := &CertificateStore{}
	// read cert
	certificate, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Printf("Failed to read %v", certFile)
		return cm, err
	}
	// read private key
	privateKey, err := ioutil.ReadFile(privKeyFile)
	if err != nil {
		log.Printf("Failed to read %v", privKeyFile)
		return cm, err
	}
	// read cacert
	cacert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Printf("Failed to read %v", caCertFile)
		return cm, err
	}
	cm.CACertificate = []byte(cacert)

	var certPEMBlock bytes.Buffer
	certPEMBlock.Write(certificate)
	certPEMBlock.WriteString("\n")
	certPEMBlock.Write(cacert)
	c, err := tls.X509KeyPair(certPEMBlock.Bytes(), privateKey)
	if err != nil {
		log.Printf("certificate manager: error parsing pki certificates: %v", err)
		return cm, err
	}
	cm.Certificate = &c
	flock.Unlock()
	return cm, nil
}

func startServer() {
	cm, err := NewCertificateStore()
	if err != nil {
		log.Fatal(err)
	}

	clientCAPool := x509.NewCertPool()
	if ok := clientCAPool.AppendCertsFromPEM(cm.CACertificate); !ok {
		log.Fatal("missing CA certificate")
	}

	server := http.Server{
		Addr: "0.0.0.0:443",
		TLSConfig: &tls.Config{
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      clientCAPool,
			GetCertificate: cm.GetCertificate,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from client service")
	})

	log.Fatal(server.ListenAndServeTLS("", ""))
}

func (cm *CertificateStore) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cm.Certificate, nil
}
