package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"time"

	"github.com/coreos/rkt/pkg/lock"
	"github.com/go-fsnotify/fsnotify"
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
	// Set up a file watch on cert file
	certWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("could not create watcher: %s", err)
	}
	err = certWatcher.Add(path.Dir(certFile))
	if err != nil {
		log.Fatalf("could not add watcher: %v", err)
	}
	startClient()
	go func() {
		for {
			select {
			case ev := <-certWatcher.Events:
				log.Println("filewatcher event:", ev)
				cm, err = NewCertificateStore()
				if err != nil {
					log.Fatal(err)
				}
			case err := <-certWatcher.Errors:
				log.Println("filewatcher error:", err)
			}
		}
	}()
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

func startClient() {
	cm, err := NewCertificateStore()
	if err != nil {
		log.Fatal(err)
	}

	rootCAPool := x509.NewCertPool()
	if ok := rootCAPool.AppendCertsFromPEM(cm.CACertificate); !ok {
		log.Fatal("missing CA certificate")
	}
	for {
		time.Sleep(5 * time.Second)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       cm.Certificates(),
				InsecureSkipVerify: false,
				RootCAs:            rootCAPool,
			},
		}
		client := http.Client{Transport: tr}
		resp, err := client.Get("https://server")
		if err != nil {
			log.Println(err)
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println(string(body))
	}
}

func (cm *CertificateStore) Certificates() []tls.Certificate {
	return []tls.Certificate{*cm.Certificate}
}
