package main

import (
	//"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"
)

var (
	namespace   string
	serviceName string
	vaultAddr   string
	token       chan string
	vaultToken  string
	name        string
)

// certificate renewal threshold in sec
const (
	certThreshold = 60
)

func main() {
	log.Println("Starting secret-controller...")

	flag.StringVar(&namespace, "namespace", "default", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&name, "name", "", "name as defined by pod.metadata.name")
	flag.StringVar(&vaultAddr, "vault-addr", "https://vault:8200", "Vault service address")
	flag.Parse()

	vaultControllerAddr := os.Getenv("VAULT_CONTROLLER_ADDR")
	if vaultControllerAddr == "" {
		vaultControllerAddr = "http://vault-controller"
	}

	token = make(chan string)
	http.Handle("/", tokenHandler{vaultAddr})
	go func() {
		log.Fatal(http.ListenAndServe(":80", nil))
	}()

	// Request for vault token to vault controller
	err := requestToken(vaultControllerAddr, name, namespace)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	vaultToken = <-token
	checkCerts()
}
