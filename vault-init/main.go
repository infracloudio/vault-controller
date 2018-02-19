// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"github.com/fsnotify/fsnotify"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"
)

const tokenFile = "/var/run/secrets/vaultproject.io/secret.json"
const certFile = "/var/run/secrets/vaultproject.io/cert.pem"
const caCertFile = "/var/run/secrets/vaultproject.io/ca-cert.pem"
const privKeyFile = "/var/run/secrets/vaultproject.io/private.pem"

var (
	namespace    string
	serviceName  string
	vaultAddr    string
	vaultToken   string
	name         string
	retryTimeout int
)

func main() {
	log.Println("Starting vault-init...")

	flag.StringVar(&namespace, "namespace", "default", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&serviceName, "service-name", "", "Kubernetes service name that resolves to this Pod")
	flag.StringVar(&name, "name", "", "name as defined by pod.metadata.name")
	flag.IntVar(&retryTimeout, "retry-timeout", 1, "retry timeout for token/certs in minutes")
	flag.Parse()

	vaultControllerAddr := os.Getenv("VAULT_CONTROLLER_ADDR")
	if vaultControllerAddr == "" {
		vaultControllerAddr = "http://vault-controller"
	}

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://vault:8200"
	}

	http.Handle("/", tokenHandler{vaultAddr})
	go func() {
		log.Fatal(http.ListenAndServe(":80", nil))
	}()

	// Ensure the token handler is ready.
	time.Sleep(time.Millisecond * 300)

	// Remove exiting token files before requesting a new one.
	if err := os.Remove(tokenFile); err != nil {
		log.Printf("could not remove token file at %s: %s", tokenFile, err)
	}

	// Remove existing certs and key
	if err := os.Remove(certFile); err != nil {
		log.Printf("could not remove cert file from %s: %s", certFile, err)
	}
	if err := os.Remove(caCertFile); err != nil {
		log.Printf("could not remove ca-cert file from %s: %s", caCertFile, err)
	}
	if err := os.Remove(privKeyFile); err != nil {
		log.Printf("could not remove private-key file from %s: %s", privKeyFile, err)
	}

	// Set up a file watch on the wrapped vault token.
	tokenWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("could not create watcher: %s", err)
	}
	err = tokenWatcher.Add(path.Dir(tokenFile))
	if err != nil {
		log.Fatalf("could not add watcher: %v", err)
	}

	done := make(chan bool)
	retryDelay := 5 * time.Second
	retryCount := retryTimeout * 60 / 5
	go func() {
		for {
			err := requestToken(vaultControllerAddr, name, namespace)
			if err != nil {
				log.Printf("token request: Request error %v; retrying in %v", err, retryDelay)
				time.Sleep(retryDelay)
				if retryCount <= 0 {
					log.Fatal("Token request timeout")
				}
				retryCount -= 1
				continue
			}
			log.Println("Token request complete; waiting for callback...")
			select {
			case <-time.After(time.Second * 30):
				log.Println("token request: Timeout waiting for callback")
				break
			case <-tokenWatcher.Events:
				tokenWatcher.Close()
				close(done)
				return
			case err := <-tokenWatcher.Errors:
				log.Println("token request: error watching the token file", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
		log.Printf("Shutdown signal received, exiting...")
	case <-done:
		writeCertsToFile()
		log.Println("Successfully obtained and unwrapped the vault token, exiting...")
	}
}
