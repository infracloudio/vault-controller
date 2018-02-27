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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	certs chan []byte
)

func readCertPath(namespace, name string) string {
	return fmt.Sprintf("secret/certs/%s/%s", namespace, name)
}

// ReadCerts reads certs from vault and save to file
func ReadCerts(ticker *time.Ticker) {
	vaultToken, err := readToken(tokenFile)
	if err != nil {
		log.Fatal(err)
	}
	path := readCertPath(namespace, serviceName)
	log.Println("reading certifificates from", path)
	u := fmt.Sprintf("%s/v1/%s", vaultAddr, path)
	request, err := http.NewRequest("GET", u, nil)
	if err != nil {
		log.Fatal("read certs: error creating request: %v", err)
	}
	request.Header.Add("X-Vault-Token", vaultToken)
	retryCount := retryTimeout * 60 / 5
	for range ticker.C {
		if retryCount <= 0 {
			log.Fatal("Certificate request timeout")
		}
		retryCount -= 1
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			log.Println("read certs: err in response %v", err)
			continue
		}
		if resp.StatusCode == 404 {
			log.Println("read certs: secret not present. Create service to generate certificate")
			continue
		}
		if resp.StatusCode == 403 {
			log.Println("read certs: access Forbidden. Please add right policy to access secret")
			continue
		}
		defer resp.Body.Close()
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("read certs: err in body")
			continue
		}
		if resp.StatusCode == 200 {
			log.Println("read certs success")
			certs <- data
		}
	}
}

func writeCertsToFile() {
	certs = make(chan []byte)
	ticker := time.NewTicker(time.Second * 5)
	go ReadCerts(ticker)
	data := <-certs
	ticker.Stop()
	log.Println("Writing certs to disk")
	var secret ReadSecret
	err := json.Unmarshal(data, &secret)
	if err != nil {
		log.Fatal("certificate manager: error parsing pki secret: %v", err)
	}

	// write ca certificate to file
	ca, err := os.Create(caCertFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(ca, secret.Data.IssuingCA)
	log.Printf("wrote %s", caCertFile)
	defer ca.Close()

	// write certificate to file
	crt, err := os.Create(certFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(crt, secret.Data.Certificate)
	log.Printf("wrote %s", certFile)
	defer crt.Close()

	// write private key to file
	p, err := os.Create(privKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(p, secret.Data.PrivateKey)
	log.Printf("wrote %s", privKeyFile)
	defer p.Close()
}
