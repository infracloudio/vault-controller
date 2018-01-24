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

	"github.com/hashicorp/vault/api"
)

type tokenHandler struct {
	vaultAddr string
}

func (h tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat(tokenFile)
	if !os.IsNotExist(err) {
		log.Println("Token file already exists")
		w.WriteHeader(409)
		return
	}

	var swi api.SecretWrapInfo
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}
	r.Body.Close()

	err = json.Unmarshal(data, &swi)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	client.SetToken(swi.Token)
	client.SetAddress(h.vaultAddr)

	// Vault knows to unwrap the client token if the token to unwrap is empty.
	secret, err := client.Logical().Unwrap("")
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	f, err := os.Create(tokenFile)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}
	defer f.Close()

	err = json.NewEncoder(f).Encode(&secret)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}
	log.Printf("wrote %s", tokenFile)
	w.WriteHeader(200)
}

func readToken(tokenFile string) (string, error) {
	log.Printf("Reading vault secret file from %s", tokenFile)
	data, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("could not read secret file: %v", err)
	}

	var secret Secret
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return "", fmt.Errorf("could not parse token file %v", err)
	}
	return secret.Auth.ClientToken, nil
}

func requestToken(vaultControllerAddr, name, namespace string) error {
	u := fmt.Sprintf("%s/token?name=%s&namespace=%s", vaultControllerAddr, name, namespace)
	log.Printf("Requesting a new wrapped token from %s", vaultControllerAddr)
	resp, err := http.Post(u, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 {
		return nil
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return fmt.Errorf("%s", data)
}
