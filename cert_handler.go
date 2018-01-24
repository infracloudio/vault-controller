package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type Service struct {
	Metadata *SvsMetadata `json:"metadata,omitempty"`
}

type SvsMetadata struct {
	Labels *Label `json:"labels,omitempty"`
	Name   string `json:"name,omitempty"`
}

type Label struct {
	App     string `json:"app,omitempty"`
	Gencert string `json:"gencert,omitempty"`
}

type PKIConfig struct {
	CommonName  string
	DNSNames    string
	IPAddresses string
	IssuePath   string
	TTL         string
}

var (
	newService chan Service
	delService chan Service
	clientset  *kubernetes.Clientset
)

func serviceWatcher() {
	kubeconfig, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	clientset, err = kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		panic(err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	watchlist := cache.NewListWatchFromClient(
		clientset.CoreV1().RESTClient(), "services", namespace, fields.Everything())
	_, controller := cache.NewInformer(
		watchlist,
		&v1.Service{},
		0*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				service := Service{}
				jsn, _ := json.Marshal(obj)
				json.Unmarshal(jsn, &service)
				log.Printf("Service created %s\n", jsn)
				newService <- service
			},
			UpdateFunc: func(oldobj, newobj interface{}) {
				service := Service{}
				jsn, _ := json.Marshal(newobj)
				json.Unmarshal(jsn, &service)
				log.Printf("Service updated %s\n", jsn)
				if (service.Metadata).Labels.Gencert == "true" {
					newService <- service
				}
			},
			DeleteFunc: func(obj interface{}) {
				service := Service{}
				jsn, _ := json.Marshal(obj)
				json.Unmarshal(jsn, &service)
				log.Printf("Service deleted %s\n", jsn)
				delService <- service
			},
		},
	)
	controller.Run(stopCh)

}

func generateCerts(p PKIConfig) (*PKIData, error) {
	u := fmt.Sprintf("%s/v1%s", vaultAddr, p.IssuePath)
	parameters := map[string]string{
		"common_name": p.CommonName,
		"ttl":         p.TTL,
		"ip_sans":     p.IPAddresses,
		"alt_names":   p.DNSNames,
	}

	var body bytes.Buffer
	err := json.NewEncoder(&body).Encode(&parameters)
	if err != nil {
		return nil, fmt.Errorf("certificate handler: error encoding request body: %v", err)
	}

	request, err := http.NewRequest("POST", u, &body)
	if err != nil {
		return nil, fmt.Errorf("certificate handler: error creating pki request: %v", err)
	}
	request.Header.Add("X-Vault-Token", vaultToken)

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("certificate handler: error during pki request: %v", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("certificate handler: error reading pki response: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(string(data))
	}

	var secret PKIIssueSecret
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return nil, fmt.Errorf("certificate handler: error parsing pki secret: %v", err)
	}
	return &secret.Data, nil
}

func serviceDomainName(name, namespace, domain string) string {
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain)
}

func certIssuePath(name string) string {
	return fmt.Sprintf("/pki/issue/%s", name)
}

func certWritePath(namespace, name string) string {
	return fmt.Sprintf("secret/certs/%s/%s", namespace, name)
}

func writeCerts(path string, p *PKIData) error {
	_, err := vaultClient.Logical().Write(path, map[string]interface{}{
		"certificate":      p.Certificate,
		"issuing_ca":       p.IssuingCA,
		"private_key":      p.PrivateKey,
		"serial_number":    p.SerialNumber,
		"private_key_type": p.PrivateKeyType,
	})
	if err != nil {
		return err
	}
	log.Println("Certificates written at", path)
	return nil
}

func deleteCerts(path string) error {
	log.Println("Deleting certificates for", path)
	_, err := vaultClient.Logical().Delete(path)
	return err
}

func updateServiceLabel(service string) {
	serviceClient := clientset.CoreV1().Services(namespace)
	s, err := serviceClient.Get(service, metav1.GetOptions{})
	if err != nil || s == nil {
		log.Printf("Error in getting service %v - %v\n", service, err)
		return
	}
	s.ObjectMeta.Labels["gencert"] = "false"
	_, err = serviceClient.Update(s)
	if err != nil {
		log.Println("Error in updating service %v - %v\n", service, err)
	}
}

func CertHandler() {
	newService = make(chan Service)
	delService = make(chan Service)
	go serviceWatcher()
	for {
		select {
		case n := <-newService:
			meta := n.Metadata
			if meta.Labels != nil && meta.Labels.Gencert == "true" && meta.Name != "" {
				serviceName := meta.Name
				p := PKIConfig{
					CommonName:  serviceDomainName(serviceName, namespace, clusterDomain),
					DNSNames:    serviceName,
					IPAddresses: "127.0.0.1",
					IssuePath:   certIssuePath(serviceName),
					TTL:         pkiTTL,
				}
				pki, err := generateCerts(p)
				if err != nil {
					log.Println(err)
					continue
				}
				err = writeCerts(certWritePath(namespace, serviceName), pki)
				if err != nil {
					log.Println("Certificate write failed for service %v - %v\n", serviceName, err)
					continue
				}
				// update service label gencert="false"
				updateServiceLabel(serviceName)
			}
		case d := <-delService:
			meta := d.Metadata
			if meta.Labels != nil && meta.Labels.Gencert != "" && meta.Name != "" {
				err := deleteCerts(certWritePath(namespace, meta.Name))
				if err != nil {
					log.Println("Certificate delete failed for service %v - %v\n", meta.Name, err)
				}
			}

		}
	}
}
