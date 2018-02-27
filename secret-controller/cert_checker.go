package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

var (
	clientset     *kubernetes.Clientset
	serviceClient v1.ServiceInterface
)

func updateDeployment(ns, service string) {
	deploymentsClient := clientset.AppsV1beta1().Deployments(ns)
	dlist, err := deploymentsClient.List(metav1.ListOptions{})
	if err != nil {
		log.Println("Error in getting list of deployment")
		return
	}
	for _, d := range dlist.Items {
		if service == d.Spec.Template.ObjectMeta.Labels["service"] {

			d.Spec.Template.ObjectMeta.Labels["lastcertupdate"] = time.Now().Format("02-01-2006T15.04.05")
			_, err = deploymentsClient.Update(&d)
			if err != nil {
				log.Printf("err in rolling update for %v - %v\n", d.ObjectMeta.Name, err)
				return
			}
			log.Println("Rolling update initiated for", d.ObjectMeta.Name)
		}
	}
}

func updateService(ns string, name string) {
	sc := clientset.CoreV1().Services(ns)
	service, err := sc.Get(name, metav1.GetOptions{})
	if err != nil {
		log.Println("Error in getting service", service, err)
	}
	service.ObjectMeta.Labels["gencert"] = "true"
	_, err = sc.Update(service)
	if err != nil {
		log.Println("Error in updating service", service, err)
	}
}

func deleteCerts(path string) {
	u := fmt.Sprintf("%s/v1/%s", vaultAddr, path)
	request, err := http.NewRequest("DELETE", u, nil)
	if err != nil {
		log.Println("Error creating request to delete certs for path - %v", path, err)
		return
	}
	request.Header.Add("X-Vault-Token", vaultToken)
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Printf("Error in deleting certificates from %v - %v status code: %v\n", path, err, resp.StatusCode)
		return
	}
	log.Println("Deleted certs from", path)
}

func readCertPath(namespace, name string) string {
	return fmt.Sprintf("secret/certs/%s/%s", namespace, name)
}

// ReadCerts reads certs from vault
func readCerts(ns, service string) (*ReadSecret, error) {
	u := fmt.Sprintf("%s/v1/%s", vaultAddr, readCertPath(ns, service))
	request, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("read certs: error creating request for service %v - %v\n", service, err)
	}
	request.Header.Add("X-Vault-Token", vaultToken)
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("read certs: err in response for service %v - %v\n", service, err)

	}
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("read certs: secret not present. Create service to generate certificate for service %v\n", service)
	}
	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("read certs: access Forbidden. Please add right policy to access secret for service %v\n", service)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read certs: err in body for service %v", service)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("read certs: received invalid response for service %v response %v\n", service, resp.StatusCode)
	}
	log.Println("read certs success for service", service)
	var secret *ReadSecret
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return nil, fmt.Errorf("Error parsing pki secret for service %v - %v\n", service, err)
	}
	return secret, nil
}

func rotateCerts(service corev1.Service) error {
	serviceName := service.ObjectMeta.Name
	serviceNs := service.ObjectMeta.Namespace
	certs, err := readCerts(serviceNs, serviceName)
	if err != nil {
		return err
	}
	c, err := tls.X509KeyPair([]byte(certs.Data.Certificate), []byte(certs.Data.PrivateKey))
	if err != nil {
		return fmt.Errorf("Error parsing pki certificates for service %v - %v", serviceName, err)
	}
	x509cert, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return fmt.Errorf("certificate parsing error for service %s - %v", serviceName, err)
	}
	exp := x509cert.NotAfter.Sub(time.Now()).Seconds()
	if exp <= float64(certThreshold*60) {
		// delete certs, generate new certs and perform rolling update if expired
		log.Printf("certificate expired for %v. Deleting old and generating new\n", serviceName)
		deleteCerts(readCertPath(serviceNs, serviceName))
		updateService(serviceNs, serviceName)
		updateDeployment(serviceNs, serviceName)
	} else {
		log.Printf("certificate expiring in %v sec for service %v\n", exp, serviceName)
	}
	return nil
}

func checkCerts() {
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	//	home := homedir.HomeDir()
	//	kubeconfig := filepath.Join(home, ".kube", "config")

	//	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	//	if err != nil {
	//		panic(err)
	//	}
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	serviceClient = clientset.CoreV1().Services(corev1.NamespaceAll)
	ser, err := serviceClient.List(metav1.ListOptions{})
	if err != nil {
		log.Println("Error in getting list of services")
		return
	}
	for _, s := range ser.Items {
		if s.ObjectMeta.Labels["gencert"] != "" {
			err := rotateCerts(s)
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}
}
