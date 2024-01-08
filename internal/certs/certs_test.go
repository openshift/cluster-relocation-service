package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var _ = Describe("KubeConfigCertManager", func() {
	var (
		dir string
		cm  KubeConfigCertManager
	)
	BeforeEach(func() {
		var err error
		dir, err = os.MkdirTemp("", "certs")
		Expect(err).NotTo(HaveOccurred())
		cm = KubeConfigCertManager{CertificatesDir: dir}
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dir)).To(Succeed())
	})

	It("generateCA success", func() {
		certPath := filepath.Join(dir, "admin-kubeconfig-client-ca.crt")
		keyPath := filepath.Join(dir, "admin-kubeconfig-client-ca.key")
		adminCA := CertInfo{
			commonName:      "admin-kubeconfig-signer",
			certificatePath: certPath,
			keyPath:         keyPath,
		}
		_, err := generateAndWriteCA(adminCA)
		Expect(err).NotTo(HaveOccurred())
		_, err = os.Stat(certPath)
		Expect(err).NotTo(HaveOccurred())
		_, err = os.Stat(keyPath)
		Expect(err).NotTo(HaveOccurred())
		caCert := loadCACertFromFile(certPath)
		checkCertValidity(caCert, time.Duration(validityTenYearsInDays)*24*time.Hour)
	})
	It("GenerateKubeApiserverServingSigningCerts success", func() {
		err := cm.GenerateKubeApiserverServingSigningCerts()
		Expect(err).NotTo(HaveOccurred())
		// verify all signer keys exists
		signerKeyFileNames := []string{
			"loadbalancer-serving-signer.key",
			"localhost-serving-signer.key",
			"service-network-serving-signer.key",
		}
		for _, fileName := range signerKeyFileNames {
			// verify all signer keys exists
			_, err = os.Stat(filepath.Join(dir, fileName))
			Expect(err).NotTo(HaveOccurred())
		}
	})
	It("GenerateIngressServingSigningCerts success", func() {
		err := cm.GenerateIngressServingSigningCerts()
		Expect(err).NotTo(HaveOccurred())
		// verify all signer keys exists
		_, err = os.Stat(filepath.Join(dir, "ingresskey-ingress-operator.key"))
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(cm.clusterCABundle)
		Expect(block).NotTo(Equal(nil))
		// Parse the CA certificate
		ingressCert, err := x509.ParseCertificate(block.Bytes)
		checkCertValidity(ingressCert, time.Duration(validityTwoYearsInDays)*24*time.Hour)
	})

	It("generateAdminUserCertificate success", func() {
		certPath := filepath.Join(dir, "admin-kubeconfig-client-ca.crt")
		keyPath := filepath.Join(dir, "admin-kubeconfig-client-ca.key")
		adminCA := CertInfo{
			commonName:      "admin-kubeconfig-signer",
			certificatePath: certPath,
			keyPath:         keyPath,
		}
		ca, err := generateAndWriteCA(adminCA)
		caCert := loadCACertFromFile(certPath)

		userCert, _, err := generateAdminUserCertificate(ca)
		Expect(err).NotTo(HaveOccurred())

		// Verify that the client cert was signed by the given
		block, _ := pem.Decode(userCert)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		cert.CheckSignatureFrom(caCert)
		checkCertValidity(cert, time.Duration(validityTenYearsInDays)*24*time.Hour)
	})

	It("GenerateKubeConfig", func() {
		apiUrl := "apiurl.com"
		cm.userClientCert = []byte("userClientCert")
		cm.userClientKey = []byte("userClientKey")
		kubeconifg, err := cm.GenerateKubeConfig(apiUrl)
		Expect(err).NotTo(HaveOccurred())
		// Load the kubeconfig file
		conifg, err := clientcmd.Load(kubeconifg)
		Expect(err).NotTo(HaveOccurred())
		Expect(conifg.Clusters["cluster"].Server).To(Equal(fmt.Sprintf("https://api.%s:6443", apiUrl)))
		Expect(string(conifg.AuthInfos["admin"].ClientKeyData)).To(Equal("userClientKey"))
		Expect(string(conifg.AuthInfos["admin"].ClientCertificateData)).To(Equal("userClientCert"))
		Expect(conifg.CurrentContext).To(Equal("admin"))
	})
})

func checkCertValidity(cert *x509.Certificate, expectedValidity time.Duration) {
	currentTime := time.Now()
	// When creating the cert NotBefore is set to currentTime minus 1 second
	startDate := cert.NotBefore.Add(1 * time.Second)
	Expect(currentTime.Before(startDate)).To(BeFalse())
	oneMinuteFromNow := currentTime.Add(time.Minute)
	Expect(oneMinuteFromNow.After(startDate)).To(BeTrue())
	notAfter := startDate.Add(expectedValidity) // Valid for 10 years
	Expect(cert.NotAfter).To(Equal(notAfter))
}

func loadCACertFromFile(caCertPath string) *x509.Certificate {
	// Load CA certificate from a file
	caCertPEM, err := os.ReadFile(caCertPath)
	Expect(err).NotTo(HaveOccurred())
	// Decode PEM-encoded CA certificate
	block, _ := pem.Decode(caCertPEM)
	Expect(block).NotTo(Equal(nil))
	// Parse the CA certificate
	caCert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return caCert
}

func TestCertManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certs Suite")
}
