package certs

import (
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/openshift/library-go/pkg/crypto"
)

type KubeConfigCertManager struct {
	CertificatesDir string
	userClientCert  []byte
	userClientKey   []byte
	clusterCABundle []byte
}
type CertInfo struct {
	keyPath         string
	certificatePath string
	commonName      string
	validity        int
}

const (
	// validityTwoYearsInDays sets the validity of a cert to 2 years.
	validityTwoYearsInDays = 365 * 2

	// validityTenYearsInDays sets the validity of a cert to 10 years.
	validityTenYearsInDays = 365 * 10
)

func (r *KubeConfigCertManager) GenerateAllCertificates() error {
	err := r.GenerateKubeApiserverServingSigningCerts()
	if err != nil {
		return fmt.Errorf("failed to generate the kube apiserver serving signing certificates: %w", err)
	}
	err = r.GenerateIngressServingSigningCerts()
	if err != nil {
		return fmt.Errorf("failed to generate the ingress signer certificates: %w", err)
	}

	adminCA := CertInfo{
		commonName:      "admin-kubeconfig-signer",
		certificatePath: filepath.Join(r.CertificatesDir, "admin-kubeconfig-client-ca.crt"),
		keyPath:         filepath.Join(r.CertificatesDir, "admin-kubeconfig-client-ca.key"),
	}
	ca, err := generateAndWriteCA(adminCA)
	if err != nil {
		return fmt.Errorf("failed to generate admin kubeconfig signer CA: %w", err)
	}

	r.userClientCert, r.userClientKey, err = generateAdminUserCertificate(ca)
	if err != nil {
		return fmt.Errorf("failed to generate admin user certificate: %w", err)

	}
	return nil
}

// GenerateKubeApiserverServingSigningCerts Create the kapi serving signer CAs and adds them to the cluster CA bundle
func (r *KubeConfigCertManager) GenerateKubeApiserverServingSigningCerts() error {
	for _, ci := range []CertInfo{
		{
			keyPath:    filepath.Join(r.CertificatesDir, "loadbalancer-serving-signer.key"),
			commonName: "kube-apiserver-lb-signer",
		},
		{
			keyPath:    filepath.Join(r.CertificatesDir, "localhost-serving-signer.key"),
			commonName: "kube-apiserver-localhost-signer",
		},
		{
			keyPath:    filepath.Join(r.CertificatesDir, "service-network-serving-signer.key"),
			commonName: "kube-apiserver-service-network-signer",
		},
	} {
		ca, err := generateAndWriteCA(ci)
		if err != nil {
			return err
		}
		certBytes, err := crypto.EncodeCertificates(ca.Config.Certs...)
		if err != nil {
			return err
		}
		// Append the PEM-encoded certificate to the cluster CA bundle
		r.clusterCABundle = append(r.clusterCABundle, certBytes...)
	}
	return nil
}

// GenerateIngressServingSigningCerts Create the ingress serving signer CAs and adds them to the cluster CA bundle
func (r *KubeConfigCertManager) GenerateIngressServingSigningCerts() error {
	ca, err := generateAndWriteCA(CertInfo{
		keyPath:    filepath.Join(r.CertificatesDir, "ingresskey-ingress-operator.key"),
		commonName: fmt.Sprintf("%s@%d", "ingress-operator", time.Now().Unix()),
		validity:   validityTwoYearsInDays,
	},
	)
	if err != nil {
		return err
	}
	certBytes, err := crypto.EncodeCertificates(ca.Config.Certs...)
	if err != nil {
		return err
	}
	// Append the PEM-encoded certificate to the cluster CA bundle
	r.clusterCABundle = append(r.clusterCABundle, certBytes...)
	return nil
}

func (r *KubeConfigCertManager) GenerateKubeConfig(url string) ([]byte, error) {
	kubeCfg := clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
	}
	kubeCfg.Clusters = map[string]*clientcmdapi.Cluster{
		"cluster": {
			Server:                   fmt.Sprintf("https://api.%s:6443", url),
			CertificateAuthorityData: r.clusterCABundle,
		},
	}
	kubeCfg.AuthInfos = map[string]*clientcmdapi.AuthInfo{
		"admin": {
			ClientCertificateData: r.userClientCert,
			ClientKeyData:         r.userClientKey,
		},
	}
	kubeCfg.Contexts = map[string]*clientcmdapi.Context{
		"admin": {
			Cluster:   "cluster",
			AuthInfo:  "admin",
			Namespace: "default",
		},
	}
	kubeCfg.CurrentContext = "admin"
	return clientcmd.Write(kubeCfg)
}

func generateSelfSignedCACertificate(commonName string, validity int) (*crypto.CA, error) {
	subject := pkix.Name{CommonName: commonName, OrganizationalUnit: []string{"openshift"}}
	newCAConfig, err := crypto.MakeSelfSignedCAConfigForSubject(
		subject,
		validity,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating self signed CA: %w", err)
	}
	return &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          newCAConfig,
	}, nil
}

func generateAndWriteCA(certInfo CertInfo) (*crypto.CA, error) {
	if certInfo.validity == 0 {
		// set validity to 10 years
		certInfo.validity = validityTenYearsInDays
	}
	ca, err := generateSelfSignedCACertificate(certInfo.commonName, certInfo.validity)
	if err != nil {
		return nil, err
	}
	if certInfo.certificatePath == "" {
		certInfo.certificatePath = "/dev/null"
	}
	ca.Config.WriteCertConfigFile(certInfo.certificatePath, certInfo.keyPath)
	return ca, nil
}

func generateAdminUserCertificate(ca *crypto.CA) ([]byte, []byte, error) {
	user := user.DefaultInfo{Name: "system:admin"}
	lifetime := validityTenYearsInDays * 24 * time.Hour

	cfg, err := ca.MakeClientCertificateForDuration(&user, lifetime)
	if err != nil {
		return nil, nil, fmt.Errorf("error making client certificate: %w", err)
	}
	crt, key, err := cfg.GetPEMBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get PEM bytes for system:admin client certificate: %w", err)
	}

	return crt, key, nil
}
