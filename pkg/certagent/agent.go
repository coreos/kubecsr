package certagent

import (
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net"
	"path"
	"time"

	"github.com/golang/glog"
	capi "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"

	"github.com/coreos/kubecsr/pkg/util"
)

// CSRConfig contains the configuration values required
// to generate a Certificate Signing Request for the agent.
type CSRConfig struct {
	// CommonName is the common name to be provided in the Certificate
	CommonName string `json:"commonName"`
	// Orgname is the name of the organization for the Certificate
	OrgName string `json:"orgName"`

	// Alternate Name values required to create CertificateRequest
	DNSNames    []string `json:"dnsNames"`
	IPAddresses []net.IP `json:"ipAddresses"`

	// AssetsDir is the directory location where certificates and
	// private keys will be saved
	AssetsDir string `json:"assetsDir"`

	// CSRName is the name of the CertificateSigningRequest object
	// that will be created
	CSRName string `json:"csrName"`
}

// CertAgent is the top level object that represents a certificate agent.
// All the fields it holds are configuration values required for
// generating a CSR, doing a POST request to the signer and writing the
// singed certificate obtained from the signer to disk.
type CertAgent struct {
	// client implements the CertificateSigningRequestInterface
	client certificatesclient.CertificateSigningRequestInterface
	// config holds all the CSR generation related configuration values.
	config CSRConfig
}

// NewAgent returns an initialized CertAgent instance or an error is unsuccessful
func NewAgent(csrConfig CSRConfig, kubeconfigFile string) (*CertAgent, error) {
	content, err := ioutil.ReadFile(kubeconfigFile)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", kubeconfigFile, err)
	}
	kubeconfig, err := clientcmd.Load(content)
	if err != nil {
		return nil, fmt.Errorf("error reading config from bytes: %v", err)
	}
	config, err := clientcmd.NewDefaultClientConfig(*kubeconfig, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error creating client config: %v", err)
	}

	client, err := certificatesclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %v", err)
	}

	return &CertAgent{
		client: client.CertificateSigningRequests(),
		config: csrConfig,
	}, nil
}

// GenerateCSRObject generates a certificate signing request object and returns it.
func GenerateCSRObject(config CSRConfig) (*capi.CertificateSigningRequest, error) {
	subject := &pkix.Name{
		Organization: []string{config.OrgName},
		CommonName:   config.CommonName,
	}

	privateKeyBytes, err := util.GeneratePrivateKey(config.AssetsDir, config.CommonName)
	if err != nil {
		return nil, fmt.Errorf("error generating private key bytes: %v", err)
	}

	privateKey, err := certutil.ParsePrivateKeyPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key for certificate request: %v", err)
	}

	csrData, err := certutil.MakeCSR(privateKey, subject, config.DNSNames, config.IPAddresses)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate request bytes: %v", err)
	}

	csr := &capi.CertificateSigningRequest{
		TypeMeta:   metav1.TypeMeta{Kind: "CertificateSigningRequest"},
		ObjectMeta: metav1.ObjectMeta{Name: config.CSRName},
		Spec: capi.CertificateSigningRequestSpec{
			Request: csrData,
		},
	}

	return csr, nil
}

// RequestCertificate will create a certificate signing request for a node
// with the config given and send it to a signer via a POST request.
// If something goes wrong it returns an error but wait forever for
// server to respond to request.
// NOTE: This method does not return the approved CSR from the signer.
func (c *CertAgent) RequestCertificate() error {
	csr, err := GenerateCSRObject(c.config)
	if err != nil {
		return fmt.Errorf("error generating CSR Object: %v", err)
	}

	duration := 10 * time.Second
	// wait forever for success and retry every duration interval
	wait.PollInfinite(duration, func() (bool, error) {
		_, err := c.client.Create(csr)
		if err != nil {
			glog.Errorf("error sending CSR to signer: %v", err)
			return false, nil
		}
		return true, nil
	})

	rcvdCSR, err := c.WaitForCertificate()
	if err != nil {
		return fmt.Errorf("error obtaining signed certificate from signer: %v", err)
	}

	// write out signed certificate to disk
	certFile := path.Join(c.config.AssetsDir, c.config.CommonName+".crt")
	if err := ioutil.WriteFile(certFile, rcvdCSR.Status.Certificate, 0644); err != nil {
		return fmt.Errorf("unable to write to %s: %v", certFile, err)
	}
	return nil
}

// WaitForCertificate waits for a certificate to be issued until timeout, or returns an error.
// It does a GET to the signer with the CSR name.
func (c *CertAgent) WaitForCertificate() (req *capi.CertificateSigningRequest, err error) {
	interval := 3 * time.Second
	timeout := 10 * time.Second

	// implement the client GET request to the signer in a poll loop.
	if err = wait.PollImmediate(interval, timeout, func() (bool, error) {
		req, err = c.client.Get(c.config.CSRName, metav1.GetOptions{})
		if err != nil {
			glog.Errorf("unable to retrieve approved CSR: %v. Retrying.", err)
			return false, nil
		}
		// if a CSR is returned without explicitly being `approved` or `denied` we want to retry
		if approved, denied := util.GetCertApprovalCondition(&req.Status); !approved && !denied {
			glog.Error("status on CSR not set. Retrying.")
			return false, nil
		}
		// if a CSR is returned with `approved` status set and no signed certificate we want to retry
		if util.IsCertificateRequestApproved(req) && len(req.Status.Certificate) == 0 {
			glog.Error("status on CSR set to `approved` but signed certificate is empty. Retrying.")
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return
}

// UnescapeIPV6Address removes left and right brackets used to escape IPv6 addresses. Example
// [2605:2700:0:3::4713:93e3] will return 2605:2700:0:3::4713:93e3. If this escaping does
// not exist return the original address without additional validation.
func UnescapeIPV6Address(addr string) string {
	firstChar := addr[:1]
	lastChar := addr[len(addr)-1:]

	if firstChar == "[" && lastChar == "]" {
		return addr[1 : len(addr)-1]
	}
	return addr
}
