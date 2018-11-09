package certsigner

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	capi "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	csrutil "k8s.io/client-go/util/certificate/csr"

	"github.com/coreos/kubecsr/pkg/util"
)

const (
	etcdPeer   = "EtcdPeer"
	etcdServer = "EtcdServer"
)

var (
	// defaultCertDuration is initialized to 365 days
	defaultCertDuration = 24 * 365 * time.Hour
	// ErrInvalidOrg defines a global error for invalid organization
	ErrInvalidOrg = errors.New("invalid organization")
	// ErrInvalidCN defines a global error for invalid subject common name
	ErrInvalidCN = errors.New("invalid subject Common Name")
)

// CertSigner signs a certiifcate using a `cfssl` Signer.
//
// NOTE: the CertSigner only signs certificates for `etcd` nodes, any other
// certificate request from other nodes will be declined.
type CertSigner struct {
	// caCert is the x509 PEM encoded certifcate of the CA used for the
	// cfssl signer
	caCert *x509.Certificate
	// caCert is the x509 PEM encoded private key of the CA used for the
	// cfssl signer
	caKey crypto.Signer
	// cfsslSigner is a `cfssl` Signer that can sign a certificate based on a
	// certificate request.
	cfsslSigner *local.Signer
}

// Config holds the configuration values required to start a new signer
type Config struct {
	// CACertFile is the file location of the Certificate Authority certificate
	CACertFile string
	// CAKeyFile is the file location of the Certificate Authority private key
	CAKeyFile string
	// ServerCertFile is the file location of the server certificate
	ServerCertFile string
	// ServerKeyFile is the file location of the server private key
	ServerKeyFile string
	// ListenAddress is the address at which the server listens for requests
	ListenAddress string
	// EtcdPeerCertDuration is the cert duration for the `EtcdPeer` profile
	EtcdPeerCertDuration time.Duration
	// EtcdServerCertDuration is the cert duration for the `EtcdServer` profile
	EtcdServerCertDuration time.Duration
}

// NewSigner returns a CertSigner object after filling in its attibutes
// from the `Config` provided.
func NewSigner(c Config) (*CertSigner, error) {
	ca, err := ioutil.ReadFile(c.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("error reading CA cert file %q: %v", c.CACertFile, err)
	}
	cakey, err := ioutil.ReadFile(c.CAKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading CA key file %q: %v", c.CAKeyFile, err)
	}

	parsedCA, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, fmt.Errorf("error parsing CA cert file %q: %v", c.CACertFile, err)
	}

	privateKey, err := helpers.ParsePrivateKeyPEM(cakey)
	if err != nil {
		return nil, fmt.Errorf("Malformed private key %v", err)
	}

	// policy is the signature configuration policy for the signer.
	policy := config.Signing{
		Profiles: map[string]*config.SigningProfile{
			etcdPeer: &config.SigningProfile{
				Usage: []string{
					string(capi.UsageKeyEncipherment),
					string(capi.UsageDigitalSignature),
					string(capi.UsageClientAuth),
					string(capi.UsageServerAuth),
				},
				Expiry:       c.EtcdPeerCertDuration,
				ExpiryString: c.EtcdPeerCertDuration.String(),
			},
			etcdServer: &config.SigningProfile{
				Usage: []string{
					string(capi.UsageKeyEncipherment),
					string(capi.UsageDigitalSignature),
					string(capi.UsageServerAuth),
				},
				Expiry:       c.EtcdServerCertDuration,
				ExpiryString: c.EtcdServerCertDuration.String(),
			},
		},
		Default: &config.SigningProfile{
			Usage: []string{
				string(capi.UsageKeyEncipherment),
				string(capi.UsageDigitalSignature),
			},
			Expiry:       defaultCertDuration,
			ExpiryString: defaultCertDuration.String(),
		},
	}

	cfs, err := local.NewSigner(privateKey, parsedCA, signer.DefaultSigAlgo(privateKey), &policy)
	if err != nil {
		return nil, fmt.Errorf("error setting up local cfssl signer: %v", err)
	}

	return &CertSigner{
		caCert:      parsedCA,
		caKey:       privateKey,
		cfsslSigner: cfs,
	}, nil
}

// Sign sends a signature request to the local signer, receiving
// a signed certificate or an error in response. If successful, It
// then returns the CSR which contains the newly signed certificate.
//
// Note: A signed certificate is issued only for etcd profiles.
func (s *CertSigner) Sign(csr *capi.CertificateSigningRequest) (*capi.CertificateSigningRequest, error) {
	x509CSR, err := csrutil.ParseCSR(csr)
	if err != nil {
		return nil, fmt.Errorf("error parsing CSR, %v", err)
	}

	if err := x509CSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("error validating signature of CSR: %v", err)
	}

	// the following step ensures that the signer server only signs CSRs from etcd nodes
	// that have a specific profile. All other requests are denied immediately.
	profile, err := getProfile(x509CSR)
	if err != nil {
		csr.Status.Conditions = []capi.CertificateSigningRequestCondition{
			capi.CertificateSigningRequestCondition{
				Type:    capi.CertificateDenied,
				Message: fmt.Sprintf("error parsing profile: %v ", err),
			},
		}
		return nil, fmt.Errorf("error parsing profile: %v", err)
	}

	csr.Status.Certificate, err = s.cfsslSigner.Sign(signer.SignRequest{
		Request: string(csr.Spec.Request),
		Profile: profile,
	})
	if err != nil {
		csr.Status.Conditions = []capi.CertificateSigningRequestCondition{
			capi.CertificateSigningRequestCondition{
				Type:    capi.CertificateDenied,
				Message: fmt.Sprintf("certificate signing error: %v ", err),
			},
		}
		return csr, err
	}

	csr.Status.Conditions = []capi.CertificateSigningRequestCondition{
		capi.CertificateSigningRequestCondition{
			Type: capi.CertificateApproved,
		},
	}

	return csr, nil
}

// getProfile returns the profile corresponding to the CSR Subject. For now only
// `etcd-peers` and `etcd-servers` are considered valid profiles.
func getProfile(csr *x509.CertificateRequest) (string, error) {
	if csr.Subject.Organization != nil && len(csr.Subject.Organization) == 1 && csr.Subject.Organization[0] == "system:etcd-peers" {
		if !strings.HasPrefix(csr.Subject.CommonName, "system:etcd-peer:") {
			return "", ErrInvalidCN
		}
		return etcdPeer, nil
	}
	if csr.Subject.Organization != nil && len(csr.Subject.Organization) == 1 && csr.Subject.Organization[0] == "system:etcd-servers" {
		if !strings.HasPrefix(csr.Subject.CommonName, "system:etcd-server:") {
			return "", ErrInvalidCN
		}
		return etcdServer, nil
	}
	return "", ErrInvalidOrg
}

// Sign uses the client to fetch the CSR from k8s API and uses the signer to sign the certificate.
func Sign(signer *CertSigner, client certificatesclient.CertificateSigningRequestInterface, name string) error {
	csr, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if approved, denied := util.GetCertApprovalCondition(&csr.Status); len(csr.Status.Certificate) > 0 || approved || denied {
		return fmt.Errorf("%s CSR seems to be already handled", name)
	}

	signed, err := signer.Sign(csr)
	if err != nil {
		if signed != nil {
			if _, denied := util.GetCertApprovalCondition(&signed.Status); denied {
				// Set denied condition.
				if _, err2 := client.UpdateApproval(signed); err2 != nil {
					return fmt.Errorf("error (%v) when updating CSR condition because sign failed %v", err2, err)
				}
			}
		}
		return err
	}

	// Sets the .status.certificate.
	rcvd, err := client.UpdateStatus(signed)
	if err != nil {
		return err
	}
	// Sets the approved condition.
	// set the conditions from signed to rvcd otherwise there will be conflict.
	rcvd.Status.Conditions = signed.Status.Conditions
	if _, err := client.UpdateApproval(rcvd); err != nil {
		return err
	}
	return nil
}
