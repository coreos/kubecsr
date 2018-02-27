package certsigner

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	capi "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes/scheme"
	csrutil "k8s.io/client-go/util/certificate/csr"
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

// CertServer is the object that handles the HTTP requests and responses.
// It recieves CSR approval requests from the client agent which the `signer`
// then attempts to sign. If successful, the approved CSR is returned to the
// agent which contains the signed certificate.
type CertServer struct {
	// mux is a request router instance
	mux *mux.Router
	// csrDir is the directory location where the signer stores CSRs
	csrDir string
	// signer is the object that handles the approval of the CSRs
	signer *CertSigner
}

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
	// CSRDir is the directory location where the signer stores CSRs and serves them
	CSRDir string
}

// loggingHandler is the HTTP handler that logs information about requests received by the server
type loggingHandler struct {
	h http.Handler
}

func (l *loggingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Info(r.Method, r.URL.Path)
	l.h.ServeHTTP(w, r)
}

// NewServer returns a CertServer object that has a CertSigner object
// as a part of it
func NewServer(c Config) (*CertServer, error) {
	signer, err := NewSigner(c)
	if err != nil {
		return nil, fmt.Errorf("error setting up a signer: %v", err)
	}

	mux := mux.NewRouter()
	server := &CertServer{
		mux:    mux,
		csrDir: c.CSRDir,
		signer: signer,
	}

	mux.HandleFunc("/apis/certificates.k8s.io/v1beta1/certificatesigningrequests", server.HandlePostCSR).Methods("POST")
	mux.HandleFunc("/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/{csrName}", server.HandleGetCSR).Methods("GET")

	return server, nil
}

func (s *CertServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
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

// HandlePostCSR takes in a CSR, attempts to approve it and writes the CSR
// to a file in the `csrDir`.
// It returns a `http.StatusOK` to the client if the recieved CSR can
// be sucessfully decoded.
func (s *CertServer) HandlePostCSR(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		glog.Errorf("Error reading request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, nil)
	if err != nil {
		glog.Errorf("Error decoding request body: %v", err)
		http.Error(w, "Failed to decode request body", http.StatusInternalServerError)
		return
	}

	csr, ok := obj.(*capi.CertificateSigningRequest)
	if !ok {
		glog.Errorf("Invalid Certificate Signing Request in request from agent: %v", err)
		http.Error(w, "Invalid Certificate Signing Request", http.StatusBadRequest)
		return
	}

	signedCSR, err := s.signer.Sign(csr)
	if err != nil {
		glog.Errorf("Error signing CSR provided in request from agent: %v", err)
		http.Error(w, "Error signing csr", http.StatusBadRequest)
		return
	}

	csrBytes, err := json.Marshal(signedCSR)
	if err != nil {
		glog.Errorf("Error marshalling approved CSR: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// write CSR to disk which will then be served to the agent.
	csrFile := path.Join(s.csrDir, signedCSR.ObjectMeta.Name)
	if err := ioutil.WriteFile(csrFile, csrBytes, 0600); err != nil {
		glog.Errorf("Unable to write to %s: %v", csrFile, err)
	}

	// Send the signed CSR back to the client agent
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(csrBytes)

	return
}

// HandleGetCSR retrieves a CSR from a directory location (`csrDir`) and returns it
// to an agent.
func (s *CertServer) HandleGetCSR(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	csrName := vars["csrName"]

	if _, err := os.Stat(filepath.Join(s.csrDir, csrName)); os.IsNotExist(err) {
		// csr file does not exist in `csrDir`
		http.Error(w, "CSR not found with given CSR name"+csrName, http.StatusNotFound)
		return
	}

	data, err := ioutil.ReadFile(filepath.Join(s.csrDir, csrName))
	if err != nil {
		http.Error(w, "error reading CSR from file", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
	return
}

// StartSignerServer initializes a new signer instance.
func StartSignerServer(c Config) error {
	s, err := NewServer(c)
	if err != nil {
		return fmt.Errorf("error setting up signer: %v", err)
	}

	h := &loggingHandler{s.mux}
	return http.ListenAndServeTLS(c.ListenAddress, c.ServerCertFile, c.ServerKeyFile, h)
}
