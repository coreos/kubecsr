package certsigner

import (
	"crypto"
	"crypto/tls"
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
	etcdMetric = "EtcdMetric"
)

var (
	// defaultCertDuration is initialized to 365 days
	defaultCertDuration = 24 * 365 * time.Hour
	// ErrInvalidOrg defines a global error for invalid organization
	ErrInvalidOrg = errors.New("invalid organization")
	// ErrInvalidCN defines a global error for invalid subject common name
	ErrInvalidCN = errors.New("invalid subject Common Name")
	// ErrProfileSupport defines a global error for a profile which was not backed by a CA signer cert..
	ErrProfileSupport = errors.New("csr profile is not currently supported")
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
	// policy
	policy *config.Signing
	// caFiles
	caFiles *SignerCAFiles
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

// CertKey stores files for the cert and key pair.
type CertKey struct {
	CertFile, KeyFile string
}

// Config holds the configuration values required to start a new signer
type Config struct {
	// SignerCAFiles
	SignerCAFiles
	// ServerCertKeys is a list of server certificates for serving on TLS based on SNI
	ServerCertKeys []CertKey
	// ListenAddress is the address at which the server listens for requests
	ListenAddress string
	// InsecureHealthCheckAddress is the address at which the server listens for insecure health checks
	InsecureHealthCheckAddress string
	// EtcdMetricCertDuration
	EtcdMetricCertDuration time.Duration
	// EtcdPeerCertDuration is the cert duration for the `EtcdPeer` profile
	EtcdPeerCertDuration time.Duration
	// EtcdServerCertDuration is the cert duration for the `EtcdServer` profile
	EtcdServerCertDuration time.Duration
	// CSRDir is the directory location where the signer stores CSRs and serves them
	CSRDir string
}

// SignerCAFiles holds the file paths to the signer CA assets
type SignerCAFiles struct {
	// CACert is the file location of the Certificate Authority certificate
	CACert string
	// CAKey is the file location of the Certificate Authority private key
	CAKey string
	// MetricCACert is the file location of the metrics Certificate Authority certificate
	MetricCACert string
	// MetricCAKey is the file location of the metrics Certificate Authority private key
	MetricCAKey string
}

// SignerCA stores the PEM encoded cert and key blocks.
type SignerCA struct {
	// caCert is the x509 PEM encoded certificate of the CA used for the
	// cfssl signer
	caCert *x509.Certificate
	// caCert is the x509 PEM encoded private key of the CA used for the
	// cfssl signer
	caKey crypto.Signer
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
	policy := signerPolicy(c)
	mux := mux.NewRouter()
	server := &CertServer{
		mux:    mux,
		csrDir: c.CSRDir,
		policy: &policy,

		caFiles: &c.SignerCAFiles,
	}

	mux.HandleFunc("/apis/certificates.k8s.io/v1beta1/certificatesigningrequests", server.HandlePostCSR).Methods("POST")
	mux.HandleFunc("/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/{csrName}", server.HandleGetCSR).Methods("GET")
	mux.HandleFunc("/readyz", HandleHealthCheck).Methods("GET", "HEAD")

	return server, nil
}

func (s *CertServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// newSignerCA returns a SignerCA object of PEM encoded CA cert and keys based on the profile passed.
func newSignerCA(sc *SignerCAFiles, csr *capi.CertificateSigningRequest) (*SignerCA, error) {
	var caCert, caKey string

	profile, err := getProfile(csr)
	if err != nil {
		return nil, err
	}
	switch profile {
	case "EtcdMetric":
		if sc.MetricCAKey != "" && sc.MetricCACert != "" {
			caCert = sc.MetricCACert
			caKey = sc.MetricCAKey
			break
		}
		return nil, ErrProfileSupport
	case "EtcdServer", "EtcdPeer":
		if sc.CAKey != "" && sc.CACert != "" {
			caCert = sc.CACert
			caKey = sc.CAKey
			break
		}
		return nil, ErrProfileSupport
	default:
		return nil, ErrInvalidOrg
	}

	ca, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, fmt.Errorf("error reading CA cert file %q: %v", caCert, err)
	}
	cakey, err := ioutil.ReadFile(caKey)
	if err != nil {
		return nil, fmt.Errorf("error reading CA key file %q: %v", caKey, err)
	}
	parsedCA, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, fmt.Errorf("error parsing CA cert file %q: %v", caCert, err)
	}
	privateKey, err := helpers.ParsePrivateKeyPEM(cakey)
	if err != nil {
		return nil, fmt.Errorf("Malformed private key %v", err)
	}

	return &SignerCA{
		caCert: parsedCA,
		caKey:  privateKey,
	}, nil
}

// signerPolicy
func signerPolicy(c Config) config.Signing {
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
			etcdMetric: &config.SigningProfile{
				Usage: []string{
					string(capi.UsageKeyEncipherment),
					string(capi.UsageDigitalSignature),
					string(capi.UsageClientAuth),
					string(capi.UsageServerAuth),
				},
				Expiry:       c.EtcdMetricCertDuration,
				ExpiryString: c.EtcdMetricCertDuration.String(),
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

	return policy
}

// NewSigner returns a CertSigner object after filling in its attibutes
// from the `Config` provided.
func NewSigner(s *SignerCA, policy *config.Signing) (*CertSigner, error) {
	cfs, err := local.NewSigner(s.caKey, s.caCert, signer.DefaultSigAlgo(s.caKey), policy)
	if err != nil {
		return nil, fmt.Errorf("error setting up local cfssl signer: %v", err)
	}

	return &CertSigner{
		caCert:      s.caCert,
		caKey:       s.caKey,
		cfsslSigner: cfs,
	}, nil
}

// Sign sends a signature request to the local signer, receiving
// a signed certificate or an error in response. If successful, It
// then returns the CSR which contains the newly signed certificate.
//
// Note: A signed certificate is issued only for etcd profiles.
func (s *CertSigner) Sign(csr *capi.CertificateSigningRequest) (*capi.CertificateSigningRequest, error) {
	// the following step ensures that the signer server only signs CSRs from etcd nodes
	// that have a specific profile. All other requests are denied immediately.
	profile, err := getProfile(csr)
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
func getProfile(csr *capi.CertificateSigningRequest) (string, error) {
	x509CSR, err := csrutil.ParseCSR(csr)
	if err != nil {
		return "", fmt.Errorf("error parsing CSR, %v", err)
	}
	if err := x509CSR.CheckSignature(); err != nil {
		return "", fmt.Errorf("error validating signature of CSR: %v", err)
	}
	if x509CSR.Subject.Organization == nil || len(x509CSR.Subject.Organization) == 0 {
		return "", ErrInvalidOrg
	}

	org := x509CSR.Subject.Organization[0]
	cn := fmt.Sprintf(org[:len(org)-1]+"%s", ":")
	switch org {
	case "system:etcd-peers":
		if strings.HasPrefix(x509CSR.Subject.CommonName, cn) {
			return etcdPeer, nil
		}
		break
	case "system:etcd-servers":
		if strings.HasPrefix(x509CSR.Subject.CommonName, cn) {
			return etcdServer, nil
		}
		break
	case "system:etcd-metrics":
		if strings.HasPrefix(x509CSR.Subject.CommonName, cn) {
			return etcdMetric, nil
		}
		break
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

	signerCA, err := newSignerCA(s.caFiles, csr)
	if err != nil {
		glog.Errorf("Error signing CSR provided in request from agent: %v", err)
		http.Error(w, "Error signing csr", http.StatusBadRequest)
		return
	}

	signer, err := NewSigner(signerCA, s.policy)
	if err != nil {
		glog.Errorf("Error signing CSR provided in request from agent: %v", err)
		http.Error(w, "Error signing csr", http.StatusBadRequest)
		return
	}

	signedCSR, err := signer.Sign(csr)
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

// HandleHealthCheck handles health check
func HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

// StartSignerServer initializes a new signer instance.
func StartSignerServer(c Config) error {
	s, err := NewServer(c)
	if err != nil {
		return fmt.Errorf("error setting up signer: %v", err)
	}
	h := &loggingHandler{s.mux}

	certs := make([]tls.Certificate, len(c.ServerCertKeys))
	for idx, pair := range c.ServerCertKeys {
		certs[idx], err = tls.LoadX509KeyPair(pair.CertFile, pair.KeyFile)
		if err != nil {
			return fmt.Errorf("Failed to load key pair from (%q, %q): %v", pair.CertFile, pair.KeyFile, err)
		}
	}
	tlsconfig := &tls.Config{
		Certificates: certs,
	}
	tlsconfig.BuildNameToCertificate()

	// start insecure health check server
	insecureHCMux := mux.NewRouter()
	insecureHCMux.HandleFunc("/readyz", HandleHealthCheck).Methods("GET", "HEAD")
	go (&http.Server{
		Handler: &loggingHandler{insecureHCMux},
		Addr:    c.InsecureHealthCheckAddress,
	}).ListenAndServe()

	return (&http.Server{
		TLSConfig: tlsconfig,
		Handler:   h,
		Addr:      c.ListenAddress,
	}).ListenAndServeTLS("", "")
}
