package certsigner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"github.com/cloudflare/cfssl/log"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	capi "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes/scheme"
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

// ServerConfig holds the configuration values required to start a new signer server
type ServerConfig struct {
	Config
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
func NewServer(c ServerConfig) (*CertServer, error) {
	signer, err := NewSigner(c.Config)
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
func StartSignerServer(c ServerConfig) error {
	s, err := NewServer(c)
	if err != nil {
		return fmt.Errorf("error setting up signer: %v", err)
	}

	h := &loggingHandler{s.mux}
	return http.ListenAndServeTLS(c.ListenAddress, c.ServerCertFile, c.ServerKeyFile, h)
}
