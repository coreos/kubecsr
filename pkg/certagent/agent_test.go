package certagent

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	certutil "k8s.io/client-go/util/cert"
)

var (
	cConfig = CSRConfig{
		DNSNames:      []string{"localhost"},
		IPAddresses:   []net.IP{net.ParseIP("127.0.0.1")},
		OrgName:       "system:etcd-peers",
		CommonName:    "system:etcd-peer:test",
		SignerAddress: "http://127.0.0.1:6443",
		AssetsDir:     ".",
	}
)

// TODO: add more unit tests to check agent specific behavior (response handling, etc)
// remove external dependencies (files on disk, network interface, etc)
func TestGenerateCSRObject(t *testing.T) {
	generatedCSR, err := GenerateCSRObject(cConfig)
	if err != nil {
		t.Fatalf("error generating CSR object: %v", err)
	}

	csrPEM := generatedCSR.Spec.Request
	if len(csrPEM) == 0 {
		t.Fatal("no certificate request found in CSR Spec")
	}

	csrBlock, rest := pem.Decode(csrPEM)
	if csrBlock == nil {
		t.Fatal("error decoding certificate request generated.")
	}

	if len(rest) != 0 {
		t.Error("found more than one PEM encoded block in certificate request")
	}

	if csrBlock.Type != certutil.CertificateRequestBlockType {
		t.Errorf("found block type %q, wanted 'CERTIFICATE REQUEST'", csrBlock.Type)
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("error parsing certificate request: %v", err)
	}

	if csr.Subject.CommonName != cConfig.CommonName {
		t.Errorf("CommonName mismatch. Wanted %v, got %v", cConfig.CommonName, csr.Subject.CommonName)
	}

	if len(csr.DNSNames) != 1 {
		t.Errorf("expected 1 DNS name in the result, got %d", len(csr.DNSNames))
	} else if csr.DNSNames[0] != cConfig.DNSNames[0] {
		t.Errorf("DNSName mismatch. Wanted %v, got %v", cConfig.DNSNames[0], csr.DNSNames[0])
	}

	if len(csr.IPAddresses) != 1 {
		t.Errorf("expected 1 IP address in the result, got %d", len(csr.IPAddresses))
	} else if csr.IPAddresses[0].String() != cConfig.IPAddresses[0].String() {
		t.Errorf("IPAddress mismatch. Wanted %v, got %v", cConfig.IPAddresses[0], csr.IPAddresses[0])
	}
}
