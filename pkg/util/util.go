package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path"

	capi "k8s.io/api/certificates/v1beta1"
)

// IsCertificateRequestApproved returns true if a certificate request has the
// "Approved" condition and no "Denied" conditions; false otherwise.
func IsCertificateRequestApproved(csr *capi.CertificateSigningRequest) bool {
	approved, denied := GetCertApprovalCondition(&csr.Status)
	return approved && !denied
}

// GetCertApprovalCondition returns both the approved status and denied status of the certificate request
func GetCertApprovalCondition(status *capi.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == capi.CertificateApproved {
			approved = true
		}
		if c.Type == capi.CertificateDenied {
			denied = true
		}
	}
	return
}

// GeneratePrivateKey returns a PEM encoded Private Key byte stream of
// an RSA 2048 bit size key and writes it to file in the `assetsDir`.
func GeneratePrivateKey(assetsDir, fileName string) ([]byte, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pemKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	})

	keyFile := path.Join(assetsDir, fileName+".key")
	if err := ioutil.WriteFile(keyFile, pemKeyBytes, 0600); err != nil {
		return nil, fmt.Errorf("unable to write to %s: %v", keyFile, err)
	}
	return pemKeyBytes, nil
}
