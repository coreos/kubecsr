package approver

import (
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"

	"github.com/golang/glog"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/util/sets"

	csrutil "k8s.io/client-go/util/certificate/csr"
)

const (
	masterRoleAuthencationGroup = "system:bootstrappers:master"
	workerRoleAuthencationGroup = "system:bootstrappers:worker"
)

func (ar *Approver) handle(csr *certificates.CertificateSigningRequest) error {
	glog.V(4).Infof("handle: csr %v", csr)
	if len(csr.Status.Certificate) != 0 {
		return nil
	}

	if approved, denied := getCertApprovalCondition(&csr.Status); approved || denied {
		return nil
	}

	x509cr, err := csrutil.ParseCSR(csr)
	if err != nil {
		return err
	}

	glog.V(4).Infof("handle: running recognizers on %s", csr.GetName())
	csrrs := ar.recognizers()
	for _, csrr := range csrrs {
		rs := csrr.recognizers
		approved := true
		for _, r := range rs {
			if !r(csr, x509cr) {
				approved = false
				break
			}
		}
		if !approved {
			continue
		}

		glog.V(4).Infof("csr %s was approved! message: %s", csr.GetName(), csrr.successMessage)
		csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{
			Type:    certificates.CertificateApproved,
			Reason:  "AutoApproved",
			Message: csrr.successMessage,
		})
		_, err = ar.kubeClient.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(csr)
		if err != nil {
			return fmt.Errorf("error updating approval for csr: %v", err)
		}
		break
	}

	return nil
}

type recognizerFunc func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool
type csrRecognizer struct {
	recognizers    []recognizerFunc
	successMessage string
}

func (ar *Approver) recognizers() []csrRecognizer {
	return []csrRecognizer{{
		recognizers:    []recognizerFunc{isSelfNodeClientCert, isRequestingMaster, ar.isValidMaster},
		successMessage: "node-csr-approver auto approved self client cert for master",
	}, {
		recognizers:    []recognizerFunc{isSelfNodeClientCert, isRequestingWorker, ar.isValidWorker},
		successMessage: "node-csr-approver auto approved self client cert for worker",
	}, {
		recognizers:    []recognizerFunc{isNodeClientCert, isRequestingMaster, ar.isValidMaster},
		successMessage: "node-csr-approver auto approved client cert for master",
	}, {
		recognizers:    []recognizerFunc{isNodeClientCert, isRequestingWorker, ar.isValidWorker},
		successMessage: "node-csr-approver auto approved client cert for worker",
	}}
}

func (ar *Approver) isValidMaster(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	nodeName := strings.TrimPrefix(x509cr.Subject.CommonName, "system:node:")
	asg, err := ar.cloud.GetInstanceGroupByNodeName(nodeName)
	if err != nil {
		return false
	}
	return ar.MasterGroup.Has(asg)
}

func (ar *Approver) isValidWorker(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	nodeName := strings.TrimPrefix(x509cr.Subject.CommonName, "system:node:")
	asg, err := ar.cloud.GetInstanceGroupByNodeName(nodeName)
	if err != nil {
		return false
	}
	return ar.WorkerGroup.Has(asg)
}

func isRequestingMaster(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	gset := sets.NewString(csr.Spec.Groups...)
	return gset.Has(masterRoleAuthencationGroup)
}

func isRequestingWorker(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	gset := sets.NewString(csr.Spec.Groups...)
	return gset.Has(workerRoleAuthencationGroup)
}

func isNodeClientCert(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if !reflect.DeepEqual([]string{"system:nodes"}, x509cr.Subject.Organization) {
		return false
	}
	if (len(x509cr.DNSNames) > 0) || (len(x509cr.EmailAddresses) > 0) || (len(x509cr.IPAddresses) > 0) {
		return false
	}
	if !hasExactUsages(csr, kubeletClientUsages) {
		return false
	}
	if !strings.HasPrefix(x509cr.Subject.CommonName, "system:node:") {
		return false
	}
	return true
}

func isSelfNodeClientCert(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if !isNodeClientCert(csr, x509cr) {
		return false
	}
	if csr.Spec.Username != x509cr.Subject.CommonName {
		return false
	}
	return true
}

func getCertApprovalCondition(status *certificates.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == certificates.CertificateApproved {
			approved = true
		}
		if c.Type == certificates.CertificateDenied {
			denied = true
		}
	}
	return
}

var kubeletClientUsages = []certificates.KeyUsage{
	certificates.UsageKeyEncipherment,
	certificates.UsageDigitalSignature,
	certificates.UsageClientAuth,
}

func hasExactUsages(csr *certificates.CertificateSigningRequest, usages []certificates.KeyUsage) bool {
	if len(usages) != len(csr.Spec.Usages) {
		return false
	}

	usageMap := map[certificates.KeyUsage]struct{}{}
	for _, u := range usages {
		usageMap[u] = struct{}{}
	}

	for _, u := range csr.Spec.Usages {
		if _, ok := usageMap[u]; !ok {
			return false
		}
	}

	return true
}
