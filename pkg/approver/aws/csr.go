package aws

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/golang/glog"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	csrutil "k8s.io/client-go/util/certificate/csr"
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
			if rerr := r(csr, x509cr); err != nil {
				glog.V(4).Infof("handle: %v", rerr)
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

type recognizerFunc func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error
type csrRecognizer struct {
	recognizers    []recognizerFunc
	successMessage string
}

func (ar *Approver) recognizers() []csrRecognizer {
	return []csrRecognizer{{
		// ensures: node present their client cert, exist(running) in cluster, belong to whitelist of ASGs.
		recognizers:    []recognizerFunc{isSelfNodeClientCert, ar.isValidNode(ar.aws.instanceID), ar.isValidASG(ar.aws.autoScalingGroupID)},
		successMessage: "kube-aws-approver approved self node client cert",
	}, {
		// ensures: node username has instance-id, presented instance-id match instance-id by aws for node name in running state, doesn't belong to cluster, belong to whitelist of ASGs.
		recognizers:    []recognizerFunc{isNodeClientCert, ar.isValidNewNode(ar.aws.instanceID), ar.isValidASG(ar.aws.autoScalingGroupID)},
		successMessage: "kube-aws-approver approved new node client cert",
	}}
}

// isNodeClientCert checks if
// - x509.CertificateRequest Organization is equal to system:nodes
// - x509.CertificateRequest DNSNames list is empty
// - x509.CertificateRequest EmailAddresses list is empty
// - x509.CertificateRequest IPAddresses list is empty
// - x509.CertificateRequest CommonName has 'system:node:' prefix
// - CertificateSigningRequest Username has 'system:bootstrappers:' prefix
// - CertificateSigningRequest has valid client key usages. (https://github.com/kubernetes/client-go/blob/7cd1d3291b7d9b1e2d54d4b69eb65995eaf8888e/util/certificate/csr/csr.go#L66-L70)
// upstream: https://github.com/kubernetes/kubernetes/blob/7488d1c9210e60aef9ad49f07cb5d8a24152db88/pkg/controller/certificates/approver/sarapprove.go#L179
// Returns nil when conditions met.
func isNodeClientCert(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
	if x509cr.Subject.Organization != nil && len(x509cr.Subject.Organization) != 1 && x509cr.Subject.Organization[0] != "system:nodes" {
		return fmt.Errorf("isNodeClientCert: error mismatch org")
	}
	if (len(x509cr.DNSNames) > 0) || (len(x509cr.EmailAddresses) > 0) || (len(x509cr.IPAddresses) > 0) {
		return fmt.Errorf("isNodeClientCert: error non empty dnsnames/emailaddress/ipaddress")
	}
	if !hasExactUsages(csr, kubeletClientUsages) {
		return fmt.Errorf("isNodeClientCert: error invalid key usages")
	}
	if !strings.HasPrefix(x509cr.Subject.CommonName, "system:node:") {
		return fmt.Errorf("isNodeClientCert: error common name doesn't have system:node: prefix")
	}
	return nil
}

// isSelfNodeClientCert checks if
// - CertificateSigningRequest is valid isNodeClientCert
// - CertificateSigningRequest username matches the CertificateRequest CommonName, i.e. the node provided its client cert to create this CertificateSigningRequest.
// upstream: https://github.com/kubernetes/kubernetes/blob/7488d1c9210e60aef9ad49f07cb5d8a24152db88/pkg/controller/certificates/approver/sarapprove.go#L195
// Returns nil when conditions met.
func isSelfNodeClientCert(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
	if err := isNodeClientCert(csr, x509cr); err != nil {
		return err
	}
	if csr.Spec.Username != x509cr.Subject.CommonName {
		return fmt.Errorf("isSelfNodeClientCert: error mismatch Username and CommonName")
	}
	return nil
}

type instanceIDFunc func(nodeName string) (string, error)

// isValidNewNode checks if
// - CertificateSigningRequest groups has system:bootstrappers
// - there exists a valid instance corresponding to the nodename from CertificateRequest
// - instance-id from CertificateSigningRequest username matches the instance-id from AWS for nodename in CertificateRequest
// - node with nodename from CertificateRequest is not already part of the cluster
// Returns nil when conditions met.
func (ar *Approver) isValidNewNode(f instanceIDFunc) recognizerFunc {
	return func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
		gset := sets.NewString(csr.Spec.Groups...)
		if !gset.Has("system:bootstrappers") {
			return fmt.Errorf("isValidNewNode: error system:bootstrapper doesn't exist in groups")
		}

		idu, err := getInstanceIDFromUsername(csr.Spec.Username)
		if err != nil {
			return fmt.Errorf("isValidNewNode: error getting id from username: %v", err)
		}

		nn, err := getNodeNameFromCN(x509cr.Subject.CommonName)
		if err != nil {
			return fmt.Errorf("isValidNewNode: error getting node name from common name: %v", err)
		}

		idn, err := f(nn)
		if err != nil {
			return fmt.Errorf("isValidNewNode: error getting instance id for %s: %v", nn, err)
		}

		if idn != idu {
			return fmt.Errorf("isValidNewNode: error mismatch instance id from Username and CommonName")
		}

		_, err = ar.kubeClient.CoreV1().Nodes().Get(nn, metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("isValidNewNode: error expecting node not found, got: %v", err)
		}

		return nil
	}

}

// isValidNode checks if
// - CertificateSigningRequest groups has system:nodes
// - there exists a valid instance corresponding to the nodename from CertificateRequest
// - node with nodename from CertificateRequest is part of the cluster and ready.
// Returns nil when conditions met.
func (ar *Approver) isValidNode(f instanceIDFunc) recognizerFunc {
	return func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
		gset := sets.NewString(csr.Spec.Groups...)
		if !gset.Has("system:nodes") {
			return fmt.Errorf("isValidNewNode: error system:nodes doesn't exist in groups")
		}

		nn, err := getNodeNameFromCN(x509cr.Subject.CommonName)
		if err != nil {
			return fmt.Errorf("isValidNewNode: error getting node name from common name: %v", err)
		}

		_, err = f(nn)
		if err != nil {
			return fmt.Errorf("isValidNode: error getting instance id for %s: %v", nn, err)
		}

		node, err := ar.kubeClient.CoreV1().Nodes().Get(nn, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("isValidNode: error getting node %s: %v", nn, err)
		}
		for _, cond := range node.Status.Conditions {
			if cond.Type == v1.NodeReady {
				if cond.Status == v1.ConditionTrue {
					return nil
				}
			}
		}
		return fmt.Errorf("isValidNode: expecting node %s status to be ready, it is not ready", nn)
	}
}

type autoScalingGroupIDFunc func(nodeName string) (string, error)

// isValidASG checks if
// - there exists a valid ASG corresponding to the nodename from CertificateRequest
// - ASG for nodename extracted from AWS belongs to the whitelist
// Returns nil when conditions met.
func (ar *Approver) isValidASG(f autoScalingGroupIDFunc) recognizerFunc {
	return func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
		nn, err := getNodeNameFromCN(x509cr.Subject.CommonName)
		if err != nil {
			return fmt.Errorf("isValidASG: error getting node name from common name: %v", err)
		}

		asg, err := f(nn)
		if err != nil {
			return fmt.Errorf("isValidASG: error getting auto scaling group for node %s: %v", nn, err)
		}

		if !ar.allowedASGs.Has(asg) {
			return fmt.Errorf("isValidASG: node %s from invalid asg %s", nn, asg)
		}
		return nil
	}
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

// getNodeNameFromCN extracts the nodename from CertificateRequest CommonName
// It expects the CommonName to be of the form 'system:node:<nodename>'
func getNodeNameFromCN(cn string) (string, error) {
	nn := strings.TrimPrefix(cn, "system:node:")
	if nn == cn {
		return "", fmt.Errorf("error system:node: prefix not found")
	}
	return nn, nil
}

// getInstanceIDFromUsername extracts the instance-id from CertificateSigningRequest Username
// It expects the Username to be of the form 'system:boostrappers:<instanceid>'
func getInstanceIDFromUsername(username string) (string, error) {
	id := strings.TrimPrefix(username, "system:bootstrappers:")
	if id == username {
		return "", fmt.Errorf("error system:bootstrappers: prefix not found")
	}
	return id, nil
}
