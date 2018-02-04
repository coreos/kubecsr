package approver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider"
	fakecloud "github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider/providers/fake"
	"github.com/golang/mock/gomock"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/util/sets"
	fakeclient "k8s.io/client-go/kubernetes/fake"
	testclient "k8s.io/client-go/testing"
	csrutil "k8s.io/client-go/util/certificate/csr"
)

func TestHandle(t *testing.T) {
	cases := []struct {
		cb     func(b *csrBuilder)
		verify func(*testing.T, []testclient.Action)
	}{{
		cb: func(b *csrBuilder) {
			b.cn = "worker-evil"
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
	}, {
		cb: func(b *csrBuilder) {
			b.cn = "system:node:worker-1"
			b.requestorGroups = []string{"system:bootstrappers:ingress"}
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
	}, {
		cb: func(b *csrBuilder) {
			b.cn = "system:node:evil"
			b.requestorGroups = []string{"system:bootstrappers:master"}
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
	}, {
		cb: func(b *csrBuilder) {
			b.cn = "system:node:master-1"
			b.requestor = "system:node:master-1"
			b.requestorGroups = []string{"system:bootstrappers:master"}
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected one calls but got: %#v", as)
			}

			a := as[0].(testclient.UpdateActionImpl)
			if got, expected := a.Verb, "update"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1beta1", Resource: "certificatesigningrequests"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Subresource, "approval"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			csr := a.Object.(*certificates.CertificateSigningRequest)
			if len(csr.Status.Conditions) != 1 {
				t.Errorf("expected CSR to have approved condition: %#v", csr)
			}
			c := csr.Status.Conditions[0]
			if got, expected := c.Type, certificates.CertificateApproved; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := c.Reason, "AutoApproved"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := c.Message, "node-csr-approver auto approved self client cert for master"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
	}, {
		cb: func(b *csrBuilder) {
			b.cn = "system:node:master-1"
			b.requestor = "system:node:token"
			b.requestorGroups = []string{"system:bootstrappers:master"}
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected one calls but got: %#v", as)
			}

			a := as[0].(testclient.UpdateActionImpl)
			if got, expected := a.Verb, "update"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1beta1", Resource: "certificatesigningrequests"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Subresource, "approval"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			csr := a.Object.(*certificates.CertificateSigningRequest)
			if len(csr.Status.Conditions) != 1 {
				t.Errorf("expected CSR to have approved condition: %#v", csr)
			}
			c := csr.Status.Conditions[0]
			if got, expected := c.Type, certificates.CertificateApproved; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := c.Reason, "AutoApproved"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := c.Message, "node-csr-approver auto approved client cert for master"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
	}, {
		cb: func(b *csrBuilder) {
			b.cn = "system:node:worker-1"
			b.requestor = "system:node:worker-1"
			b.requestorGroups = []string{"system:bootstrappers:worker"}
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected one calls but got: %#v", as)
			}

			a := as[0].(testclient.UpdateActionImpl)
			if got, expected := a.Verb, "update"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1beta1", Resource: "certificatesigningrequests"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Subresource, "approval"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			csr := a.Object.(*certificates.CertificateSigningRequest)
			if len(csr.Status.Conditions) != 1 {
				t.Errorf("expected CSR to have approved condition: %#v", csr)
			}
			c := csr.Status.Conditions[0]
			if got, expected := c.Type, certificates.CertificateApproved; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := c.Reason, "AutoApproved"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := c.Message, "node-csr-approver auto approved self client cert for worker"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
	}, {
		cb: func(b *csrBuilder) {
			b.cn = "system:node:worker-1"
			b.requestor = "system:node:token"
			b.requestorGroups = []string{"system:bootstrappers:worker"}
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected one calls but got: %#v", as)
			}

			a := as[0].(testclient.UpdateActionImpl)
			if got, expected := a.Verb, "update"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1beta1", Resource: "certificatesigningrequests"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Subresource, "approval"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			csr := a.Object.(*certificates.CertificateSigningRequest)
			if len(csr.Status.Conditions) != 1 {
				t.Errorf("expected CSR to have approved condition: %#v", csr)
			}
			c := csr.Status.Conditions[0]
			if got, expected := c.Type, certificates.CertificateApproved; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := c.Reason, "AutoApproved"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := c.Message, "node-csr-approver auto approved client cert for worker"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
	}}
	for idx, c := range cases {
		t.Run(fmt.Sprintf("test #%d", idx), func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			client := &fakeclient.Clientset{}
			cloud := fakecloud.NewFake(mockCtrl)

			nodetogroup := map[string]string{
				"master-1": "asg-master-1",
				"master-2": "asg-master-2",
				"worker-1": "asg-worker-1",
				"worker-2": "asg-worker-2",
				"evil":     "evil-asg",
			}
			for k, v := range nodetogroup {
				cloud.EXPECT().GetInstanceGroupByNodeName(k).Return(v, nil).AnyTimes()
			}
			ar := &Approver{
				kubeClient:  client,
				cloud:       cloud,
				MasterGroup: sets.NewString("asg-master-1", "asg-master-2"),
				WorkerGroup: sets.NewString("asg-worker-1", "asg-worker-2"),
			}

			b := csrBuilder{
				cn:        "system:node:foo",
				orgs:      []string{"system:nodes"},
				requestor: "system:node:foo",
				usages: []certificates.KeyUsage{
					certificates.UsageKeyEncipherment,
					certificates.UsageDigitalSignature,
					certificates.UsageClientAuth,
				},
			}
			c.cb(&b)
			csr := makeTestCsr(b)
			if err := ar.handle(csr); err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			c.verify(t, client.Actions())
		})
	}
}

func TestHasKubeletUsages(t *testing.T) {
	cases := []struct {
		usages   []certificates.KeyUsage
		expected bool
	}{
		{
			usages:   nil,
			expected: false,
		},
		{
			usages:   []certificates.KeyUsage{},
			expected: false,
		},
		{
			usages: []certificates.KeyUsage{
				certificates.UsageKeyEncipherment,
				certificates.UsageDigitalSignature,
			},
			expected: false,
		},
		{
			usages: []certificates.KeyUsage{
				certificates.UsageKeyEncipherment,
				certificates.UsageDigitalSignature,
				certificates.UsageServerAuth,
			},
			expected: false,
		},
		{
			usages: []certificates.KeyUsage{
				certificates.UsageKeyEncipherment,
				certificates.UsageDigitalSignature,
				certificates.UsageClientAuth,
			},
			expected: true,
		},
	}
	for _, c := range cases {
		if hasExactUsages(&certificates.CertificateSigningRequest{
			Spec: certificates.CertificateSigningRequestSpec{
				Usages: c.usages,
			},
		}, kubeletClientUsages) != c.expected {
			t.Errorf("unexpected result of hasKubeletUsages(%v), expecting: %v", c.usages, c.expected)
		}
	}
}

func TestRecognizers(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	client := &fakeclient.Clientset{}
	cloud := fakecloud.NewFake(mockCtrl)

	nodetogroup := map[string]string{
		"master-1": "asg-master-1",
		"master-2": "asg-master-2",
		"worker-1": "asg-worker-1",
		"worker-2": "asg-worker-2",
		"evil":     "evil-asg",
	}
	for k, v := range nodetogroup {
		cloud.EXPECT().GetInstanceGroupByNodeName(k).Return(v, nil).AnyTimes()
	}
	cloud.EXPECT().GetInstanceGroupByNodeName("unknown").Return("", cloudprovider.ErrInstanceGroupNotFound).AnyTimes()

	ar := &Approver{
		kubeClient:  client,
		cloud:       cloud,
		MasterGroup: sets.NewString("asg-master-1", "asg-master-2"),
		WorkerGroup: sets.NewString("asg-worker-1", "asg-worker-2"),
	}

	cases := []struct {
		cbs     []func(b *csrBuilder)
		r       recognizerFunc
		success bool
	}{{
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
			},
		},
		r:       isNodeClientCert,
		success: true,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
			},
		},
		r:       isSelfNodeClientCert,
		success: true,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.cn = "mike"
			},
			func(b *csrBuilder) {
				b.orgs = nil
			},
			func(b *csrBuilder) {
				b.orgs = []string{"system:master"}
			},
			func(b *csrBuilder) {
				b.usages = append(b.usages, certificates.UsageServerAuth)
			},
		},
		r:       isNodeClientCert,
		success: false,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.cn = "mike"
			},
			func(b *csrBuilder) {
				b.orgs = nil
			},
			func(b *csrBuilder) {
				b.orgs = []string{"system:master"}
			},
			func(b *csrBuilder) {
				b.usages = append(b.usages, certificates.UsageServerAuth)
			},
		},
		r:       isSelfNodeClientCert,
		success: false,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.requestor = "joe"
			},
			func(b *csrBuilder) {
				b.cn = "system:node:bar"
			},
		},
		r:       isNodeClientCert,
		success: true,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.requestor = "joe"
			},
			func(b *csrBuilder) {
				b.cn = "system:node:bar"
			},
		},
		r:       isSelfNodeClientCert,
		success: false,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.requestorGroups = []string{"system:bootstrappers:master"}
			},
		},
		r:       isRequestingMaster,
		success: true,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.requestorGroups = []string{"system:bootstrappers:worker"}
			},
			func(b *csrBuilder) {
				b.requestorGroups = []string{"system:bootstrappers:node"}
			},
		},
		r:       isRequestingMaster,
		success: false,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.requestorGroups = []string{"system:bootstrappers:worker"}
			},
		},
		r:       isRequestingWorker,
		success: true,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.requestorGroups = []string{"system:bootstrappers:master"}
			},
			func(b *csrBuilder) {
				b.requestorGroups = []string{"system:bootstrappers:node"}
			},
		},
		r:       isRequestingWorker,
		success: false,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.cn = "system:node:master-1"
			},
			func(b *csrBuilder) {
				b.cn = "system:node:master-2"
			},
		},
		r:       ar.isValidMaster,
		success: true,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.cn = "system:node:worker-1"
			},
			func(b *csrBuilder) {
				b.cn = "system:node:evil"
			},
			func(b *csrBuilder) {
				b.cn = "system:node:unknown"
			},
		},
		r:       ar.isValidMaster,
		success: false,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.cn = "system:node:worker-1"
			},
			func(b *csrBuilder) {
				b.cn = "system:node:worker-2"
			},
		},
		r:       ar.isValidWorker,
		success: true,
	}, {
		cbs: []func(b *csrBuilder){
			func(b *csrBuilder) {
				b.cn = "system:node:master-1"
			},
			func(b *csrBuilder) {
				b.cn = "system:node:evil"
			},
			func(b *csrBuilder) {
				b.cn = "system:node:unknown"
			},
		},
		r:       ar.isValidWorker,
		success: false,
	}}

	for idx1, c := range cases {
		for idx2, cb := range c.cbs {
			b := csrBuilder{
				cn:        "system:node:foo",
				orgs:      []string{"system:nodes"},
				requestor: "system:node:foo",
				usages: []certificates.KeyUsage{
					certificates.UsageKeyEncipherment,
					certificates.UsageDigitalSignature,
					certificates.UsageClientAuth,
				},
			}
			cb(&b)
			t.Run(fmt.Sprintf("test #%d.%d", idx1, idx2), func(t *testing.T) {
				csr := makeTestCsr(b)
				x509cr, err := csrutil.ParseCSR(csr)
				if err != nil {
					t.Errorf("unexpected err: %v", err)
				}
				if c.r(csr, x509cr) != c.success {
					t.Errorf("expected recognized to be %v", c.success)
				}
			})
		}

	}
}

type csrBuilder struct {
	cn              string
	orgs            []string
	requestor       string
	requestorGroups []string
	usages          []certificates.KeyUsage
	dns             []string
	emails          []string
	ips             []net.IP
}

func makeTestCsr(b csrBuilder) *certificates.CertificateSigningRequest {
	random := rand.Reader
	pk, err := ecdsa.GenerateKey(elliptic.P224(), random)
	if err != nil {
		panic(err)
	}
	csrb, err := x509.CreateCertificateRequest(random, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   b.cn,
			Organization: b.orgs,
		},
		DNSNames:       b.dns,
		EmailAddresses: b.emails,
		IPAddresses:    b.ips,
	}, pk)
	if err != nil {
		panic(err)
	}
	return &certificates.CertificateSigningRequest{
		Spec: certificates.CertificateSigningRequestSpec{
			Username: b.requestor,
			Groups:   b.requestorGroups,
			Usages:   b.usages,
			Request:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrb}),
		},
	}
}
