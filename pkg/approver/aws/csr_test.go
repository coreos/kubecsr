package aws

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

	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"
	testclient "k8s.io/client-go/testing"
	csrutil "k8s.io/client-go/util/certificate/csr"
)

func TestHasKubeletUsages(t *testing.T) {
	cases := []struct {
		usages   []certificates.KeyUsage
		expected bool
	}{{
		usages:   nil,
		expected: false,
	}, {
		usages:   []certificates.KeyUsage{},
		expected: false,
	}, {
		usages: []certificates.KeyUsage{
			certificates.UsageKeyEncipherment,
			certificates.UsageDigitalSignature,
		},
		expected: false,
	}, {
		usages: []certificates.KeyUsage{
			certificates.UsageKeyEncipherment,
			certificates.UsageDigitalSignature,
			certificates.UsageServerAuth,
		},
		expected: false,
	}, {
		usages: []certificates.KeyUsage{
			certificates.UsageKeyEncipherment,
			certificates.UsageDigitalSignature,
			certificates.UsageClientAuth,
		},
		expected: true,
	}}
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

func TestClientCert(t *testing.T) {
	cases := []struct {
		cbm func(b *csrBuilder)
		r   recognizerFunc
		err bool
	}{{
		cbm: func(b *csrBuilder) {},
		r:   isNodeClientCert,
		err: false,
	}, {
		cbm: func(b *csrBuilder) {},
		r:   isSelfNodeClientCert,
		err: false,
	}, {
		cbm: func(b *csrBuilder) {
			b.orgs = nil
		},
		r:   isNodeClientCert,
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.orgs = []string{"system:master"}
		},
		r:   isNodeClientCert,
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.dns = []string{"test-dns"}
		},
		r:   isNodeClientCert,
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.emails = []string{"test@test.com"}
		},
		r:   isNodeClientCert,
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "test"
		},
		r:   isNodeClientCert,
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = ""
		},
		r:   isNodeClientCert,
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.usages = append(b.usages, certificates.UsageServerAuth)
		},
		r:   isNodeClientCert,
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "system:node:testnode"
			b.requestor = "system:random-user"
		},
		r:   isSelfNodeClientCert,
		err: true,
	}}
	for idx, c := range cases {
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
		c.cbm(&b)
		t.Run(fmt.Sprintf("test #%d", idx), func(t *testing.T) {
			csr := makeTestCSR(t, b)
			x509cr, err := csrutil.ParseCSR(csr)
			if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			err = c.r(csr, x509cr)
			if err != nil && !c.err {
				t.Errorf("expected err: %v got:%v", c.err, err)
			}
		})
	}
}

func TestIsValidNewNode(t *testing.T) {
	nodetoid := map[string]string{
		"valid-node":   "id-1",
		"another-node": "id-2",
	}
	cases := []struct {
		cbm    func(b *csrBuilder)
		react  testclient.ReactionFunc
		verify func(*testing.T, []testclient.Action)
		err    bool
	}{{
		cbm: func(b *csrBuilder) {
			b.requestorGroups = []string{"evil:group"}
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.requestor = "system:master"
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "random"
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "system:node:random-node"
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "system:node:valid-node"
			b.requestor = "system:node:id-x"
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {},
		react: func(action testclient.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, apierrors.NewInternalError(fmt.Errorf("dummy error"))
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected 1 client calls but got: %#v", as)
			}

			a := as[0].(testclient.GetActionImpl)
			if got, expected := a.Verb, "get"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Name, "valid-node"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "system:node:another-node"
			b.requestor = "system:bootstrappers:id-2"
		},
		react: func(action testclient.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "another-node",
				},
			}, nil
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected 1 client calls but got: %#v", as)
			}

			a := as[0].(testclient.GetActionImpl)
			if got, expected := a.Verb, "get"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Name, "another-node"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {},
		react: func(action testclient.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, apierrors.NewNotFound((schema.GroupResource{Group: "", Resource: "nodes"}), "valid-node")
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected 1 client calls but got: %#v", as)
			}

			a := as[0].(testclient.GetActionImpl)
			if got, expected := a.Verb, "get"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Name, "valid-node"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
		err: false,
	}}
	for idx, c := range cases {
		b := csrBuilder{
			cn:              "system:node:valid-node",
			orgs:            []string{"system:nodes"},
			requestor:       "system:bootstrappers:id-1",
			requestorGroups: []string{"system:bootstrappers"},
			usages: []certificates.KeyUsage{
				certificates.UsageKeyEncipherment,
				certificates.UsageDigitalSignature,
				certificates.UsageClientAuth,
			},
		}
		c.cbm(&b)
		t.Run(fmt.Sprintf("test #%d", idx), func(t *testing.T) {
			fclient := &fake.Clientset{}
			fclient.AddReactor("get", "nodes", c.react)
			ar := &Approver{
				kubeClient: fclient,
			}
			csr := makeTestCSR(t, b)
			x509cr, err := csrutil.ParseCSR(csr)
			if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			r := ar.isValidNewNode(mapNodesToInstanceIDs(nodetoid))
			err = r(csr, x509cr)
			if err != nil && !c.err {
				t.Errorf("expected err: %v got:%v", c.err, err)
			}
			c.verify(t, fclient.Actions())
		})
	}
}

func TestIsValidNode(t *testing.T) {
	nodetoid := map[string]string{
		"valid-node":   "id-1",
		"another-node": "id-2",
	}
	cases := []struct {
		cbm    func(b *csrBuilder)
		react  testclient.ReactionFunc
		verify func(*testing.T, []testclient.Action)
		err    bool
	}{{
		cbm: func(b *csrBuilder) {
			b.requestorGroups = []string{"evil:group"}
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "random"
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "system:node:random-node"
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 0 {
				t.Errorf("expected no client calls but got: %#v", as)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "system:node:another-node"
			b.requestor = "system:node:another-node"
		},
		react: func(action testclient.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, apierrors.NewNotFound((schema.GroupResource{Group: "", Resource: "nodes"}), "another-node")
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected 1 client calls but got: %#v", as)
			}

			a := as[0].(testclient.GetActionImpl)
			if got, expected := a.Verb, "get"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Name, "another-node"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {},
		react: func(action testclient.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "valid-node",
				},
				Status: v1.NodeStatus{
					Conditions: nil,
				},
			}, nil
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected 1 client calls but got: %#v", as)
			}

			a := as[0].(testclient.GetActionImpl)
			if got, expected := a.Verb, "get"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Name, "valid-node"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {},
		react: func(action testclient.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "valid-node",
				},
				Status: v1.NodeStatus{
					Conditions: []v1.NodeCondition{{
						Type:   v1.NodeReady,
						Status: v1.ConditionFalse,
					}},
				},
			}, nil
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected 1 client calls but got: %#v", as)
			}

			a := as[0].(testclient.GetActionImpl)
			if got, expected := a.Verb, "get"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Name, "valid-node"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {},
		react: func(action testclient.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "valid-node",
				},
				Status: v1.NodeStatus{
					Conditions: []v1.NodeCondition{{
						Type:   v1.NodeReady,
						Status: v1.ConditionTrue,
					}},
				},
			}, nil
		},
		verify: func(t *testing.T, as []testclient.Action) {
			if len(as) != 1 {
				t.Errorf("expected 1 client calls but got: %#v", as)
			}

			a := as[0].(testclient.GetActionImpl)
			if got, expected := a.Verb, "get"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Resource, (schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}); got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
			if got, expected := a.Name, "valid-node"; got != expected {
				t.Errorf("got: %v, expected: %v", got, expected)
			}
		},
		err: false,
	}}
	for idx, c := range cases {
		b := csrBuilder{
			cn:              "system:node:valid-node",
			orgs:            []string{"system:nodes"},
			requestor:       "system:node:valid-node",
			requestorGroups: []string{"system:nodes"},
			usages: []certificates.KeyUsage{
				certificates.UsageKeyEncipherment,
				certificates.UsageDigitalSignature,
				certificates.UsageClientAuth,
			},
		}
		c.cbm(&b)
		t.Run(fmt.Sprintf("test #%d", idx), func(t *testing.T) {
			fclient := &fake.Clientset{}
			fclient.AddReactor("get", "nodes", c.react)
			ar := &Approver{
				kubeClient: fclient,
			}
			csr := makeTestCSR(t, b)
			x509cr, err := csrutil.ParseCSR(csr)
			if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			r := ar.isValidNode(mapNodesToInstanceIDs(nodetoid))
			err = r(csr, x509cr)
			if err != nil && !c.err {
				t.Errorf("expected err: %v got:%v", c.err, err)
			}
			c.verify(t, fclient.Actions())
		})
	}
}

func TestIsValidASG(t *testing.T) {
	nodetoasg := map[string]string{
		"valid-node":   "asg-1",
		"another-node": "asg-2",
	}
	wasgs := []string{"asg-1"}
	cases := []struct {
		cbm func(b *csrBuilder)
		err bool
	}{{
		cbm: func(b *csrBuilder) {
			b.cn = "invalid"
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "system:node:random-node"
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {
			b.cn = "system:node:another-node"
		},
		err: true,
	}, {
		cbm: func(b *csrBuilder) {},
		err: false,
	}}

	for idx, c := range cases {
		b := csrBuilder{
			cn:              "system:node:valid-node",
			orgs:            []string{"system:nodes"},
			requestor:       "system:node:valid-node",
			requestorGroups: []string{"system:nodes"},
			usages: []certificates.KeyUsage{
				certificates.UsageKeyEncipherment,
				certificates.UsageDigitalSignature,
				certificates.UsageClientAuth,
			},
		}
		c.cbm(&b)
		t.Run(fmt.Sprintf("test #%d", idx), func(t *testing.T) {
			ar := &Approver{
				allowedASGs: sets.NewString(wasgs...),
			}
			csr := makeTestCSR(t, b)
			x509cr, err := csrutil.ParseCSR(csr)
			if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			r := ar.isValidASG(mapNodesToASGs(nodetoasg))
			err = r(csr, x509cr)
			if err != nil && !c.err {
				t.Errorf("expected err: %v got:%v", c.err, err)
			}
		})
	}
}

func mapNodesToInstanceIDs(m map[string]string) instanceIDFunc {
	return func(nodeName string) (string, error) {
		id, ok := m[nodeName]
		if !ok {
			return "", fmt.Errorf("no instance id found for %s", nodeName)
		}
		return id, nil
	}
}

func mapNodesToASGs(m map[string]string) autoScalingGroupIDFunc {
	return func(nodeName string) (string, error) {
		id, ok := m[nodeName]
		if !ok {
			return "", fmt.Errorf("no asg found for %s", nodeName)
		}
		return id, nil
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

func makeTestCSR(t *testing.T, b csrBuilder) *certificates.CertificateSigningRequest {
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
		t.Fatalf("error creating csr: %v", err)
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
