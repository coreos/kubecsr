package approver

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/juju/ratelimit"

	certificates "k8s.io/api/certificates/v1beta1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	certificatesv1b1listers "k8s.io/client-go/listers/certificates/v1beta1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider"
)

const (
	resyncPeriod      = 10 * time.Second
	masterNodeRoleKey = "node-role.kubernetes.io/master"
	workerNodeRoleKey = "node-role.kubernetes.io/node"
)

type Approver struct {
	kubeClient kubernetes.Interface
	cloud      cloudprovider.Interface

	nodeLister corelisters.NodeLister
	nodeSynced cache.InformerSynced
	csrLister  certificatesv1b1listers.CertificateSigningRequestLister
	csrSynced  cache.InformerSynced
	queue      workqueue.RateLimitingInterface

	MasterGroup sets.String
	WorkerGroup sets.String
}

func New(client kubernetes.Interface, cloud cloudprovider.Interface) (*Approver, error) {
	ar := &Approver{
		kubeClient:  client,
		cloud:       cloud,
		MasterGroup: sets.NewString(),
		WorkerGroup: sets.NewString(),
	}

	ar.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 1000*time.Second),
		&workqueue.BucketRateLimiter{Bucket: ratelimit.NewBucketWithRate(float64(10), int64(100))},
	), "node-csr-approver")

	sharedInformer := informers.NewSharedInformerFactory(ar.kubeClient, resyncPeriod)

	nodeInformer := sharedInformer.Core().V1().Nodes()
	ar.nodeLister = nodeInformer.Lister()
	ar.nodeSynced = nodeInformer.Informer().HasSynced

	csrInformer := sharedInformer.Certificates().V1beta1().CertificateSigningRequests()
	// Manage the addition/update of certificate requests
	csrInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certificates.CertificateSigningRequest)
			glog.V(4).Infof("Adding certificate request %s", csr.Name)
			ar.enqueueCertificateRequest(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			oldCSR := old.(*certificates.CertificateSigningRequest)
			glog.V(4).Infof("Updating certificate request %s", oldCSR.Name)
			ar.enqueueCertificateRequest(new)
		},
		DeleteFunc: func(obj interface{}) {
			csr, ok := obj.(*certificates.CertificateSigningRequest)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					glog.V(2).Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				csr, ok = tombstone.Obj.(*certificates.CertificateSigningRequest)
				if !ok {
					glog.V(2).Infof("Tombstone contained object that is not a CSR: %#v", obj)
					return
				}
			}
			glog.V(4).Infof("Deleting certificate request %s", csr.Name)
			ar.enqueueCertificateRequest(obj)
		},
	})
	ar.csrLister = csrInformer.Lister()
	ar.csrSynced = csrInformer.Informer().HasSynced

	go sharedInformer.Start(wait.NeverStop)
	return ar, nil
}

func (ar *Approver) Run(workers int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer ar.queue.ShutDown()

	glog.Info("Starting node-csr-approver")
	defer glog.Info("Shutting down node-csr-approver")

	if !cache.WaitForCacheSync(stopCh, ar.csrSynced, ar.nodeSynced) {
		return fmt.Errorf("error timeout waiting for caches")
	}

	var err error
	err = wait.PollImmediate(5*time.Minute, 5*time.Minute, func() (bool, error) {
		err := ar.setupWhiteLists()
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("Couldn't complete setting up instance group whitelists: %v", err)
	}
	glog.V(4).Infof("Master Instancegroup: %s Worker Instancegroup: %s", ar.MasterGroup, ar.WorkerGroup)

	err = wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		err := ar.kubeClient.RbacV1().ClusterRoleBindings().Delete("system-bootstrap-approve-node-client-csr", &metav1.DeleteOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			glog.Errorf("error deleting auto-approver: %v", err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("Couldn't delete auto approval cluster role: %v", err)
	}
	glog.V(4).Info("deleted the auto approve cluster role")

	// start consumer.
	for i := 0; i < workers; i++ {
		go wait.Until(ar.worker, time.Second, stopCh)
	}
	<-stopCh

	return nil
}

func (ar *Approver) worker() {
	for ar.processNextItem() {
	}
}

func (ar *Approver) processNextItem() bool {
	key, quit := ar.queue.Get()
	if quit {
		return false
	}
	defer ar.queue.Done(key)

	if err := ar.syncFunc(key.(string)); err != nil {
		ar.queue.AddRateLimited(key)
		glog.V(4).Infof("Sync %v failed with : %v", key, err)
		return true
	}

	ar.queue.Forget(key)
	return true
}

func (ar *Approver) syncFunc(key string) error {
	startTime := time.Now()
	defer func() {
		glog.V(4).Infof("Finished syncing certificate request %q (%v)", key, time.Now().Sub(startTime))
	}()
	csr, err := ar.csrLister.Get(key)
	if apierrors.IsNotFound(err) {
		glog.V(3).Infof("csr has been deleted: %v", key)
		return nil
	}
	if err != nil {
		return err
	}

	if csr.Status.Certificate != nil {
		// no need to do anything because it already has a cert
		return nil
	}
	// need to operate on a copy so we don't mutate the csr in the shared cache
	csr = csr.DeepCopy()

	return ar.handle(csr)
}

func (ar *Approver) setupWhiteLists() error {
	msel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchLabels: map[string]string{
			masterNodeRoleKey: "",
		},
	})
	if err != nil {
		return err
	}
	mg, err := ar.findInstanceGroupFromSelector(msel)
	if err != nil {
		return err
	}
	ar.MasterGroup.Insert(mg...)

	wsel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchLabels: map[string]string{
			workerNodeRoleKey: "",
		},
	})
	if err != nil {
		return err
	}
	wg, err := ar.findInstanceGroupFromSelector(wsel)
	if err != nil {
		return err
	}
	ar.WorkerGroup.Insert(wg...)

	return nil
}

func (ar *Approver) findInstanceGroupFromSelector(sel labels.Selector) ([]string, error) {
	nodes, err := ar.nodeLister.List(sel)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available yet")
	}

	results := []string{}
	for _, node := range nodes {
		glog.V(4).Infof("fetching instance group for node: %s", node.GetName())
		ig, err := ar.cloud.GetInstanceGroupByNodeName(node.GetName())
		if err != nil {
			return nil, err
		}
		glog.V(4).Infof("fetched instance group for node: %s g: %s", node.GetName(), ig)
		results = append(results, ig)
	}
	return results, nil
}

func (ar *Approver) enqueueCertificateRequest(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}

	ar.queue.Add(key)
}
