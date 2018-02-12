package aws

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/golang/glog"
	"github.com/juju/ratelimit"

	certificates "k8s.io/api/certificates/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	certificateslisters "k8s.io/client-go/listers/certificates/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// Config defines settings for Approver.
type Config struct {
	RegionName  string
	AllowedASGs []string
}

// Approver approvers CSRs.
type Approver struct {
	kubeClient  kubernetes.Interface
	aws         *awsCloud
	allowedASGs sets.String

	csrInformer cache.SharedIndexInformer
	csrLister   certificateslisters.CertificateSigningRequestLister
	csrSynced   cache.InformerSynced
	queue       workqueue.RateLimitingInterface
}

// New return a new Approver.
func New(client kubernetes.Interface, config Config) (*Approver, error) {
	ar := &Approver{
		kubeClient: client,
	}

	c, err := newAWSCloud(config.RegionName)
	if err != nil {
		return nil, err
	}
	ar.aws = c

	ar.allowedASGs = sets.NewString(config.AllowedASGs...)

	ar.queue = workqueue.NewRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 100*time.Second),
		&workqueue.BucketRateLimiter{Bucket: ratelimit.NewBucketWithRate(float64(10), int64(100))},
	))

	csrInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return client.CertificatesV1beta1().CertificateSigningRequests().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return client.CertificatesV1beta1().CertificateSigningRequests().Watch(options)
			},
		},
		&certificates.CertificateSigningRequest{},
		3*time.Minute,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	csrInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certificates.CertificateSigningRequest)
			glog.V(4).Infof("Adding certificate request %s", csr.Name)
			ar.enqueueCertificateRequest(obj)
		},
	})
	ar.csrLister = certificateslisters.NewCertificateSigningRequestLister(csrInformer.GetIndexer())
	ar.csrSynced = csrInformer.HasSynced

	return ar, nil
}

// Run starts the Approver's consumers.
func (ar *Approver) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer ar.queue.ShutDown()

	glog.Info("Starting kube-aws-approver")
	defer glog.Info("Shutting down kube-aws-approver")

	go ar.csrInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, ar.csrSynced) {
		utilruntime.HandleError(fmt.Errorf("error timeout waiting for caches"))
		return
	}

	// start consumer.
	wait.Until(func() {
		for ar.processNextItem() {
		}
	}, time.Second, stopCh)
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

func (ar *Approver) enqueueCertificateRequest(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	ar.queue.Add(key)
}
