package main

import (
	"flag"
	"os"
	"time"

	"github.com/coreos/kubecsr/pkg/nodeapprover"
	"github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider"
	"github.com/golang/glog"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	//Cloud Providers
	_ "github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider/providers"
)

var (
	kubeconfig    = flag.String("kubeconfig", "", "kubeconfig file with acces to cluster. (testing only)")
	cloudProvider = flag.String("cloud-provider", "", "The provider for cloud services.  Empty string for no provider.")
	cloudConfig   = flag.String("cloud-config", "", "The path to the cloud provider configuration file.  Empty string for no configuration file.")
)

func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()

	var config *rest.Config
	var err error

	if *kubeconfig != "" {
		glog.V(4).Infof("Loading kube client config from path %q", *kubeconfig)
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	} else {
		glog.V(4).Infof("Using in-cluster kube client config")
		config, err = rest.InClusterConfig()
	}

	if *cloudProvider == "" {
		glog.Info("Nothing to do here. Exiting...")
		return
	}

	cloud, err := cloudprovider.InitCloudProvider(*cloudProvider, *cloudConfig)
	if err != nil {
		glog.Errorf("error starting cloud provider %s: %v", "aws", err)
		return
	}
	client := kubernetes.NewForConfigOrDie(config)

	id, err := os.Hostname()
	if err != nil {
		glog.Errorf("error %v", err)
		return
	}

	// add a uniquifier so that two processes on the same host don't accidentally both become active
	id = id + "_" + string(uuid.NewUUID())
	recorder := record.
		NewBroadcaster().
		NewRecorder(runtime.NewScheme(), v1.EventSource{Component: "node-csr-approver"})

	rl, err := resourcelock.New(resourcelock.ConfigMapsResourceLock,
		"kube-system",
		"node-csr-approver",
		client.CoreV1(),
		resourcelock.ResourceLockConfig{
			Identity:      id,
			EventRecorder: recorder,
		})
	if err != nil {
		glog.Fatalf("error creating lock: %v", err)
	}
	leaderelection.RunOrDie(leaderelection.LeaderElectionConfig{
		Lock:          rl,
		LeaseDuration: 90 * time.Second,
		RenewDeadline: 60 * time.Second,
		RetryPeriod:   30 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(stop <-chan struct{}) {
				glog.Info("Became leader: starting node-csr-approver.")
				ar, err := approver.New(client, cloud)
				if err != nil {
					glog.Fatalf("error creating approver %v", err)
				}
				err = ar.Run(2, stop)
				if err != nil {
					glog.Fatalf("error running approver: %v", err)
				}
			},
			OnStoppedLeading: func() {
				glog.Fatalf("leaderelection lost")
			},
		},
	})
	panic("unreachable")
}
