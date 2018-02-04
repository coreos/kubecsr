package azure

import (
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/go-autorest/autorest"
	"github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider"
	"github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider/internal"
	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/wait"
)

// cache used by getVirtualMachine
// 15s for expiration duration
var vmCache = internal.NewTimedCache(15 * time.Second)

type availabilitySet struct {
	*Cloud
}

func newAvailabilitySet(az *Cloud) *availabilitySet {
	return &availabilitySet{
		Cloud: az,
	}
}

func (as *availabilitySet) GetInstanceIDByNodeName(name string) (string, error) {
	var machine compute.VirtualMachine
	var err error

	machine, err = as.getVirtualMachine(name)
	if err != nil {
		if as.CloudProviderBackoff {
			glog.V(4).Infof("InstanceID(%s) backing off", name)
			machine, err = as.getVirtualMachineWithRetry(name)
			if err != nil {
				glog.V(4).Infof("InstanceID(%s) abort backoff", name)
				return "", err
			}
		} else {
			return "", err
		}
	}
	return *machine.ID, nil
}

func (as *availabilitySet) GetInstanceGroupByNodeName(name string) (string, error) {
	var machine compute.VirtualMachine
	var err error

	machine, err = as.getVirtualMachine(name)
	if err != nil {
		if as.CloudProviderBackoff {
			glog.V(4).Infof("InstanceID(%s) backing off", name)
			machine, err = as.getVirtualMachineWithRetry(name)
			if err != nil {
				glog.V(4).Infof("InstanceID(%s) abort backoff", name)
				return "", err
			}
		} else {
			return "", err
		}
	}

	if machine.VirtualMachineProperties == nil && machine.VirtualMachineProperties.AvailabilitySet == nil {
		return "", cloudprovider.ErrInstanceGroupNotFound
	}

	return *machine.VirtualMachineProperties.AvailabilitySet.ID, nil
}

type vmRequest struct {
	lock *sync.Mutex
	vm   *compute.VirtualMachine
}

func (az *Cloud) getVirtualMachine(nodeName string) (vm compute.VirtualMachine, err error) {
	vmName := nodeName
	cachedRequest, err := vmCache.GetOrCreate(vmName, func() interface{} {
		return &vmRequest{
			lock: &sync.Mutex{},
			vm:   nil,
		}
	})
	if err != nil {
		return compute.VirtualMachine{}, err
	}
	request := cachedRequest.(*vmRequest)

	if request.vm == nil {
		request.lock.Lock()
		defer request.lock.Unlock()
		vm, err = az.VirtualMachinesClient.Get(az.ResourceGroup, vmName, compute.InstanceView)
		exists, realErr := checkResourceExistsFromError(err)
		if realErr != nil {
			return vm, realErr
		}

		if !exists {
			return vm, cloudprovider.ErrInstanceNotFound
		}

		request.vm = &vm
		return *request.vm, nil
	}

	glog.V(4).Infof("getVirtualMachine hits cache for(%s)", vmName)
	return *request.vm, nil
}

func (az *Cloud) getVirtualMachineWithRetry(name string) (compute.VirtualMachine, error) {
	var machine compute.VirtualMachine
	var retryErr error

	bf := wait.Backoff{
		Steps: 1,
	}
	if az.CloudProviderBackoff {
		bf = az.resourceRequestBackoff
	}
	err := wait.ExponentialBackoff(bf, func() (bool, error) {
		machine, retryErr = az.getVirtualMachine(name)
		if retryErr != nil {
			glog.Errorf("backoff: failure, will retry,err=%v", retryErr)
			return false, nil
		}
		glog.V(4).Info("backoff: success")
		return true, nil
	})
	if err == wait.ErrWaitTimeout {
		err = retryErr
	}

	return machine, err
}

func checkResourceExistsFromError(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	v, ok := err.(autorest.DetailedError)
	if !ok {
		return false, err
	}
	if v.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, v
}
