package azure

import (
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider"
	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
)

type scaleSetInfo struct {
	ID   string
	Name string
}

type scaleSetVMInfo struct {
	ID       string
	NodeName string
	scaleSetInfo
}

type scaleSet struct {
	*Cloud

	// availabilitySet is also required for scaleSet because some instances
	// (e.g. master nodes) may not belong to any scale sets.
	availabilitySet vmSet

	cacheMutex sync.Mutex
	// A local cache of scale sets. The key is scale set name and the value is a
	// list of virtual machines belonging to the scale set.
	cache                     map[string][]scaleSetVMInfo
	availabilitySetNodesCache sets.String
}

func newScaleSet(az *Cloud) *scaleSet {
	ss := &scaleSet{
		Cloud:                     az,
		availabilitySet:           newAvailabilitySet(az),
		availabilitySetNodesCache: sets.NewString(),
		cache: make(map[string][]scaleSetVMInfo),
	}

	go wait.Until(func() {
		ss.cacheMutex.Lock()
		defer ss.cacheMutex.Unlock()

		if err := ss.updateCache(); err != nil {
			glog.Errorf("updateCache failed: %v", err)
		}
	}, 5*time.Minute, wait.NeverStop)

	return ss
}

func (ss *scaleSet) GetInstanceIDByNodeName(name string) (string, error) {
	vm, err := ss.getCachedVirtualMachine(name)
	if err != nil {
		if err == cloudprovider.ErrInstanceNotFound {
			glog.V(4).Infof("GetInstanceIDByNodeName: node %q is not found in scale sets, assuming it is managed by availability set", name)
			return ss.availabilitySet.GetInstanceIDByNodeName(name)
		}
		return "", err
	}

	return vm.ID, nil
}

func (ss *scaleSet) GetInstanceGroupByNodeName(name string) (string, error) {
	vm, err := ss.getCachedVirtualMachine(name)
	if err != nil {
		if err == cloudprovider.ErrInstanceNotFound {
			glog.V(4).Infof("GetInstanceIDByNodeName: node %q is not found in scale sets, assuming it is managed by availability set", name)
			return ss.availabilitySet.GetInstanceGroupByNodeName(name)
		}
		return "", err
	}

	return vm.scaleSetInfo.ID, nil
}

func (ss *scaleSet) updateCache() error {
	scaleSets, err := ss.listScaleSetsWithRetry()
	if err != nil {
		return err
	}

	localCache := make(map[string][]scaleSetVMInfo)
	for _, ssi := range scaleSets {
		if _, ok := localCache[ssi.Name]; !ok {
			localCache[ssi.Name] = make([]scaleSetVMInfo, 0)
		}
		vms, err := ss.listScaleSetVMsWithRetry(ssi.Name)
		if err != nil {
			return err
		}

		for _, vm := range vms {
			nodeName := ""
			if vm.OsProfile != nil && vm.OsProfile.ComputerName != nil {
				nodeName = strings.ToLower(*vm.OsProfile.ComputerName)
			}

			localCache[ssi.Name] = append(localCache[ssi.Name], scaleSetVMInfo{
				ID:           *vm.ID,
				NodeName:     nodeName,
				scaleSetInfo: ssi,
			})
		}
	}

	// Only update cache after all steps are success.
	ss.cache = localCache
	return nil
}

func (ss *scaleSet) getCachedVirtualMachine(nodeName string) (scaleSetVMInfo, error) {
	ss.cacheMutex.Lock()
	defer ss.cacheMutex.Unlock()

	getVMFromCache := func(nodeName string) (scaleSetVMInfo, bool) {
		glog.V(4).Infof("Getting scaleSetVMInfo for %q from cache %v", nodeName, ss.cache)
		for scaleSetName := range ss.cache {
			for _, vm := range ss.cache[scaleSetName] {
				if vm.NodeName == nodeName {
					return vm, true
				}
			}
		}

		return scaleSetVMInfo{}, false
	}
	vm, found := getVMFromCache(nodeName)
	if found {
		return vm, nil
	}

	// Known node not managed by scale sets.
	if ss.availabilitySetNodesCache.Has(nodeName) {
		glog.V(4).Infof("Found node %q in availabilitySetNodesCache", nodeName)
		return scaleSetVMInfo{}, cloudprovider.ErrInstanceNotFound
	}

	// Update cache and try again.
	glog.V(4).Infof("vmss cache before updateCache: %v", ss.cache)
	if err := ss.updateCache(); err != nil {
		glog.Errorf("updateCache failed with error: %v", err)
		return scaleSetVMInfo{}, err
	}
	glog.V(4).Infof("vmss cache after updateCache: %v", ss.cache)
	vm, found = getVMFromCache(nodeName)
	if found {
		return vm, nil
	}

	// Node still not found, assuming it is not managed by scale sets.
	glog.V(4).Infof("Node %q doesn't belong to any scale sets, adding it to availabilitySetNodesCache", nodeName)
	ss.availabilitySetNodesCache.Insert(nodeName)
	return scaleSetVMInfo{}, cloudprovider.ErrInstanceNotFound
}

func (ss *scaleSet) listScaleSetsWithRetry() ([]scaleSetInfo, error) {
	var err error
	var result compute.VirtualMachineScaleSetListResult
	allScaleSets := make([]scaleSetInfo, 0)
	bf := wait.Backoff{
		Steps: 1,
	}
	if ss.CloudProviderBackoff {
		bf = ss.resourceRequestBackoff
	}

	backoffError := wait.ExponentialBackoff(bf, func() (bool, error) {
		result, err = ss.VirtualMachineScaleSetsClient.List(ss.ResourceGroup)
		if err != nil {
			glog.Errorf("VirtualMachineScaleSetsClient.List for %v failed: %v", ss.ResourceGroup, err)
			return false, err
		}

		return true, nil
	})
	if backoffError != nil {
		return nil, backoffError
	}

	appendResults := (result.Value != nil && len(*result.Value) > 0)
	for appendResults {
		for _, s := range *result.Value {
			allScaleSets = append(allScaleSets, scaleSetInfo{*s.ID, *s.Name})
		}
		appendResults = false

		if result.NextLink != nil {
			backoffError := wait.ExponentialBackoff(bf, func() (bool, error) {
				result, err = ss.VirtualMachineScaleSetsClient.ListNextResults(result)
				if err != nil {
					glog.Errorf("VirtualMachineScaleSetsClient.ListNextResults for %v failed: %v", ss.ResourceGroup, err)
					return false, err
				}

				return true, nil
			})
			if backoffError != nil {
				return nil, backoffError
			}

			appendResults = (result.Value != nil && len(*result.Value) > 0)
		}

	}

	return allScaleSets, nil
}

func (ss *scaleSet) listScaleSetVMsWithRetry(scaleSetName string) ([]compute.VirtualMachineScaleSetVM, error) {
	var err error
	var result compute.VirtualMachineScaleSetVMListResult
	allVMs := make([]compute.VirtualMachineScaleSetVM, 0)
	bf := wait.Backoff{
		Steps: 1,
	}
	if ss.CloudProviderBackoff {
		bf = ss.resourceRequestBackoff
	}

	backoffError := wait.ExponentialBackoff(bf, func() (bool, error) {
		result, err = ss.VirtualMachineScaleSetVMsClient.List(ss.ResourceGroup, scaleSetName, "", "", string(compute.InstanceView))
		if err != nil {
			glog.Errorf("VirtualMachineScaleSetVMsClient.List for %v failed: %v", scaleSetName, err)
			return false, err
		}

		return true, nil
	})
	if backoffError != nil {
		return nil, backoffError
	}

	appendResults := (result.Value != nil && len(*result.Value) > 0)
	for appendResults {
		allVMs = append(allVMs, *result.Value...)
		appendResults = false

		if result.NextLink != nil {
			backoffError := wait.ExponentialBackoff(bf, func() (bool, error) {
				result, err = ss.VirtualMachineScaleSetVMsClient.ListNextResults(result)
				if err != nil {
					glog.Errorf("VirtualMachineScaleSetVMsClient.ListNextResults for %v failed: %v", scaleSetName, err)
					return false, err
				}

				return true, nil
			})
			if backoffError != nil {
				return nil, backoffError
			}

			appendResults = (result.Value != nil && len(*result.Value) > 0)
		}

	}

	return allVMs, nil
}
