package azure

import (
	"time"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"k8s.io/client-go/util/flowcontrol"
)

type azClientConfig struct {
	subscriptionID          string
	resourceManagerEndpoint string
	servicePrincipalToken   *adal.ServicePrincipalToken
	rateLimiter             flowcontrol.RateLimiter
}

type azVirtualMachinesClient struct {
	client      compute.VirtualMachinesClient
	rateLimiter flowcontrol.RateLimiter
}

func newAzVirtualMachinesClient(config *azClientConfig) *azVirtualMachinesClient {
	virtualMachinesClient := compute.NewVirtualMachinesClient(config.subscriptionID)
	virtualMachinesClient.BaseURI = config.resourceManagerEndpoint
	virtualMachinesClient.Authorizer = autorest.NewBearerAuthorizer(config.servicePrincipalToken)
	virtualMachinesClient.PollingDelay = 5 * time.Second

	return &azVirtualMachinesClient{
		rateLimiter: config.rateLimiter,
		client:      virtualMachinesClient,
	}
}

func (az *azVirtualMachinesClient) Get(resourceGroupName string, VMName string, expand compute.InstanceViewTypes) (result compute.VirtualMachine, err error) {
	az.rateLimiter.Accept()
	result, err = az.client.Get(resourceGroupName, VMName, expand)
	return
}

type azVirtualMachineScaleSetsClient struct {
	client      compute.VirtualMachineScaleSetsClient
	rateLimiter flowcontrol.RateLimiter
}

func newAzVirtualMachineScaleSetsClient(config *azClientConfig) *azVirtualMachineScaleSetsClient {
	virtualMachineScaleSetsClient := compute.NewVirtualMachineScaleSetsClient(config.subscriptionID)
	virtualMachineScaleSetsClient.BaseURI = config.resourceManagerEndpoint
	virtualMachineScaleSetsClient.Authorizer = autorest.NewBearerAuthorizer(config.servicePrincipalToken)
	virtualMachineScaleSetsClient.PollingDelay = 5 * time.Second

	return &azVirtualMachineScaleSetsClient{
		client:      virtualMachineScaleSetsClient,
		rateLimiter: config.rateLimiter,
	}
}

func (az *azVirtualMachineScaleSetsClient) List(resourceGroupName string) (result compute.VirtualMachineScaleSetListResult, err error) {
	az.rateLimiter.Accept()
	result, err = az.client.List(resourceGroupName)
	return
}

func (az *azVirtualMachineScaleSetsClient) ListNextResults(lastResults compute.VirtualMachineScaleSetListResult) (result compute.VirtualMachineScaleSetListResult, err error) {
	az.rateLimiter.Accept()
	result, err = az.client.ListNextResults(lastResults)
	return
}

type azVirtualMachineScaleSetVMsClient struct {
	client      compute.VirtualMachineScaleSetVMsClient
	rateLimiter flowcontrol.RateLimiter
}

func newAzVirtualMachineScaleSetVMsClient(config *azClientConfig) *azVirtualMachineScaleSetVMsClient {
	virtualMachineScaleSetVMsClient := compute.NewVirtualMachineScaleSetVMsClient(config.subscriptionID)
	virtualMachineScaleSetVMsClient.BaseURI = config.resourceManagerEndpoint
	virtualMachineScaleSetVMsClient.Authorizer = autorest.NewBearerAuthorizer(config.servicePrincipalToken)
	virtualMachineScaleSetVMsClient.PollingDelay = 5 * time.Second

	return &azVirtualMachineScaleSetVMsClient{
		client:      virtualMachineScaleSetVMsClient,
		rateLimiter: config.rateLimiter,
	}
}

func (az *azVirtualMachineScaleSetVMsClient) List(resourceGroupName string, virtualMachineScaleSetName string, filter string, selectParameter string, expand string) (result compute.VirtualMachineScaleSetVMListResult, err error) {
	az.rateLimiter.Accept()
	result, err = az.client.List(resourceGroupName, virtualMachineScaleSetName, filter, selectParameter, expand)
	return
}

func (az *azVirtualMachineScaleSetVMsClient) ListNextResults(lastResults compute.VirtualMachineScaleSetVMListResult) (result compute.VirtualMachineScaleSetVMListResult, err error) {
	az.rateLimiter.Accept()
	result, err = az.client.ListNextResults(lastResults)
	return
}
