package azure

import (
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider"
	"github.com/golang/glog"
	yaml "gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/flowcontrol"
)

const (
	// CloudProviderName is the value used for the --cloud-provider flag
	CloudProviderName      = "azure"
	rateLimitQPSDefault    = 1.0
	rateLimitBucketDefault = 5
	backoffRetriesDefault  = 6
	backoffExponentDefault = 1.5
	backoffDurationDefault = 5 // in seconds
	backoffJitterDefault   = 1.0

	vmTypeVMSS     = "vmss"
	vmTypeStandard = "standard"
)

func init() {
	cloudprovider.RegisterCloudProvider(CloudProviderName, NewCloud)
}

type Config struct {
	AzureAuthConfig

	ResourceGroup                string  `json:"resourceGroup" yaml:"resourceGroup"`
	Location                     string  `json:"location" yaml:"location"`
	VMType                       string  `json:"vmType" yaml:"vmType"`
	CloudProviderBackoff         bool    `json:"cloudProviderBackoff" yaml:"cloudProviderBackoff"`
	CloudProviderBackoffRetries  int     `json:"cloudProviderBackoffRetries" yaml:"cloudProviderBackoffRetries"`
	CloudProviderBackoffExponent float64 `json:"cloudProviderBackoffExponent" yaml:"cloudProviderBackoffExponent"`
	CloudProviderBackoffDuration int     `json:"cloudProviderBackoffDuration" yaml:"cloudProviderBackoffDuration"`
	CloudProviderBackoffJitter   float64 `json:"cloudProviderBackoffJitter" yaml:"cloudProviderBackoffJitter"`
	CloudProviderRateLimit       bool    `json:"cloudProviderRateLimit" yaml:"cloudProviderRateLimit"`
	CloudProviderRateLimitQPS    float32 `json:"cloudProviderRateLimitQPS" yaml:"cloudProviderRateLimitQPS"`
	CloudProviderRateLimitBucket int     `json:"cloudProviderRateLimitBucket" yaml:"cloudProviderRateLimitBucket"`
}

type Cloud struct {
	Config
	Environment            azure.Environment
	resourceRequestBackoff wait.Backoff
	vmSet                  vmSet

	// Client for standard.
	VirtualMachinesClient *azVirtualMachinesClient

	// Clients for vmss.
	VirtualMachineScaleSetsClient   *azVirtualMachineScaleSetsClient
	VirtualMachineScaleSetVMsClient *azVirtualMachineScaleSetVMsClient
}

func NewCloud(configReader io.Reader) (cloudprovider.Interface, error) {
	config, err := parseConfig(configReader)
	if err != nil {
		return nil, err
	}

	env, err := ParseAzureEnvironment(config.Cloud)
	if err != nil {
		return nil, err
	}

	servicePrincipalToken, err := GetServicePrincipalToken(&config.AzureAuthConfig, env)
	if err != nil {
		return nil, err
	}

	// operationPollRateLimiter.Accept() is a no-op if rate limits are configured off.
	operationPollRateLimiter := flowcontrol.NewFakeAlwaysRateLimiter()
	if config.CloudProviderRateLimit {
		// Assign rate limit defaults if no configuration was passed in
		if config.CloudProviderRateLimitQPS == 0 {
			config.CloudProviderRateLimitQPS = rateLimitQPSDefault
		}
		if config.CloudProviderRateLimitBucket == 0 {
			config.CloudProviderRateLimitBucket = rateLimitBucketDefault
		}
		operationPollRateLimiter = flowcontrol.NewTokenBucketRateLimiter(
			config.CloudProviderRateLimitQPS,
			config.CloudProviderRateLimitBucket)
		glog.V(2).Infof("Azure cloudprovider using rate limit config: QPS=%g, bucket=%d", config.CloudProviderRateLimitQPS, config.CloudProviderRateLimitBucket)
	}

	azClientConfig := &azClientConfig{
		subscriptionID:          config.SubscriptionID,
		resourceManagerEndpoint: env.ResourceManagerEndpoint,
		servicePrincipalToken:   servicePrincipalToken,
		rateLimiter:             operationPollRateLimiter,
	}
	az := Cloud{
		Config:      *config,
		Environment: *env,

		VirtualMachinesClient:           newAzVirtualMachinesClient(azClientConfig),
		VirtualMachineScaleSetsClient:   newAzVirtualMachineScaleSetsClient(azClientConfig),
		VirtualMachineScaleSetVMsClient: newAzVirtualMachineScaleSetVMsClient(azClientConfig),
	}

	// Conditionally configure resource request backoff
	if az.CloudProviderBackoff {
		// Assign backoff defaults if no configuration was passed in
		if az.CloudProviderBackoffRetries == 0 {
			az.CloudProviderBackoffRetries = backoffRetriesDefault
		}
		if az.CloudProviderBackoffExponent == 0 {
			az.CloudProviderBackoffExponent = backoffExponentDefault
		}
		if az.CloudProviderBackoffDuration == 0 {
			az.CloudProviderBackoffDuration = backoffDurationDefault
		}
		if az.CloudProviderBackoffJitter == 0 {
			az.CloudProviderBackoffJitter = backoffJitterDefault
		}
		az.resourceRequestBackoff = wait.Backoff{
			Steps:    az.CloudProviderBackoffRetries,
			Factor:   az.CloudProviderBackoffExponent,
			Duration: time.Duration(az.CloudProviderBackoffDuration) * time.Second,
			Jitter:   az.CloudProviderBackoffJitter,
		}
		glog.V(2).Infof("Azure cloudprovider using retry backoff: retries=%d, exponent=%f, duration=%d, jitter=%f", az.CloudProviderBackoffRetries, az.CloudProviderBackoffExponent, az.CloudProviderBackoffDuration, az.CloudProviderBackoffJitter)
	}

	if strings.EqualFold(vmTypeVMSS, az.Config.VMType) {
		az.vmSet = newScaleSet(&az)
	} else {
		az.vmSet = newAvailabilitySet(&az)
	}

	return &az, nil
}

func (c *Cloud) GetInstanceIDByNodeName(nodeName string) (string, error) {
	return c.vmSet.GetInstanceIDByNodeName(nodeName)
}

func (c *Cloud) GetInstanceGroupByNodeName(nodeName string) (string, error) {
	return c.vmSet.GetInstanceGroupByNodeName(nodeName)
}

type vmSet interface {
	GetInstanceIDByNodeName(string) (string, error)
	GetInstanceGroupByNodeName(string) (string, error)
}

// parseConfig returns a parsed configuration for an Azure cloudprovider config file
func parseConfig(configReader io.Reader) (*Config, error) {
	var config Config

	if configReader == nil {
		return &config, nil
	}

	configContents, err := ioutil.ReadAll(configReader)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(configContents, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
