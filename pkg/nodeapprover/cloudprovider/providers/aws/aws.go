package aws

import (
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider"
)

// ProviderName is the name of this cloud provider.
const ProviderName = "aws"

// Cloud is an implementation of Interface.
type Cloud struct {
	ec2 *ec2.EC2
	asg *autoscaling.AutoScaling
}

func init() {
	cloudprovider.RegisterCloudProvider(ProviderName, func(config io.Reader) (cloudprovider.Interface, error) {
		creds := credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.EnvProvider{},
				&ec2rolecreds.EC2RoleProvider{
					Client: ec2metadata.New(session.New(&aws.Config{})),
				},
				&credentials.SharedCredentialsProvider{},
			})

		aws := &awsSDKProvider{
			creds: creds,
		}
		return newAWSCloud(config, aws)
	})
}

func (c *Cloud) GetInstanceIDByNodeName(nodeName string) (string, error) {
	privateDNSName := nodeName
	filters := []*ec2.Filter{
		newEc2Filter("private-dns-name", privateDNSName),
		newEc2Filter("instance-state-name", "running"),
	}
	req := &ec2.DescribeInstancesInput{
		Filters: filters,
	}
	instances, err := c.describeInstances(req)
	if err != nil {
		return "", err
	}

	if len(instances) == 0 {
		return "", cloudprovider.ErrInstanceNotFound
	}
	if len(instances) > 1 {
		return "", fmt.Errorf("multiple instances found for name: %s", nodeName)
	}

	return aws.StringValue(instances[0].InstanceId), nil
}

func (c *Cloud) GetInstanceGroupByNodeName(nodeName string) (string, error) {
	instanceID, err := c.GetInstanceIDByNodeName(nodeName)
	if err != nil {
		return "", err
	}
	if instanceID == "" {
		return "", fmt.Errorf("error got empty instance id from aws")
	}

	reqASI := &autoscaling.DescribeAutoScalingInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceID),
		},
	}
	instances, err := c.describeAutoScalingInstances(reqASI)
	if err != nil {
		return "", err
	}
	if len(instances) == 0 {
		return "", cloudprovider.ErrInstanceGroupNotFound
	}
	if len(instances) > 1 {
		return "", fmt.Errorf("multiple auto scaling instances found for name: %s", nodeName)
	}

	return aws.StringValue(instances[0].AutoScalingGroupName), nil
}

func (c *Cloud) describeInstances(request *ec2.DescribeInstancesInput) ([]*ec2.Instance, error) {
	// Instances are paged
	results := []*ec2.Instance{}
	var nextToken *string
	for {
		response, err := c.ec2.DescribeInstances(request)
		if err != nil {
			return nil, fmt.Errorf("error listing AWS instances: %q", err)
		}

		for _, reservation := range response.Reservations {
			results = append(results, reservation.Instances...)
		}

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		request.NextToken = nextToken
	}
	return results, nil
}

func (c *Cloud) describeAutoScalingInstances(request *autoscaling.DescribeAutoScalingInstancesInput) ([]*autoscaling.InstanceDetails, error) {
	results := []*autoscaling.InstanceDetails{}
	var nextToken *string
	for {
		response, err := c.asg.DescribeAutoScalingInstances(request)
		if err != nil {
			return nil, fmt.Errorf("error listing AS instances: %q", err)
		}

		results = append(results, response.AutoScalingInstances...)

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		request.NextToken = nextToken
	}
	return results, nil
}

type awsSDKProvider struct {
	creds *credentials.Credentials
}

func (p *awsSDKProvider) Metadata() *ec2metadata.EC2Metadata {
	return ec2metadata.New(session.New(&aws.Config{}))
}

func (p *awsSDKProvider) Compute(regionName string) *ec2.EC2 {
	awsConfig := &aws.Config{
		Region:      &regionName,
		Credentials: p.creds,
	}
	awsConfig = awsConfig.WithCredentialsChainVerboseErrors(true)
	return ec2.New(session.New(awsConfig))

}

func (p *awsSDKProvider) Autoscaling(regionName string) *autoscaling.AutoScaling {
	awsConfig := &aws.Config{
		Region:      &regionName,
		Credentials: p.creds,
	}
	awsConfig = awsConfig.WithCredentialsChainVerboseErrors(true)
	return autoscaling.New(session.New(awsConfig))
}

// Derives the region from a valid az name.
// Returns an error if the az is known invalid (empty)
func azToRegion(az string) (string, error) {
	if len(az) < 1 {
		return "", fmt.Errorf("invalid (empty) AZ")
	}
	region := az[:len(az)-1]
	return region, nil
}

func newAWSCloud(config io.Reader, awsp *awsSDKProvider) (*Cloud, error) {
	metadata := awsp.Metadata()

	zone, err := metadata.GetMetadata("placement/availability-zone")
	if err != nil {
		return nil, err
	}

	regionName, err := azToRegion(zone)
	if err != nil {
		return nil, err
	}

	ec2 := awsp.Compute(regionName)
	asg := awsp.Autoscaling(regionName)

	return &Cloud{
		ec2: ec2,
		asg: asg,
	}, nil
}

func newEc2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, aws.String(value))
	}
	return filter
}
