package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
)

type awsCloud struct {
	ec2 *ec2.EC2
	asg *autoscaling.AutoScaling
}

func newAWSCloud(regionName string) (*awsCloud, error) {
	creds := credentials.NewChainCredentials([]credentials.Provider{
		&credentials.EnvProvider{},
		&credentials.SharedCredentialsProvider{},
		&ec2rolecreds.EC2RoleProvider{
			Client: ec2metadata.New(session.New(&aws.Config{})),
		},
	})

	if regionName == "" {
		mc := ec2metadata.New(session.New(&aws.Config{}))
		zone, err := mc.GetMetadata("placement/availability-zone")
		if err != nil {
			return nil, err
		}
		regionName, err = azToRegion(zone)
		if err != nil {
			return nil, err
		}
	}

	awsConfig := &aws.Config{
		Region:      &regionName,
		Credentials: creds,
	}
	awsConfig = awsConfig.WithCredentialsChainVerboseErrors(true)
	ec2 := ec2.New(session.New(awsConfig))
	asg := autoscaling.New(session.New(awsConfig))

	return &awsCloud{
		ec2: ec2,
		asg: asg,
	}, nil
}

func (c *awsCloud) instanceID(nodeName string) (string, error) {
	privateDNSName := nodeName
	filters := []*ec2.Filter{
		newEC2Filter("private-dns-name", privateDNSName),
		newEC2Filter("instance-state-name", "running"),
	}
	req := &ec2.DescribeInstancesInput{
		Filters: filters,
	}
	instances, err := c.describeInstances(req)
	if err != nil {
		return "", err
	}

	if len(instances) == 0 {
		return "", fmt.Errorf("no instance found for %s", nodeName)
	}
	if len(instances) > 1 {
		return "", fmt.Errorf("multiple instances found for name: %s", nodeName)
	}

	return aws.StringValue(instances[0].InstanceId), nil
}

func (c *awsCloud) autoScalingGroupID(nodeName string) (string, error) {
	instanceID, err := c.instanceID(nodeName)
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
		return "", fmt.Errorf("error no instance group found for %s", nodeName)
	}
	if len(instances) > 1 {
		return "", fmt.Errorf("multiple auto scaling instances found for name: %s", nodeName)
	}

	return aws.StringValue(instances[0].AutoScalingGroupName), nil
}

func (c *awsCloud) describeInstances(request *ec2.DescribeInstancesInput) ([]*ec2.Instance, error) {
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

func (c *awsCloud) describeAutoScalingInstances(request *autoscaling.DescribeAutoScalingInstancesInput) ([]*autoscaling.InstanceDetails, error) {
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

// Derives the region from a valid az name.
// Returns an error if the az is known invalid (empty)
func azToRegion(az string) (string, error) {
	if len(az) < 1 {
		return "", fmt.Errorf("invalid (empty) AZ")
	}
	region := az[:len(az)-1]
	return region, nil
}

func newEC2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, aws.String(value))
	}
	return filter
}
