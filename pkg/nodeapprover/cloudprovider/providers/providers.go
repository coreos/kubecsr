package providers

import (
	// Cloud providers
	_ "github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider/providers/aws"
	_ "github.com/coreos/kubecsr/pkg/nodeapprover/cloudprovider/providers/azure"
)
