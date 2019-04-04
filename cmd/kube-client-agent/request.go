package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	agent "github.com/coreos/kubecsr/pkg/certagent"
	"github.com/spf13/cobra"
)

var (
	requestCmd = &cobra.Command{
		Use:     "request --FLAGS",
		Short:   "Request a signed certificate",
		Long:    "This command generates a valid CSR for the etcd node it is running on and provides the CSR to a signer for approval",
		PreRunE: validateRequestOpts,
		RunE:    runCmdRequest,
	}

	requestOpts struct {
		commonName  string
		orgName     string
		dnsNames    string
		ipAddresses string
		assetsDir   string
		kubeconfig  string
		maxRetry    int
	}
)

func init() {
	rootCmd.AddCommand(requestCmd)
	requestCmd.PersistentFlags().StringVar(&requestOpts.commonName, "commonname", "", "Common name for the certificate being requested")
	requestCmd.PersistentFlags().StringVar(&requestOpts.orgName, "orgname", "", "CA private key file for signer")
	requestCmd.PersistentFlags().StringVar(&requestOpts.dnsNames, "dnsnames", "", "Comma separated DNS names of the node to be provided for the X509 certificate")
	requestCmd.PersistentFlags().StringVar(&requestOpts.ipAddresses, "ipaddrs", "", "Comma separated IP addresses of the node to be provided for the X509 certificate")
	requestCmd.PersistentFlags().StringVar(&requestOpts.assetsDir, "assetsdir", "", "Directory location for the agent where it stores signed certs")
	requestCmd.PersistentFlags().StringVar(&requestOpts.kubeconfig, "kubeconfig", "", "Path to the kubeconfig file to connect to apiserver. If \"\", InClusterConfig is used which uses the service account kubernetes gives to pods.")
	requestCmd.PersistentFlags().IntVar(&requestOpts.maxRetry, "max-retry", 0, "If value is greater than 0 wait 10 seconds for success and retry N times.")
}

func validateRequestOpts(cmd *cobra.Command, args []string) error {
	if requestOpts.ipAddresses == "" && requestOpts.dnsNames == "" {
		return errors.New("need to provide either both or atleast one of --ipaddresses and --dnsnames flag")
	}
	if requestOpts.commonName == "" {
		return errors.New("missing required flag: --commonname")
	}
	if requestOpts.orgName == "" {
		return errors.New("missing required flag: --orgname")
	}
	if requestOpts.assetsDir == "" {
		return errors.New("missing required flag: --assetsdir")
	}
	if requestOpts.kubeconfig == "" {
		return errors.New("missing required flag: --kubeconfig")
	}
	return nil

}

// runCmdRequest starts an instance of the agent which requests a CSR to be approved by the signer
func runCmdRequest(cmd *cobra.Command, args []string) error {
	var ips []net.IP

	// Empty ip addresses are also allowed.
	if requestOpts.ipAddresses != "" {
		ipAddrs := strings.Split(requestOpts.ipAddresses, ",")
		for _, addr := range ipAddrs {
			ip := net.ParseIP(addr)
			if ip == nil {
				return fmt.Errorf("invalid ipaddress: %s", addr)
			}
			ips = append(ips, ip)
		}
	}

	config := agent.CSRConfig{
		CommonName:  requestOpts.commonName,
		OrgName:     requestOpts.orgName,
		DNSNames:    strings.Split(requestOpts.dnsNames, ","),
		IPAddresses: ips,
		AssetsDir:   requestOpts.assetsDir,
		MaxRetry:    requestOpts.maxRetry,
	}
	a, err := agent.NewAgent(config, requestOpts.kubeconfig)
	if err != nil {
		return fmt.Errorf("error creating agent: %s", err)
	}
	if err := a.RequestCertificate(); err != nil {
		return fmt.Errorf("error requesting certificate: %s", err)
	}
	return nil
}
