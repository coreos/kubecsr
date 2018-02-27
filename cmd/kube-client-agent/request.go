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
		addr        string
		caCert      string
	}
)

func init() {
	rootCmd.AddCommand(requestCmd)
	requestCmd.PersistentFlags().StringVar(&requestOpts.commonName, "commonname", "", "Common name for the certificate being requested")
	requestCmd.PersistentFlags().StringVar(&requestOpts.orgName, "orgname", "", "CA private key file for signer")
	requestCmd.PersistentFlags().StringVar(&requestOpts.dnsNames, "dnsnames", "", "Comma separated DNS names of the node to be provided for the X509 certificate")
	requestCmd.PersistentFlags().StringVar(&requestOpts.ipAddresses, "ipaddrs", "", "Comma separated IP addresses of the node to be provided for the X509 certificate")
	requestCmd.PersistentFlags().StringVar(&requestOpts.assetsDir, "assetsdir", "", "Directory location for the agent where it stores signed certs")
	requestCmd.PersistentFlags().StringVar(&requestOpts.addr, "address", "0.0.0.0:6443", "Address on which the signer listens for requests")
	requestCmd.PersistentFlags().StringVar(&requestOpts.caCert, "cacert", "", "CA certificate for the client agent to establish trust with the signer")
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
	if requestOpts.caCert == "" {
		return errors.New("missing required flag: --cacert")
	}
	return nil

}

// runCmdRequest starts an instance of the agent which requests a CSR to be approved by the signer
func runCmdRequest(cmd *cobra.Command, args []string) error {
	ipAddrs := strings.Split(requestOpts.ipAddresses, ",")
	ips := make([]net.IP, len(ipAddrs))
	for i, addr := range ipAddrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("invalid ipaddress: %s", addr)
		}
		ips[i] = ip
	}

	c := agent.CSRConfig{
		CommonName:    requestOpts.commonName,
		OrgName:       requestOpts.orgName,
		DNSNames:      strings.Split(requestOpts.dnsNames, ","),
		IPAddresses:   ips,
		AssetsDir:     requestOpts.assetsDir,
		SignerAddress: requestOpts.addr,
	}

	if err := agent.StartAgent(c, requestOpts.caCert); err != nil {
		return fmt.Errorf("error starting agent: %s", err)
	}
	return nil
}
