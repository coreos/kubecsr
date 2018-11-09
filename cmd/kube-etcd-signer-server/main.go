package main

import (
	"errors"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:               "kube-etcd-signer-server",
		Short:             "Certificate signer server",
		Long:              "",
		PersistentPreRunE: validateRootOpts,
	}

	rootOpts struct {
		caCrtFile     string
		caKeyFile     string
		peerCertDur   string
		serverCertDur string
	}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&rootOpts.caCrtFile, "cacrt", "", "CA certificate file for signer")
	rootCmd.PersistentFlags().StringVar(&rootOpts.caKeyFile, "cakey", "", "CA private key file for signer")
	rootCmd.PersistentFlags().StringVar(&rootOpts.peerCertDur, "peercertdur", "8760h", "Certificate duration for etcd peer certs (defaults to 365 days)")
	rootCmd.PersistentFlags().StringVar(&rootOpts.serverCertDur, "servercertdur", "8760h", "Certificate duration for etcd server certs (defaults to 365 days)")
}

// validateRootOpts validates the user flag values given to the signer server
func validateRootOpts(cmd *cobra.Command, args []string) error {
	if rootOpts.caCrtFile == "" || rootOpts.caKeyFile == "" {
		return errors.New("both --cacrt and --cakey are required flags")
	}
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		glog.Exitf("Error executing kube-etcd-signer-server: %v", err)
	}

}
