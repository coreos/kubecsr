package main

import (
	"errors"
	"fmt"
	"time"

	signer "github.com/coreos/kubecsr/pkg/certsigner"
	"github.com/spf13/cobra"
)

var (
	serveCmd = &cobra.Command{
		Use:     "serve --FLAGS",
		Short:   "serve signer server",
		Long:    "This command runs an instance of the signer server which accepts certificate requests and responds with an approved CSR",
		PreRunE: validateServeOpts,
		RunE:    runCmdServe,
	}

	serveOpts struct {
		sCrtFile string
		sKeyFile string
		addr     string
		csrDir   string
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.PersistentFlags().StringVar(&serveOpts.sCrtFile, "servcrt", "", "Server certificate file for signer")
	serveCmd.PersistentFlags().StringVar(&serveOpts.sKeyFile, "servkey", "", "Server private key file for signer")
	serveCmd.PersistentFlags().StringVar(&serveOpts.addr, "address", "0.0.0.0:6443", "Address on which the signer listens for requests")
	serveCmd.PersistentFlags().StringVar(&serveOpts.csrDir, "csrdir", "", "Directory location where signer will save CSRs.")
}

// validateServeOpts validates the user flag values given to the signer server
func validateServeOpts(cmd *cobra.Command, args []string) error {
	if serveOpts.sCrtFile == "" || serveOpts.sKeyFile == "" {
		return errors.New("both --servcrt and --servkey are required flags")
	}
	if serveOpts.csrDir == "" {
		return errors.New("missing required flag: --csrdir")
	}
	return nil
}

// runCmdServe invokes an instance of the signer with the given configuration arguments
func runCmdServe(cmd *cobra.Command, args []string) error {
	pCertDur, err := time.ParseDuration(rootOpts.peerCertDur)
	if err != nil {
		return fmt.Errorf("error parsing duration for etcd peer cert: %v", err)
	}

	sCertDur, err := time.ParseDuration(rootOpts.serverCertDur)
	if err != nil {
		return fmt.Errorf("error parsing duration for etcd server cert: %v", err)
	}

	c := signer.ServerConfig{
		Config: signer.Config{
			CACertFile:             rootOpts.caCrtFile,
			CAKeyFile:              rootOpts.caKeyFile,
			ServerCertFile:         serveOpts.sCrtFile,
			ServerKeyFile:          serveOpts.sKeyFile,
			ListenAddress:          serveOpts.addr,
			EtcdPeerCertDuration:   pCertDur,
			EtcdServerCertDuration: sCertDur,
		},
		CSRDir: serveOpts.csrDir,
	}

	if err := signer.StartSignerServer(c); err != nil {
		return fmt.Errorf("error starting signer: %v", err)
	}

	return nil
}
