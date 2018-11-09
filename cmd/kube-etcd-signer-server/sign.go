package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	"k8s.io/client-go/tools/clientcmd"

	signer "github.com/coreos/kubecsr/pkg/certsigner"
)

var (
	signCmd = &cobra.Command{
		Use:     "sign CSR_NAME --FLAGS",
		Short:   "sign certificate signing requests",
		Long:    "This command runs signs the specified certificate signing request from k8s API",
		PreRunE: validateSignOpts,
		RunE:    runCmdSign,
	}

	signOpts struct {
		kubeconfig string
	}
)

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.PersistentFlags().StringVar(&signOpts.kubeconfig, "kubeconfig", "", "Kubeconfig used to communicate with k8s API.")
}

// validateSignOpts validates the user flag values given to the signer server
func validateSignOpts(cmd *cobra.Command, args []string) error {
	if signOpts.kubeconfig == "" {
		return errors.New("missing required flag: --kubeconfig")
	}

	if len(args) != 1 {
		return errors.New("exactly one arg<CSR_NAME> required")
	}
	return nil
}

// runCmdSign invokes an instance of the signer with the given configuration arguments
func runCmdSign(cmd *cobra.Command, args []string) error {
	pCertDur, err := time.ParseDuration(rootOpts.peerCertDur)
	if err != nil {
		return fmt.Errorf("error parsing duration for etcd peer cert: %v", err)
	}

	sCertDur, err := time.ParseDuration(rootOpts.serverCertDur)
	if err != nil {
		return fmt.Errorf("error parsing duration for etcd server cert: %v", err)
	}

	c := signer.Config{
		CACertFile:             rootOpts.caCrtFile,
		CAKeyFile:              rootOpts.caKeyFile,
		ServerCertFile:         serveOpts.sCrtFile,
		ServerKeyFile:          serveOpts.sKeyFile,
		ListenAddress:          serveOpts.addr,
		EtcdPeerCertDuration:   pCertDur,
		EtcdServerCertDuration: sCertDur,
	}

	s, err := signer.NewSigner(c)
	if err != nil {
		return err
	}

	config, err := clientcmd.BuildConfigFromFlags("", signOpts.kubeconfig)
	if err != nil {
		return err
	}
	client, err := certificatesclient.NewForConfig(config)
	if err != nil {
		return err
	}

	return signer.Sign(s, client.CertificateSigningRequests(), args[0])
}
