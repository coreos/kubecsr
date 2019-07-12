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
		caCrtFile     string
		caKeyFile     string
		mCACrtFile    string
		mCAKeyFile    string
		mCASigner     bool
		sCrtFiles     []string
		sKeyFiles     []string
		addr          string
		peerCertDur   string
		serverCertDur string
		metricCertDur string
		csrDir        string

		insecureHealthCheckAddr string
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&serveOpts.caCrtFile, "cacrt", "", "CA certificate file for signer")
	serveCmd.PersistentFlags().StringVar(&serveOpts.caKeyFile, "cakey", "", "CA private key file for signer")
	serveCmd.PersistentFlags().StringArrayVar(&serveOpts.sCrtFiles, "servcrt", []string{}, "Server certificate file for signer")
	serveCmd.PersistentFlags().StringArrayVar(&serveOpts.sKeyFiles, "servkey", []string{}, "Server private key file for signer")
	serveCmd.PersistentFlags().StringVar(&serveOpts.mCACrtFile, "metric-cacrt", "", "CA certificate file for metrics signer")
	serveCmd.PersistentFlags().StringVar(&serveOpts.mCAKeyFile, "metric-cakey", "", "CA private key file for metrics signer")
	serveCmd.PersistentFlags().StringVar(&serveOpts.addr, "address", "0.0.0.0:6443", "Address on which the signer listens for requests")
	serveCmd.PersistentFlags().StringVar(&serveOpts.insecureHealthCheckAddr, "insecure-health-check-address", "0.0.0.0:6440", "Address on which the signer listens for insecure health requests")
	serveCmd.PersistentFlags().StringVar(&serveOpts.metricCertDur, "metriccertdur", "8760h", "Certificate duration for etcd metrics certs (defaults to 365 days)")
	serveCmd.PersistentFlags().StringVar(&serveOpts.peerCertDur, "peercertdur", "8760h", "Certificate duration for etcd peer certs (defaults to 365 days)")
	serveCmd.PersistentFlags().StringVar(&serveOpts.serverCertDur, "servercertdur", "8760h", "Certificate duration for etcd server certs (defaults to 365 days)")
	serveCmd.PersistentFlags().StringVar(&serveOpts.csrDir, "csrdir", "", "Directory location where signer will save CSRs.")
}

// validateServeOpts validates the user flag values given to the signer server
func validateServeOpts(cmd *cobra.Command, args []string) error {
	caPair := 0
	if serveOpts.caCrtFile != "" && serveOpts.caKeyFile != "" {
		caPair++
	}
	if serveOpts.mCACrtFile != "" && serveOpts.mCAKeyFile != "" {
		caPair++
	}
	if caPair == 0 {
		return errors.New("no signer CA flags passed one cert/key pair is required")
	}

	if cl, kl := len(serveOpts.sCrtFiles), len(serveOpts.sKeyFiles); cl == 0 || kl == 0 {
		return errors.New("at least one pair of --servcrt and --servkey is required")
	} else if cl != kl {
		return fmt.Errorf("%d --servercrt does not match %d --servkey", cl, kl)
	}
	if serveOpts.csrDir == "" {
		return errors.New("missing required flag: --csrdir")
	}
	return nil
}

// runCmdServe invokes an instance of the signer with the given configuration arguments
func runCmdServe(cmd *cobra.Command, args []string) error {
	pCertDur, err := time.ParseDuration(serveOpts.peerCertDur)
	if err != nil {
		return fmt.Errorf("error parsing duration for etcd peer cert: %v", err)
	}

	sCertDur, err := time.ParseDuration(serveOpts.serverCertDur)
	if err != nil {
		return fmt.Errorf("error parsing duration for etcd server cert: %v", err)
	}
	mCertDur, err := time.ParseDuration(serveOpts.metricCertDur)
	if err != nil {
		return fmt.Errorf("error parsing duration for etcd metric cert: %v", err)
	}

	ca := signer.SignerCAFiles{
		CACert:       serveOpts.caCrtFile,
		CAKey:        serveOpts.caKeyFile,
		MetricCACert: serveOpts.mCACrtFile,
		MetricCAKey:  serveOpts.mCAKeyFile,
	}
	servercerts := make([]signer.CertKey, len(serveOpts.sCrtFiles))
	for idx := range serveOpts.sCrtFiles {
		servercerts[idx] = signer.CertKey{CertFile: serveOpts.sCrtFiles[idx], KeyFile: serveOpts.sKeyFiles[idx]}
	}
	c := signer.Config{
		SignerCAFiles:          ca,
		ServerCertKeys:         servercerts,
		ListenAddress:          serveOpts.addr,
		EtcdMetricCertDuration: mCertDur,
		EtcdPeerCertDuration:   pCertDur,
		EtcdServerCertDuration: sCertDur,
		CSRDir:                 serveOpts.csrDir,

		InsecureHealthCheckAddress: serveOpts.insecureHealthCheckAddr,
	}

	if err := signer.StartSignerServer(c); err != nil {
		return fmt.Errorf("error starting signer: %v", err)
	}

	return nil
}
