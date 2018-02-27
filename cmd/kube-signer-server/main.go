package main

import (
	"github.com/golang/glog"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "kube-signer-server",
		Short: "Certificate signer server",
		Long:  "",
	}
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		glog.Exitf("Error executing kube-signer-server: %v", err)
	}

}
