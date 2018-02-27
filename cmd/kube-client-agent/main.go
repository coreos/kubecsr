package main

import (
	"github.com/golang/glog"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "kube-client-agent",
		Short: "Certificate client agent",
		Long:  "",
	}
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		glog.Exitf("Error executing kube-client-agent: %v", err)
	}

}
