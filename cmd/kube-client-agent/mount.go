package main

import (
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	mountSecretCmd = &cobra.Command{
		Use:     "mount --FLAGS",
		Short:   "Mount a secret with certs",
		Long:    "This command mouts the secret with valid certs signed by etcd-cert-signer-controller",
		PreRunE: validateMountSecretOpts,
		RunE:    runCmdMountSecret,
	}

	mountSecretOpts struct {
		commonName string
		assetsDir  string
	}
)

func validateMountSecretOpts(cmd *cobra.Command, args []string) error {
	if mountSecretOpts.commonName == "" {
		return fmt.Errorf("missing required flag: --commonname")
	}
	if mountSecretOpts.assetsDir == "" {
		return fmt.Errorf("missing required flag: --assetsdir")
	}
	return nil

}

func runCmdMountSecret(cmd *cobra.Command, args []string) error {
	return mountSecret()
}

// mount will secret will look for secret in the form of
// <profile>-<podFQDN>, where profile can be peer, server
// and metric and mount the certs as commonname.crt/commonname.key
// this will run as init container in etcd pod managed by CEO.
func mountSecret() error {
	var err error
	inClusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("error creating in cluster client config: %v", err)
	}

	client, err := kubernetes.NewForConfig(inClusterConfig)
	if err != nil {
		return fmt.Errorf("error creating client: %v", err)
	}

	duration := 10 * time.Second
	var s *v1.Secret
	// wait forever for success and retry every duration interval
	err = wait.PollInfinite(duration, func() (bool, error) {
		fmt.Println(requestOpts.commonName)
		s, err = client.CoreV1().Secrets("openshift-etcd").Get(getSecretName(mountSecretOpts.commonName), metav1.GetOptions{})
		if err != nil {
			glog.Errorf("error in getting secret %s/%s: %v", "openshift-etcd", getSecretName(mountSecretOpts.commonName), err)
			return false, err
		}
		err = ensureCertKeys(s.Data)
		if err != nil {
			return false, err
		}

		return true, nil

	})

	if err != nil {
		return err
	}

	// write out signed certificate to disk
	certFile := path.Join(mountSecretOpts.assetsDir, mountSecretOpts.commonName+".crt")
	if err := ioutil.WriteFile(certFile, s.Data["tls.crt"], 0644); err != nil {
		return fmt.Errorf("unable to write to %s: %v", certFile, err)
	}
	keyFile := path.Join(mountSecretOpts.assetsDir, mountSecretOpts.commonName+".key")
	if err := ioutil.WriteFile(keyFile, s.Data["tls.key"], 0644); err != nil {
		return fmt.Errorf("unable to write to %s: %v", keyFile, err)
	}
	return nil
}

func getSecretName(commonName string) string {
	prefix := ""
	if strings.Contains(commonName, "peer") {
		prefix = "peer"
	}
	if strings.Contains(commonName, "server") {
		prefix = "server"
	}
	if strings.Contains(commonName, "metric") {
		prefix = "metric"
	}
	return prefix + "-" + strings.Split(commonName, ":")[2]
}

func ensureCertKeys(data map[string][]byte) error {
	if len(data["tls.crt"]) == 0 || len(data["tls.key"]) == 0 {
		return fmt.Errorf("invalid secret data")
	}
	return nil
}
