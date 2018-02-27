# Kubernetes CSR utilities

[![Build Status](https://travis-ci.org/coreos/kubecsr.svg?branch=master)](https://travis-ci.org/coreos/kubecsr)

![](/Documentation/img/caution.png)

DO NOT DEPEND ON ANYTHING IN THIS REPO

This is a scratch space for experiments around [Kubernetes TLS bootstrapping][tls-bootstrapping]. We plan for this repo to hold CSR sidecars, cloud integrated signers, and CSR approvers. As these components mature, and if others find them useful, hopefully they can find other homes. Possibly as a [Kubernetes incubator][incubator] project.

[tls-bootstrapping]: https://kubernetes.io/docs/admin/kubelet-tls-bootstrapping/
[incubator]: https://github.com/kubernetes/community/blob/master/incubator.md

# Documentation for tools in this repo

1. [Kube AWS Approver](Documentation/kube-aws-approver.md)
2. [etcd Certificate Generator](Documentation/etcd-certificate-generator.md)

# Development guide

## Building binaries

Run `make all` to build binarys to `_output/bin/linux/` directory location.

Run `make check` to run basic checks like `gofmt`, `golint`, `go vet`, `dep` transitive dependency check, and all `unit tests`.

Run `make vendor` to update `vendor/`. `make vendor` runs `dep ensure` command.

### Building image

Make sure you have built the latest binary by running `make all`.

Then to build an image run,
```shell
BUILD_IMAGE=<tool-name> ./scripts/build-image.sh
```

To build anf push the image run,
```shell
PUSH_IMAGE=true BUILD_IMAGE=<tool-name> ./scripts/build-image.sh
```
