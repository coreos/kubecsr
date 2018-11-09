ROOT_DIR:=$(shell git rev-parse --show-toplevel)
GOFILES:=$(shell find . -name '*.go' | grep -v -E '(./vendor)')
GOFLAGS=
IMAGE_REPO=quay.io/coreos
IMAGE_TAG:=$(shell $(ROOT_DIR)/scripts/git-version.sh)

$( shell mkdir -p bin )

build: bin/kube-aws-approver

check:
	@./scripts/gofmt.sh $(shell go list ./...)
	@golint -set_exit_status $(shell go list ./...)
	@go vet $(shell go list ./...)
	@./scripts/verify-gopkg.sh
	@go test -v $(shell go list ./... | grep -v '/e2e')

bin/kube-aws-approver: $(GOFILES)
	@go build $(GOFLAGS) -o $(ROOT_DIR)/bin/kube-aws-approver github.com/coreos/kubecsr/cmd/kube-aws-approver

bin/kube-etcd-signer-server: $(GOFILES)
	@go build $(GOFLAGS) -o $(ROOT_DIR)/bin/kube-etcd-signer-server github.com/coreos/kubecsr/cmd/kube-etcd-signer-server

bin/kube-client-agent: $(GOFILES)
	@go build $(GOFLAGS) -o $(ROOT_DIR)/bin/kube-client-agent github.com/coreos/kubecsr/cmd/kube-client-agent

image/kube-aws-approver:
	@docker build -t $(IMAGE_REPO)/kube-aws-approver:$(IMAGE_TAG) -f $(ROOT_DIR)/dockerfiles/Dockerfile.kube-aws-approver .

push/kube-aws-approver: image/kube-aws-approver
	@docker push $(IMAGE_REPO)/kube-aws-approver:$(IMAGE_TAG)

image/kube-etcd-signer-server:
	@docker build -t $(IMAGE_REPO)/kube-etcd-signer-server:$(IMAGE_TAG) -f $(ROOT_DIR)/dockerfiles/Dockerfile.kube-etcd-signer-server .

push/kube-etcd-signer-server: image/kube-etcd-signer-server
	@docker push $(IMAGE_REPO)/kube-etcd-signer-server:$(IMAGE_TAG)

image/kube-client-agent:
	@docker build -t $(IMAGE_REPO)/kube-client-agent:$(IMAGE_TAG) -f $(ROOT_DIR)/dockerfiles/Dockerfile.kube-client-agent .

push/kube-client-agent: image/kube-client-agent
	@docker push $(IMAGE_REPO)/kube-client-agent:$(IMAGE_TAG)

test:
	@go test -v -i $(shell go list ./... | grep -v '/vendor/')
	@go test -v $(shell go list ./... | grep -v '/vendor/')

vendor:
	@dep ensure

clean:
	rm -rf $(ROOT_DIR)/bin

.PHONY: build check clean vendor
