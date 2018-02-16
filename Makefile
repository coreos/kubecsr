ROOT_DIR:=$(shell git rev-parse --show-toplevel)
GOFILES:=$(shell find . -name '*.go' | grep -v -E '(./vendor)')
GOFLAGS=
IMAGE_REPO=
IMAGE_TAG:=$(shell $(ROOT_DIR)/scripts/git-version.sh)

$( shell mkdir -p bin )

build: bin/kube-aws-approver

image: image/kube-aws-approver

check:
	@./scripts/gofmt.sh $(shell go list ./...)
	@golint -set_exit_status $(shell go list ./...)
	@go vet $(shell go list ./...)
	@./scripts/verify-gopkg.sh
	@go test -v $(shell go list ./... | grep -v '/e2e')

bin/kube-aws-approver: $(GOFILES)
	@go build $(GOFLAGS) -o $(ROOT_DIR)bin/kube-aws-approver github.com/coreos/kubecsr/cmd/kube-aws-approver

image/kube-aws-approver: IMAGE_REPO=quay.io/coreos/kube-aws-approver
image/kube-aws-approver:
	docker build -t $(IMAGE_REPO):$(IMAGE_TAG) -f $(ROOT_DIR)/Dockerfile.kube-aws-approver .

vendor:
	@dep ensure

clean:
	rm -rf _output

.PHONY: build image check clean vendor
