export GO15VENDOREXPERIMENT:=1
export CGO_ENABLED:=0
export GOARCH:=amd64

SHELL:=$(shell which bash)
LOCAL_OS:=$(shell uname | tr A-Z a-z)
GOFILES:=$(shell find . -name '*.go' | grep -v -E '(./vendor)')
GOFLAGS=

all:
	#_output/bin/$(LOCAL_OS)/binary
	#_output/bin/linux/binary

check:
	@gofmt -l -s $(GOFILES) | read; if [ $$? == 0 ]; then gofmt -s -d $(GOFILES); exit 1; fi
	@golint -set_exit_status $(shell go list ./...)
	@go vet $(shell go list ./...)
	@./scripts/verify-gopkg.sh
	@go test -v $(shell go list ./... | grep -v '/e2e')

_output/bin/%: GOOS=$(word 1, $(subst /, ,$*))
_output/bin/%: GOARCH=$(word 2, $(subst /, ,$*))
_output/bin/%: GOARCH:=amd64
_output/bin/%: $(GOFILES)
	mkdir -p $(dir $@)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $@ github.com/coreos/kubecsr/cmd/$(notdir $@)

vendor:
	@dep ensure

clean:
	rm -rf _output

.PHONY: all check clean vendor
