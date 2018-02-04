export GO15VENDOREXPERIMENT:=1
export CGO_ENABLED:=0
export GOARCH:=amd64
export GOOS:=linux

GOFILES:=$(shell find . -name '*.go' | grep -v -E '(./vendor)')
GOFLAGS:=

all: \
	_output/bin/nodeapprover \

check:
	@gofmt -l -s $(GOFILES) | read; if [ $$? == 0 ]; then gofmt -s -d $(GOFILES); exit 1; fi
	@go vet $(shell go list ./... | grep -v '/vendor/')
	@go test -v $(shell go list ./... | grep -v '/vendor/\|/e2e')

_output/bin/%: $(GOFILES)
	mkdir -p $(dir $@)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $@ github.com/coreos/kubecsr/cmd/$(notdir $@)

vendor:
	@glide update -v
	@glide-vc --use-lock-file

clean:
	rm -rf _output

.PHONY: all check clean vendor