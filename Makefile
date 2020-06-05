SHELL := /bin/bash

COMMIT_SHA := $(shell git rev-parse HEAD)

.PHONY: all
all: vendor verify

tools:
	go get -u github.com/mitchellh/gox
	go get -u github.com/tcnksm/ghr

vendor:
	go get ./...

verify:
	go fmt ./...
	go vet ./...
	go test ./...

release:
	gox -arch="amd64" -os="linux windows darwin" \
	    -output "dist/aws-reverse-proxy_{{.OS}}_{{.Arch}}" ./aws-reverse-proxy/
	gox -arch="amd64" -os="linux windows darwin" \
	    -output "dist/aws-curl_{{.OS}}_{{.Arch}}" ./aws-curl/
	ghr -t $$GITHUB_TOKEN -u chronoslynx -r aws-signing -c $(COMMIT_SHA) --replace `cat VERSION` dist/

docker:
	docker build -t bsick7/aws-signing .

latest:
	docker push bsick7/aws-signing
