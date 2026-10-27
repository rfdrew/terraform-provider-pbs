.DEFAULT_GOAL := help
.PHONY: help build install test testacc docs docs-offline docs-validate fmt vet lint pbs-up pbs-down clean

BINARY  := terraform-provider-pbs
VERSION ?= dev

# tfplugindocs is pinned: releases differ in how they render the front matter,
# and CI fails whenever `make docs` changes anything under docs/, so @latest
# would break the docs check whenever a new release came out.
TFPLUGINDOCS_VERSION ?= v0.25.0

# tfplugindocs renders from the schema of whichever Terraform it runs. Releases
# before 1.12 report no resource identities and those before 1.14 no actions or
# list resources, and tfplugindocs then leaves them out without complaint, so it
# is told to download this release instead of using the one on PATH. It must be
# an exact version: tfplugindocs refuses wildcards such as 1.14.x.
TERRAFORM_DOCS_VERSION ?= 1.14.0

# docs-offline and docs-validate need neither Terraform nor a provider build:
# tools/providerschema dumps the provider's schema in process, in the format
# of `terraform providers schema -json`, and tfplugindocs reads that file
# instead. tfplugindocs looks the provider up in such a file by its short name
# (or under registry.terraform.io/hashicorp/), never under rfdrew/, so the
# dump is keyed by the short name.
PROVIDERS_SCHEMA ?= $(or $(TMPDIR),/tmp)/terraform-provider-pbs-schema.json

# `go run module@version` resolves the module even when the module cache
# already holds it, and with GOPROXY=off, as in a sandbox without network, that
# fails. The module cache doubles as a file-based proxy, whose checksums were
# verified when it was filled, so tfplugindocs is resolved from there instead.
ifeq ($(GOPROXY),off)
TFPLUGINDOCS_ENV ?= GOPROXY=file://$(shell go env GOMODCACHE)/cache/download GOSUMDB=off
endif
TFPLUGINDOCS = $(TFPLUGINDOCS_ENV) go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@$(TFPLUGINDOCS_VERSION)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the provider binary
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

install: ## Build and install into the Go bin directory
	go install -ldflags "-X main.version=$(VERSION)" .

fmt: ## Format Go and Terraform sources
	gofmt -w .
	@command -v terraform >/dev/null && terraform fmt -recursive ./examples || true

vet: ## Run go vet
	go vet ./...

lint: fmt vet ## Format, vet and run golangci-lint if it is installed
	@if command -v golangci-lint >/dev/null; then golangci-lint run ./...; \
		else echo "golangci-lint is not installed; CI runs it"; fi

# The acceptance tests skip themselves without TF_ACC, so this runs only the
# unit tests, which need no PBS.
test: ## Run unit tests (no PBS needed)
	go test ./... -v

# Acceptance tests create, change and delete real configuration on the
# server. Point them at a throwaway one -- `make pbs-up` boots one and
# prints the exports you need.
testacc: ## Run acceptance tests (requires PBS_ENDPOINT and PBS_API_TOKEN)
	TF_ACC=1 go test ./... -v -timeout 30m

pbs-up: ## Boot a throwaway PBS in Docker and print the PBS_* exports
	@./scripts/bootstrap-test-pbs.sh

pbs-down: ## Remove the throwaway PBS
	@./scripts/bootstrap-test-pbs.sh --teardown

docs: ## Regenerate docs/ from the schemas and examples, through Terraform
	$(TFPLUGINDOCS) generate \
		--provider-name pbs \
		--rendered-provider-name "Proxmox Backup Server" \
		--tf-version $(TERRAFORM_DOCS_VERSION)

docs-offline: ## Regenerate docs/ without Terraform, from an in-process schema dump
	go run ./tools/providerschema -key pbs -o $(PROVIDERS_SCHEMA)
	$(TFPLUGINDOCS) generate \
		--providers-schema $(PROVIDERS_SCHEMA) \
		--provider-name pbs \
		--rendered-provider-name "Proxmox Backup Server"

docs-validate: ## Check docs/ and examples/ with tfplugindocs validate
	go run ./tools/providerschema -key pbs -o $(PROVIDERS_SCHEMA)
	$(TFPLUGINDOCS) validate \
		--providers-schema $(PROVIDERS_SCHEMA) \
		--provider-name pbs

clean: ## Remove build artefacts
	rm -f $(BINARY) $(PROVIDERS_SCHEMA)
