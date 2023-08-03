REPO_PATH := $(shell git rev-parse --show-toplevel)
CHANGED_FILES := $(shell git diff-files)

ifeq ($(strip $(CHANGED_FILES)),)
GIT_VERSION := $(shell git describe --tags --long --always)
else
GIT_VERSION := $(shell git describe --tags --long --always)-dirty-$(shell git diff | shasum -a256 | cut -c -6)
endif

IMG ?= gcr.io/arrikto-playground/kubeflow/oidc-authservice
TAG ?= $(GIT_VERSION)

.EXPORT_ALL_VARIABLES:
DOCKER_BUILDKIT := 1
PATH := $(CURDIR)/bin/deps:$(CURDIR)/bin/deps/go/bin:$(PATH)
GOROOT := $(CURDIR)/bin/deps/go


all: build

build:
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o bin/oidc-authservice
	chmod +x bin/oidc-authservice

test:
	go test -v ./

docker-build:
	docker build -t $(IMG):$(TAG) .

docker-push:
	docker push $(IMG):$(TAG)

bin/plantuml.jar:
	mkdir -p bin
	wget -O bin/plantuml.jar 'https://netix.dl.sourceforge.net/project/plantuml/1.2020.0/plantuml.1.2020.0.jar'

docs: bin/plantuml.jar
	java -jar bin/plantuml.jar -tsvg -v -o $(REPO_PATH)/docs/media $(REPO_PATH)/docs/media/source/oidc_authservice_sequence_diagram.plantuml

e2e: docker-build
	# Run E2E tests
	cd e2e/manifests/authservice/base && \
		kustomize edit set image gcr.io/arrikto/kubeflow/oidc-authservice=$(IMG):$(TAG)
	# Use -count=1 to skip Go's test cache
	TEST_IMAGE=$(IMG):$(TAG) go test -v -count=1 ./e2e

publish: docker-build docker-push

bin/deps:
	mkdir -p bin/deps
	hack/binary_deps.py bin/deps

.PHONY: all build docker-build docker-push docs e2e publish bin/deps
