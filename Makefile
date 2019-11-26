REPO_PATH := $(shell git rev-parse --show-toplevel)
CHANGED_FILES := $(shell git diff-files)

ifeq ($(strip $(CHANGED_FILES)),)
GIT_VERSION := $(shell git describe --tags --long --always)
else
GIT_VERSION := $(shell git describe --tags --long --always)-dirty-$(shell git diff | shasum -a256 | cut -c -6)
endif

IMG ?= gcr.io/arrikto-playground/kubeflow/oidc-authservice
TAG ?= $(GIT_VERSION)

all: build

build:
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o bin/oidc-authservice
	chmod +x bin/oidc-authservice

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
	# Start AuthService container
	docker run -d --user=root --name=e2e-authservice-container\
		--net host \
		--env OIDC_PROVIDER=http://localhost:5556/dex \
		--env OIDC_SCOPES=email \
		--env CLIENT_ID=test \
		--env CLIENT_SECRET=12341234 \
		--env REDIRECT_URL=http://localhost:8080/login/oidc \
		--env STORE_PATH=/data.db \
		$(IMG):$(TAG)
	# Start OIDC Provider container
	docker run -d --user root --name=e2e-oidc-provider \
		-v $(REPO_PATH)/e2e/dex-config.yaml:/etc/dex/cfg/config.yaml \
		--net host \
		quay.io/dexidp/dex:v2.19.0 \
		serve /etc/dex/cfg/config.yaml
	sleep 15
	# Run E2E tests
	-go test ./e2e -v
	# Teardown OIDC Provider container
	docker container stop e2e-oidc-provider
	docker container rm e2e-oidc-provider
	# Teardown AuthService container
	docker container stop e2e-authservice-container
	docker container rm e2e-authservice-container

publish: docker-build docker-push

.PHONY: all build docker-build docker-push docs e2e publish