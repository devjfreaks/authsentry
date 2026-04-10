BINARY     := authsentry
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -ldflags="-s -w -X main.version=$(VERSION)"
IMAGE      := authsentry
DOCKER_TAG := latest

.PHONY: all build test lint clean docker docker-push run-example

all: build

build:
	CGO_ENABLED=1 go build $(LDFLAGS) -o $(BINARY) .

build-static:
	CGO_ENABLED=1 go build -ldflags="-s -w -linkmode external -extldflags -static" -o $(BINARY) .

test:
	go test ./... -v -race -timeout 60s

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY) report.html cache.db

docker:
	docker build -t $(IMAGE):$(DOCKER_TAG) .
	docker build -t $(IMAGE):$(VERSION) .

docker-push: docker
	docker tag $(IMAGE):$(DOCKER_TAG) $(DOCKER_USER)/$(IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_USER)/$(IMAGE):$(DOCKER_TAG)

run-example: build
	./$(BINARY) testdata/sample_django.log \
		--format django \
		--output html \
		--out report.html \
		--workers 5 \
		--rps 10 \
		--enrich-all \
		--no-prompt

generate-sample:
	mkdir -p testdata
	go run ./tools/gensample/... > testdata/sample_django.log

help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
