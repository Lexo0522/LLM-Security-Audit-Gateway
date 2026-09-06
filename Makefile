BINARY := ai-audit-gateway
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race vet lint fuzz integration smoke docker clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/gateway ./cmd/gateway
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/audit-consumer ./cmd/audit-consumer
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/seed ./cmd/seed

test:
	go test ./...

race:
	CGO_ENABLED=1 go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

# Short smoke fuzz per target; longer runs belong to a dedicated job.
fuzz:
	go test -fuzz FuzzParse -fuzztime 30s ./internal/normalize
	go test -fuzz FuzzExtractFragments -fuzztime 30s ./internal/stream
	go test -fuzz FuzzEngineAudit -fuzztime 30s ./internal/rule

integration:
	./tests/integration/run-compose.ps1

# Full-stack smoke test: builds the images, boots a dedicated compose project
# with fresh volumes, exercises the admin/proxy acceptance path, tears down.
smoke:
	pwsh ./tests/smoke/run-smoke.ps1

docker:
	docker build -f deploy/Dockerfile.gateway --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) ..

clean:
	rm -rf bin
